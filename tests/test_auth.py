import secrets
from dataclasses import replace

import pytest
from cryptography.fernet import Fernet
from fastmcp.server.auth import AccessToken
from fastmcp.server.auth.providers.google import GoogleTokenVerifier
from starlette.testclient import TestClient

from auth import OwnerGoogleVerifier, make_storage, owner_matches
from server import create_app, create_server
from settings import GOOGLE_SCOPES, Settings


@pytest.fixture
def settings(tmp_path):
    return Settings(
        public_base_url="https://connector.example.com",
        google_client_id="fixture.apps.googleusercontent.com",
        google_client_secret="fixture-google-secret",
        owner_google_email="owner@example.com",
        token_encryption_key=Fernet.generate_key().decode(),
        jwt_signing_key=secrets.token_urlsafe(48),
        token_store_dir=tmp_path / "oauth",
    )


def token(**claims):
    return AccessToken(
        token="upstream-fixture-token", client_id="google-subject", scopes=GOOGLE_SCOPES,
        claims={"email": "owner@example.com", "email_verified": True, **claims},
    )


@pytest.mark.parametrize("claims", [
    {"email": "someone-else@example.com"},
    {"email_verified": False},
    {"email_verified": "false"},
    {"email_verified": None},
    {"email": None},
])
def test_other_or_unverified_identity_denied(claims):
    assert not owner_matches(token(**claims), "owner@example.com")


def test_owner_and_scope_validation():
    assert owner_matches(token(email="OWNER@example.com"), "owner@example.com")
    assert not owner_matches(None, "owner@example.com")
    missing_scope = token().model_copy(update={"scopes": ["openid"]})
    assert not owner_matches(missing_scope, "owner@example.com")


@pytest.mark.asyncio
async def test_verifier_applies_owner_restriction_after_google_verification(monkeypatch):
    async def google_result(self, value):
        return token(email="different@example.com")
    monkeypatch.setattr(GoogleTokenVerifier, "verify_token", google_result)
    verifier = OwnerGoogleVerifier(owner_email="owner@example.com", required_scopes=GOOGLE_SCOPES)
    assert await verifier.verify_token("opaque-input") is None


@pytest.mark.asyncio
async def test_encrypted_store_survives_restart(settings):
    original = make_storage(settings)
    secret = "sentinel-refresh-token-do-not-store-in-cleartext"
    await original.put(key="fixture", value={"refresh_token": secret})
    files = [p for p in settings.token_store_dir.rglob("*") if p.is_file()]
    assert files
    assert all(secret.encode() not in p.read_bytes() for p in files)
    reopened = make_storage(settings)
    assert await reopened.get(key="fixture") == {"refresh_token": secret}


def test_secrets_excluded_from_settings_repr(settings):
    representation = repr(settings)
    assert settings.google_client_secret not in representation
    assert settings.jwt_signing_key not in representation
    assert settings.token_encryption_key not in representation
    with_meta = replace(settings, meta_access_token="fixture-meta-secret", meta_ad_account_id="act_123")
    assert with_meta.meta_access_token not in repr(with_meta)


@pytest.mark.parametrize("overrides", [
    {"meta_access_token": "fixture-meta-secret"},
    {"meta_ad_account_id": "act_123"},
    {"meta_access_token": "fixture-meta-secret", "meta_ad_account_id": "act_123/ads"},
    {"meta_access_token": "contains whitespace", "meta_ad_account_id": "act_123"},
    {"meta_graph_api_version": "v26.0/../me"},
])
def test_meta_configuration_cannot_leak_tokens_or_change_request_target(settings, overrides):
    with pytest.raises(ValueError):
        replace(settings, **overrides)


@pytest.mark.parametrize("url", [
    "http://connector.example.com", "https://user:password@connector.example.com",
    "https://connector.example.com/path", "https://connector.example.com?token=secret",
])
def test_public_url_is_an_https_origin(settings, url):
    with pytest.raises(ValueError):
        replace(settings, public_base_url=url)


@pytest.mark.parametrize("callback", [
    "https://attacker.example.com/callback",
    "https://chatgpt.com.attacker.example.com/connector/oauth/123",
    "https://chatgpt.com@attacker.example.com/connector/oauth/123",
    "https://chatgpt.com/*",
    "http://chatgpt.com/connector/oauth/123",
])
def test_redirect_configuration_cannot_allow_an_arbitrary_site(settings, callback):
    with pytest.raises(ValueError):
        replace(settings, allowed_client_redirect_uris=(callback,))


def test_mcp_requires_auth_and_metadata_advertises_own_resource(settings):
    with TestClient(create_app(settings), base_url=settings.public_base_url) as client:
        health = client.get("/health")
        assert health.status_code == 200
        assert health.json() == {"status": "ok"}
        response = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        assert response.status_code == 401
        assert "resource_metadata" in response.headers["www-authenticate"]
        protected = client.get("/.well-known/oauth-protected-resource/mcp")
        assert protected.status_code == 200
        assert protected.json()["resource"] == settings.public_base_url + "/mcp"
        metadata = client.get("/.well-known/oauth-authorization-server")
        assert metadata.status_code == 200
        assert metadata.json()["issuer"].rstrip("/") == settings.public_base_url
        assert "S256" in metadata.json()["code_challenge_methods_supported"]
        assert settings.google_client_secret not in metadata.text
        for bearer in ("invalid.jwt.token", "a-google-access-token-is-not-an-mcp-token"):
            rejected = client.post("/mcp", headers={"Authorization": "Bearer " + bearer},
                                   json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
            assert rejected.status_code == 401


def test_dynamic_registration_restricts_callbacks_and_does_not_return_google_secret(settings):
    with TestClient(create_app(settings), base_url=settings.public_base_url) as client:
        bad = client.post("/register", json={
            "redirect_uris": ["https://attacker.example.com/callback"],
            "client_name": "Untrusted client", "token_endpoint_auth_method": "none",
        })
        assert bad.status_code == 400
        allowed = client.post("/register", json={
            "redirect_uris": ["https://chatgpt.com/connector/oauth/fixture"],
            "client_name": "ChatGPT", "token_endpoint_auth_method": "none",
        })
        assert allowed.status_code == 201
        assert settings.google_client_secret not in allowed.text
        assert allowed.json()["client_id"] != settings.google_client_id


def test_http_rejects_unexpected_hosts_and_browser_origins(settings):
    with TestClient(create_app(settings), base_url=settings.public_base_url) as client:
        assert client.get("/health", headers={"Host": "healthcheck.railway.app"}).status_code == 200
        bad_host = client.get("/health", headers={"Host": "attacker.example.com"})
        assert bad_host.status_code in (400, 403, 421)
        bad_origin = client.post("/mcp", headers={"Origin": "https://attacker.example.com"},
                                 json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        assert bad_origin.status_code == 403
        allowed_origin = client.get("/health", headers={"Origin": settings.public_base_url})
        assert allowed_origin.status_code == 200


@pytest.mark.asyncio
async def test_tool_catalogue_only_exposes_read_operations(settings):
    server = create_server(settings)
    tools = await server.list_tools()
    assert tools
    assert all(tool.annotations.read_only_hint is True for tool in tools)
    assert not any(any(word in tool.name for word in ("create", "delete", "mutate", "update")) for tool in tools)


@pytest.mark.asyncio
async def test_meta_tools_are_optional_and_require_verified_owner(settings, monkeypatch):
    from fastmcp.exceptions import ToolError
    import server as server_module

    assert not any(t.name.startswith("meta_") for t in await create_server(settings).list_tools())
    configured = replace(settings, meta_access_token="fixture-meta-secret", meta_ad_account_id="act_123")
    server = create_server(configured)
    meta_tools = [t for t in await server.list_tools() if t.name.startswith("meta_")]
    assert {t.name for t in meta_tools} == {
        "meta_ad_account", "meta_campaigns", "meta_adsets", "meta_ads", "meta_insights",
    }
    assert all(t.annotations.read_only_hint for t in meta_tools)

    def denied(_):
        raise ToolError("Owner login required")

    def unexpected_client(*args, **kwargs):
        pytest.fail("Meta client must not be created for an unauthorised caller")

    monkeypatch.setattr(server_module, "current_google_token", denied)
    monkeypatch.setattr(server_module, "MetaReportingClient", unexpected_client)
    with pytest.raises(ToolError, match="Owner login required"):
        await server.call_tool("meta_ad_account", {})


@pytest.mark.asyncio
async def test_meta_tool_uses_its_configured_account_and_private_credential(settings, monkeypatch):
    import server as server_module
    configured = replace(settings, meta_access_token="fixture-meta-secret", meta_ad_account_id="act_123")
    called = []

    class Client:
        def __init__(self, token, account_id, *, api_version):
            assert token == configured.meta_access_token
            assert account_id == "act_123"
            assert api_version == "v26.0"

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def account(self):
            called.append("account")
            return {"id": "act_123", "name": "Fixture", "currency": "USD"}

    monkeypatch.setattr(server_module, "current_google_token", lambda _: "upstream-google-fixture")
    monkeypatch.setattr(server_module, "MetaReportingClient", Client)
    result = await create_server(configured).call_tool("meta_ad_account", {})
    assert called == ["account"]
    assert result.structured_content["id"] == "act_123"
    assert configured.meta_access_token not in str(result)
