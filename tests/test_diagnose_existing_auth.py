import json
import logging
import os
from pathlib import Path
import secrets
import time

from cryptography.fernet import Fernet
from fastmcp.server.auth.oauth_proxy.models import UpstreamTokenSet
import httpx2
import pytest

from auth import make_storage
from diagnose_existing_auth import (
    CLIENT_COLLECTION, UPSTREAM_COLLECTION, TOKENINFO_URL, USERINFO_URL,
    ReadOnlyFileTreeStore, diagnose_google_access, diagnose_latest,
)
from settings import GOOGLE_SCOPES, Settings


SECRET = "private-token-sentinel-never-print"
EMAIL = "owner-private-sentinel@example.com"
CANDIDATE = "candidate-private-sentinel@example.com"
SUBJECT = "subject-private-sentinel"
CLIENT_ID = "client-private-sentinel"


@pytest.fixture
def diagnostic_settings(tmp_path):
    return Settings(
        public_base_url="https://connector.example.com",
        google_client_id="fixture.apps.googleusercontent.com",
        google_client_secret="private-client-secret-sentinel",
        owner_google_email=EMAIL,
        token_encryption_key=Fernet.generate_key().decode(),
        jwt_signing_key=secrets.token_urlsafe(48),
        token_store_dir=tmp_path / "oauth",
    )


def tokeninfo(settings, **changes):
    return {
        "aud": settings.google_client_id, "sub": SUBJECT,
        "scope": " ".join(GOOGLE_SCOPES), "expires_in": "3600",
        "email": EMAIL, "email_verified": "true", **changes,
    }


def transport_for(settings, info=None, *, userinfo_status=200, userinfo=None, failure=None):
    requests = []
    info = tokeninfo(settings) if info is None else info

    async def handler(request):
        requests.append(request)
        assert request.method == "GET"
        endpoint = str(request.url).split("?")[0]
        assert endpoint in (TOKENINFO_URL, USERINFO_URL)
        if failure:
            raise failure
        if endpoint == TOKENINFO_URL:
            return httpx2.Response(200, json=info)
        return httpx2.Response(userinfo_status, json=userinfo or {})

    return httpx2.MockTransport(handler), requests


def assert_safe(result, logs=""):
    output = json.dumps(result) + logs
    for forbidden in (SECRET, EMAIL, CANDIDATE, SUBJECT, CLIENT_ID, *GOOGLE_SCOPES):
        assert forbidden not in output


@pytest.mark.asyncio
@pytest.mark.parametrize("changes,expected", [
    ({}, "google_access_valid"),
    ({"email": CANDIDATE}, "configured_owner_mismatch"),
    ({"scope": "openid"}, "google_required_scopes_missing"),
    ({"aud": None}, "google_audience_missing"),
    ({"aud": "other.apps.googleusercontent.com"}, "google_audience_mismatch"),
    ({"sub": None}, "google_subject_missing"),
    ({"email_verified": "false"}, "google_verified_identity_unavailable"),
    ({"expires_in": "-1"}, "google_access_expired_or_expiry_missing"),
])
async def test_validation_stages_and_no_authorisation(diagnostic_settings, changes, expected):
    transport, requests = transport_for(diagnostic_settings, tokeninfo(diagnostic_settings, **changes))
    async with httpx2.AsyncClient(transport=transport) as client:
        result = await diagnose_google_access(
            diagnostic_settings, SECRET, http_client=client, candidate_owner_email=CANDIDATE,
        )
    assert result["stage"] == expected
    assert result["ok"] is (expected == "google_access_valid")
    assert len(requests) <= 2
    if expected == "configured_owner_mismatch":
        assert result["candidate_owner_matches"] is True
    assert_safe(result)


@pytest.mark.asyncio
async def test_userinfo_failure_is_visible_and_does_not_invent_identity(diagnostic_settings):
    info = tokeninfo(diagnostic_settings)
    del info["email"]
    del info["email_verified"]
    transport, _ = transport_for(diagnostic_settings, info, userinfo_status=503)
    async with httpx2.AsyncClient(transport=transport) as client:
        result = await diagnose_google_access(diagnostic_settings, SECRET, http_client=client)
    assert result["userinfo_status"] == 503
    assert result["stage"] == "google_verified_identity_unavailable"
    assert result["configured_owner_matches"] is False
    assert_safe(result)


@pytest.mark.asyncio
async def test_userinfo_failure_preserves_valid_tokeninfo_identity(diagnostic_settings):
    transport, _ = transport_for(diagnostic_settings, userinfo_status=503)
    async with httpx2.AsyncClient(transport=transport) as client:
        result = await diagnose_google_access(diagnostic_settings, SECRET, http_client=client)
    assert result["userinfo_status"] == 503
    assert result["ok"] is True


@pytest.mark.asyncio
async def test_userinfo_verified_email_fallback(diagnostic_settings):
    info = tokeninfo(diagnostic_settings)
    del info["email"]
    del info["email_verified"]
    transport, _ = transport_for(diagnostic_settings, info, userinfo={"email": EMAIL, "verified_email": True})
    async with httpx2.AsyncClient(transport=transport) as client:
        result = await diagnose_google_access(diagnostic_settings, SECRET, http_client=client)
    assert result["ok"] is True


@pytest.mark.asyncio
async def test_request_exception_and_debug_logging_do_not_expose_credentials(diagnostic_settings, caplog):
    caplog.set_level(logging.DEBUG)
    error = RuntimeError(f"{SECRET} {EMAIL} {TOKENINFO_URL}?access_token={SECRET}")
    transport, _ = transport_for(diagnostic_settings, failure=error)
    async with httpx2.AsyncClient(transport=transport) as client:
        result = await diagnose_google_access(diagnostic_settings, SECRET, http_client=client)
    assert result["stage"] == "google_tokeninfo_request_failed"
    assert result["tokeninfo_error_class"] == "RuntimeError"
    assert_safe(result, caplog.text)


@pytest.mark.asyncio
async def test_successful_http_debug_logs_do_not_expose_credentials(diagnostic_settings, caplog):
    caplog.set_level(logging.DEBUG)
    transport, _ = transport_for(diagnostic_settings)
    async with httpx2.AsyncClient(transport=transport) as client:
        result = await diagnose_google_access(diagnostic_settings, SECRET, http_client=client)
    assert result["ok"] is True
    assert_safe(result, caplog.text)


@pytest.mark.asyncio
async def test_malformed_response_does_not_expose_body(diagnostic_settings, caplog):
    caplog.set_level(logging.DEBUG)
    async def handler(request):
        return httpx2.Response(200, content=SECRET)
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(handler)) as client:
        result = await diagnose_google_access(diagnostic_settings, SECRET, http_client=client)
    assert result["stage"] == "google_tokeninfo_response_invalid"
    assert_safe(result, caplog.text)


async def add_grant(settings, key="opaque-grant-fixture", *, expires_in=3600):
    store = make_storage(settings)
    grant = UpstreamTokenSet(
        upstream_token_id=key, access_token=SECRET, refresh_token="refresh-" + SECRET,
        refresh_token_expires_at=time.time() + 86400, expires_at=time.time() + expires_in,
        token_type="Bearer", scope=" ".join(GOOGLE_SCOPES), client_id=CLIENT_ID,
        created_at=time.time(), raw_token_data={},
    )
    await store.put(key=key, value=grant.model_dump(), collection=UPSTREAM_COLLECTION, ttl=86400)
    await store.put(
        key=CLIENT_ID,
        value={"client_id": CLIENT_ID, "redirect_uris": ["https://chatgpt.com/connector/oauth/fixture"],
               "token_endpoint_auth_method": "none"},
        collection=CLIENT_COLLECTION,
    )
    return store


def snapshot(directory):
    return {
        str(path.relative_to(directory)): (
            path.read_bytes() if path.is_file() else None,
            path.stat().st_mode, path.stat().st_mtime_ns,
        )
        for path in [directory, *directory.rglob("*")]
    }


@pytest.mark.asyncio
async def test_existing_store_is_unchanged_and_exact_client_bearer_unverified(diagnostic_settings):
    await add_grant(diagnostic_settings)
    before = snapshot(diagnostic_settings.token_store_dir)
    transport, requests = transport_for(diagnostic_settings)
    async with httpx2.AsyncClient(transport=transport) as client:
        result = await diagnose_latest(diagnostic_settings, http_client=client)
    assert result["ok"] is True
    assert result["records"][0]["client_registration_present"] is True
    assert result["client_bearer_checked"] is False
    assert not result["refresh_attempted"]
    assert not result["authorisation_attempted"]
    assert not result["store_mutation_attempted"]
    assert len(requests) == 2
    assert snapshot(diagnostic_settings.token_store_dir) == before
    assert_safe(result)


@pytest.mark.asyncio
async def test_expired_access_does_not_refresh_or_contact_google(diagnostic_settings):
    await add_grant(diagnostic_settings, expires_in=-60)
    before = snapshot(diagnostic_settings.token_store_dir)
    transport, requests = transport_for(diagnostic_settings)
    async with httpx2.AsyncClient(transport=transport) as client:
        result = await diagnose_latest(diagnostic_settings, http_client=client)
    assert result["records"][0]["stage"] == "stored_access_expired"
    assert result["records"][0]["refresh_token_present"] is True
    assert requests == []
    assert snapshot(diagnostic_settings.token_store_dir) == before
    assert_safe(result)


@pytest.mark.asyncio
async def test_missing_store_is_not_created(diagnostic_settings):
    transport, requests = transport_for(diagnostic_settings)
    async with httpx2.AsyncClient(transport=transport) as client:
        result = await diagnose_latest(diagnostic_settings, http_client=client)
    assert result["stage"] == "storage_diagnostic_failed"
    assert not diagnostic_settings.token_store_dir.exists()
    assert requests == []
    assert_safe(result)


@pytest.mark.asyncio
async def test_missing_collection_metadata_is_not_created(diagnostic_settings):
    diagnostic_settings.token_store_dir.mkdir()
    (diagnostic_settings.token_store_dir / UPSTREAM_COLLECTION).mkdir()
    before = snapshot(diagnostic_settings.token_store_dir)
    transport, requests = transport_for(diagnostic_settings)
    async with httpx2.AsyncClient(transport=transport) as client:
        result = await diagnose_latest(diagnostic_settings, http_client=client)
    assert result["stage"] == "storage_diagnostic_failed"
    assert snapshot(diagnostic_settings.token_store_dir) == before
    assert requests == []


@pytest.mark.asyncio
async def test_only_latest_record_is_read_by_default_and_limit_is_bounded(diagnostic_settings):
    for number in range(4):
        key = f"opaque-grant-{number}"
        await add_grant(diagnostic_settings, key, expires_in=3600 if number == 3 else -60)
        path = diagnostic_settings.token_store_dir / UPSTREAM_COLLECTION / f"{key}.json"
        os.utime(path, ns=(number * 1000000000, number * 1000000000))
    transport, requests = transport_for(diagnostic_settings)
    async with httpx2.AsyncClient(transport=transport) as client:
        result = await diagnose_latest(diagnostic_settings, http_client=client)
        expanded = await diagnose_latest(diagnostic_settings, http_client=client, limit=3)
        bad_limit = await diagnose_latest(diagnostic_settings, http_client=client, limit=4)
    assert len(result["records"]) == 1 and result["ok"]
    assert len(expanded["records"]) == 3
    assert expanded["records"][1]["stage"] == "stored_access_expired"
    assert bad_limit["stage"] == "invalid_diagnostic_limit"
    assert len(requests) == 4


@pytest.mark.asyncio
async def test_write_apis_are_disabled(diagnostic_settings):
    await add_grant(diagnostic_settings)
    store = ReadOnlyFileTreeStore(diagnostic_settings.token_store_dir)
    before = snapshot(diagnostic_settings.token_store_dir)
    for method in (store.put, store.put_many, store.delete, store.delete_many):
        with pytest.raises(RuntimeError):
            await method()
    assert snapshot(diagnostic_settings.token_store_dir) == before
