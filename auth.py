"""Google OAuth behind an MCP OAuth proxy with encrypted persistent storage."""

from __future__ import annotations

from cryptography.fernet import Fernet
from fastmcp.server.auth import AccessToken, OAuthProxy
from fastmcp.server.auth.providers.google import GoogleTokenVerifier
from fastmcp.server.dependencies import get_access_token
from fastmcp.exceptions import ToolError
from key_value.aio.stores.filetree import FileTreeStore
from key_value.aio.wrappers.encryption import FernetEncryptionWrapper

from settings import GOOGLE_SCOPES, Settings


def owner_matches(token: AccessToken | None, email: str) -> bool:
    """Only a Google-verified email can match the configured owner."""
    if token is None:
        return False
    claims = token.claims or {}
    verified = claims.get("email_verified")
    return (
        (verified is True or verified == "true")
        and isinstance(claims.get("email"), str)
        and claims["email"].casefold() == email.casefold()
        and set(GOOGLE_SCOPES).issubset(token.scopes)
    )


class OwnerGoogleVerifier(GoogleTokenVerifier):
    def __init__(self, *, owner_email: str, **kwargs):
        super().__init__(**kwargs)
        self.owner_email = owner_email

    async def verify_token(self, token: str) -> AccessToken | None:
        validated = await super().verify_token(token)
        return validated if owner_matches(validated, self.owner_email) else None


def make_storage(settings: Settings) -> FernetEncryptionWrapper:
    settings.token_store_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    settings.token_store_dir.chmod(0o700)
    return FernetEncryptionWrapper(
        key_value=FileTreeStore(data_directory=settings.token_store_dir),
        fernet=Fernet(settings.token_encryption_key.encode("ascii")),
    )


def make_auth(settings: Settings) -> OAuthProxy:
    # Use the library's complete OAuth implementation. MCP access tokens are
    # signed for this server; Google tokens remain in encrypted server storage.
    return OAuthProxy(
        upstream_authorization_endpoint="https://accounts.google.com/o/oauth2/v2/auth",
        upstream_token_endpoint="https://oauth2.googleapis.com/token",
        upstream_client_id=settings.google_client_id,
        upstream_client_secret=settings.google_client_secret,
        token_verifier=OwnerGoogleVerifier(
            owner_email=settings.owner_google_email,
            audience=settings.google_client_id,
            required_scopes=GOOGLE_SCOPES,
        ),
        base_url=settings.public_base_url,
        issuer_url=settings.public_base_url,
        redirect_path="/auth/callback",
        allowed_client_redirect_uris=list(settings.allowed_client_redirect_uris),
        valid_scopes=GOOGLE_SCOPES,
        client_storage=make_storage(settings),
        jwt_signing_key=settings.jwt_signing_key,
        require_authorization_consent=True,
        forward_pkce=True,
        forward_resource=False,
        extra_authorize_params={
            "access_type": "offline",
            "prompt": "consent select_account",
        },
        token_expiry_threshold_seconds=60,
        # DCR works for ChatGPT. Disable optional arbitrary client metadata fetches.
        enable_cimd=False,
    )


def current_google_token(settings: Settings) -> str:
    token = get_access_token()
    if not owner_matches(token, settings.owner_google_email):
        raise ToolError("Sign in with the configured Google owner account and grant the required scopes.")
    return token.token
