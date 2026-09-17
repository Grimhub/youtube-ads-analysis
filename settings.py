"""Validated deployment settings. Credentials come only from the environment."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.fernet import Fernet

GOOGLE_SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/youtube.readonly",
    "https://www.googleapis.com/auth/yt-analytics.readonly",
    "https://www.googleapis.com/auth/adwords",
]

# Restrict dynamic registration to ChatGPT's documented callback paths.
CHATGPT_REDIRECT_URIS = (
    "https://chatgpt.com/connector/oauth/*",
    "https://chatgpt.com/connector_platform_oauth_redirect",
)


@dataclass(frozen=True)
class Settings:
    public_base_url: str
    google_client_id: str
    google_client_secret: str = field(repr=False)
    owner_google_email: str
    token_encryption_key: str = field(repr=False)
    jwt_signing_key: str = field(repr=False)
    token_store_dir: Path
    allowed_client_redirect_uris: tuple[str, ...] = CHATGPT_REDIRECT_URIS
    meta_access_token: str | None = field(default=None, repr=False)
    meta_ad_account_id: str | None = None
    meta_graph_api_version: str = "v26.0"

    def __post_init__(self) -> None:
        if bool(self.meta_access_token) != bool(self.meta_ad_account_id):
            raise ValueError("Configure META_ACCESS_TOKEN and META_AD_ACCOUNT_ID together.")
        if self.meta_access_token is not None and (
            not self.meta_access_token or any(c.isspace() for c in self.meta_access_token)
        ):
            raise ValueError("META_ACCESS_TOKEN must be a non-empty token without whitespace.")
        if self.meta_ad_account_id is not None and not re.fullmatch(r"act_[0-9]+", self.meta_ad_account_id):
            raise ValueError("META_AD_ACCOUNT_ID must be an act_ prefixed numeric ID.")
        if not re.fullmatch(r"v[0-9]+\.[0-9]+", self.meta_graph_api_version):
            raise ValueError("META_GRAPH_API_VERSION must be a version such as v26.0.")
        parsed = urlsplit(self.public_base_url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
            or any(c in self.public_base_url for c in "\r\n\t *")
        ):
            raise ValueError("PUBLIC_BASE_URL must be the public HTTPS origin, without a path.")
        object.__setattr__(self, "public_base_url", self.public_base_url.rstrip("/"))
        if not self.google_client_id.endswith(".apps.googleusercontent.com"):
            raise ValueError("GOOGLE_CLIENT_ID must be a Google OAuth web application client ID.")
        if not self.google_client_secret.strip():
            raise ValueError("GOOGLE_CLIENT_SECRET is required.")
        email = self.owner_google_email.strip().casefold()
        if "@" not in email or any(c.isspace() for c in email):
            raise ValueError("OWNER_GOOGLE_EMAIL must be the Google account email.")
        object.__setattr__(self, "owner_google_email", email)
        try:
            Fernet(self.token_encryption_key.encode("ascii"))
        except (ValueError, UnicodeError) as exc:
            raise ValueError("TOKEN_ENCRYPTION_KEY must be a generated Fernet key.") from exc
        if len(self.jwt_signing_key) < 43:
            raise ValueError("JWT_SIGNING_KEY must contain at least 32 random bytes, encoded as text.")
        if self.jwt_signing_key == self.token_encryption_key:
            raise ValueError("Use separate random signing and encryption keys.")
        if not self.token_store_dir.is_absolute():
            raise ValueError("TOKEN_STORE_DIR must be an absolute path on persistent storage.")
        if not self.allowed_client_redirect_uris:
            raise ValueError("At least one ChatGPT callback URI must be configured.")
        for uri in self.allowed_client_redirect_uris:
            target = urlsplit(uri)
            if (
                target.scheme != "https"
                or target.netloc != "chatgpt.com"
                or target.query
                or target.fragment
                or not (
                    target.path == "/connector_platform_oauth_redirect"
                    or target.path == "/connector/oauth/*"
                    or (
                        target.path.startswith("/connector/oauth/")
                        and "*" not in target.path
                        and "?" not in target.path
                        and "[" not in target.path
                        and "]" not in target.path
                    )
                )
            ):
                raise ValueError("MCP_REDIRECT_URIS must use ChatGPT's HTTPS OAuth callback paths.")

    @classmethod
    def from_env(cls) -> "Settings":
        names = (
            "PUBLIC_BASE_URL", "GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET",
            "OWNER_GOOGLE_EMAIL", "TOKEN_ENCRYPTION_KEY", "JWT_SIGNING_KEY",
            "TOKEN_STORE_DIR",
        )
        missing = [name for name in names if not os.environ.get(name)]
        if missing:
            raise ValueError("Missing required settings: " + ", ".join(missing))
        redirects = CHATGPT_REDIRECT_URIS
        if os.environ.get("MCP_REDIRECT_URIS"):
            value = json.loads(os.environ["MCP_REDIRECT_URIS"])
            if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
                raise ValueError("MCP_REDIRECT_URIS must be a JSON array of URLs.")
            redirects = tuple(value)
        return cls(
            public_base_url=os.environ["PUBLIC_BASE_URL"],
            google_client_id=os.environ["GOOGLE_CLIENT_ID"],
            google_client_secret=os.environ["GOOGLE_CLIENT_SECRET"],
            owner_google_email=os.environ["OWNER_GOOGLE_EMAIL"],
            token_encryption_key=os.environ["TOKEN_ENCRYPTION_KEY"],
            jwt_signing_key=os.environ["JWT_SIGNING_KEY"],
            token_store_dir=Path(os.environ["TOKEN_STORE_DIR"]),
            allowed_client_redirect_uris=redirects,
            meta_access_token=os.environ.get("META_ACCESS_TOKEN") or None,
            meta_ad_account_id=os.environ.get("META_AD_ACCOUNT_ID") or None,
            meta_graph_api_version=os.environ.get("META_GRAPH_API_VERSION", "v26.0"),
        )
