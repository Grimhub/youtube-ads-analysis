"""Inspect an existing grant inside its server without starting authorisation.

This module never prints credentials, identity values, scopes or storage keys.
It never calls a token, authorisation, registration or callback endpoint. Run it
only in the connector's own trusted container with its existing environment.
The existing app's auth.py and settings.py must be importable.
"""

from __future__ import annotations

import argparse
import asyncio
from contextlib import contextmanager
import json
import logging
import os
from pathlib import Path
import re
import time
from typing import Any

from anyio import Path as AsyncPath
from cryptography.fernet import Fernet
from fastmcp.server.auth.oauth_proxy.models import ProxyDCRClient, UpstreamTokenSet
from fastmcp.server.auth.providers.google import GoogleTokenVerifier
import httpx2
from key_value.aio.adapters.pydantic import PydanticAdapter
from key_value.aio.stores.filetree import FileTreeStore
from key_value.aio.stores.filetree.store import (
    DiskCollectionInfo,
    validate_path_within_directory,
)
from key_value.aio.wrappers.encryption import FernetEncryptionWrapper

from auth import owner_matches
from settings import GOOGLE_SCOPES, Settings


UPSTREAM_COLLECTION = "mcp-upstream-tokens"
CLIENT_COLLECTION = "mcp-oauth-proxy-clients"
TOKENINFO_URL = "https://oauth2.googleapis.com/tokeninfo"
USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"
_OPAQUE_KEY = re.compile(r"[A-Za-z0-9_-]{1,200}\Z")


def _failure(stage: str, error: Exception | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"stage": stage, "ok": False}
    if error is not None:
        # Never interpolate str(error), repr(error), response bodies or URLs.
        name = type(error).__name__
        result["error_class"] = name if re.fullmatch(r"[A-Za-z_]{1,80}", name) else "Exception"
    return result


@contextmanager
def _quiet_dependencies():
    """Dependency HTTP logs can contain access-token query parameters."""
    prefixes = ("httpx", "httpx2", "httpcore", "httpcore2", "fastmcp.server.auth")
    names = set(prefixes)
    names.update(
        name for name in logging.Logger.manager.loggerDict
        if any(name == prefix or name.startswith(prefix + ".") for prefix in prefixes)
    )
    previous = {name: logging.getLogger(name).level for name in names}
    try:
        for name in names:
            logging.getLogger(name).setLevel(logging.CRITICAL + 1)
        yield
    finally:
        for name, level in previous.items():
            logging.getLogger(name).setLevel(level)


class ReadOnlyFileTreeStore(FileTreeStore):
    """Reuse FileTreeStore reads, preventing lazy metadata creation and writes.

    Pinned to the application's py-key-value-aio 0.4.5 storage format. In that
    version get()/ttl() return None for expired entries and do not delete them.
    Ordinary FileTreeStore collection setup can create metadata, so we replace
    only that setup with loading existing metadata and containment checks.
    """

    def __init__(self, data_directory: Path):
        super().__init__(data_directory=data_directory, auto_create=False)

    async def _setup_collection(self, *, collection: str) -> None:
        if collection in self._collection_infos:
            return
        collection_name = self._sanitize_collection(collection=collection)
        info_path = AsyncPath(self._metadata_directory / f"{collection_name}-info.json")
        await validate_path_within_directory(info_path, self._data_directory)
        if not await info_path.is_file():
            raise FileNotFoundError("Existing collection metadata is unavailable")
        info = await DiskCollectionInfo.from_file(
            file=info_path,
            root_directory=self._data_directory,
            serialization_adapter=self._serialization_adapter,
            key_sanitization_strategy=self._key_sanitization_strategy,
        )
        if info.collection != collection:
            raise ValueError("Collection metadata does not match")
        await validate_path_within_directory(info.directory, self._data_directory)
        self._collection_infos[collection] = info

    async def put(self, *args, **kwargs):
        raise RuntimeError("Diagnostic storage is read-only")

    async def put_many(self, *args, **kwargs):
        raise RuntimeError("Diagnostic storage is read-only")

    async def delete(self, *args, **kwargs):
        raise RuntimeError("Diagnostic storage is read-only")

    async def delete_many(self, *args, **kwargs):
        raise RuntimeError("Diagnostic storage is read-only")

    async def newest_keys(self, collection: str, limit: int) -> list[str]:
        await self.setup_collection(collection=collection)
        info = self._collection_infos[collection]
        candidates: list[tuple[int, str]] = []
        async for entry in info._list_file_paths():
            # OAuthProxy-generated identifiers use URL-safe characters. Never
            # return these keys outside this process or follow entry symlinks.
            if await entry.is_symlink() or not _OPAQUE_KEY.fullmatch(entry.stem):
                continue
            await validate_path_within_directory(entry, self._data_directory)
            candidates.append(((await entry.stat()).st_mtime_ns, entry.stem))
        candidates.sort(reverse=True)
        return [key for _, key in candidates[:limit]]


class _StatusOnlyClient:
    """Give the production verifier responses while retaining only safe status.

    Only two fixed GET endpoints are permitted. Error bodies, arbitrary profile
    values and token-bearing request URLs never reach verifier error messages.
    """

    def __init__(self, client: httpx2.AsyncClient, report: dict[str, Any], settings: Settings):
        self.client = client
        self.report = report
        self.settings = settings

    async def get(self, url: str, **kwargs) -> httpx2.Response:
        if url not in (TOKENINFO_URL, USERINFO_URL):
            raise ValueError("Unexpected diagnostic endpoint")
        stage = "tokeninfo" if url == TOKENINFO_URL else "userinfo"
        request = httpx2.Request("GET", url)  # No query token in this request.
        try:
            response = await self.client.get(url, **kwargs)
        except Exception as exc:
            self.report[f"{stage}_request_ok"] = False
            self.report[f"{stage}_error_class"] = _failure("request_error", exc)["error_class"]
            return httpx2.Response(503, json={}, request=request)
        self.report[f"{stage}_request_ok"] = True
        self.report[f"{stage}_status"] = response.status_code
        if response.status_code != 200:
            return httpx2.Response(response.status_code, json={}, request=request)
        try:
            data = response.json()
            if not isinstance(data, dict):
                raise ValueError("Unexpected JSON structure")
            if stage == "tokeninfo":
                if "scope" in data and not isinstance(data["scope"], str):
                    raise ValueError("Unexpected scope structure")
                self.report["audience_present"] = bool(data.get("aud"))
                self.report["audience_matches"] = data.get("aud") == self.settings.google_client_id
                self.report["subject_present"] = bool(data.get("sub"))
                scopes = data.get("scope", "").split()
                self.report["required_scopes_present"] = set(GOOGLE_SCOPES).issubset(scopes)
                allowed = ("aud", "sub", "scope", "expires_in", "email", "email_verified")
            else:
                allowed = ("email", "verified_email")
            cleaned = {key: data[key] for key in allowed if key in data}
            self.report[f"{stage}_json_ok"] = True
            return httpx2.Response(200, json=cleaned, request=request)
        except Exception as exc:
            self.report[f"{stage}_json_ok"] = False
            self.report[f"{stage}_error_class"] = _failure("response_error", exc)["error_class"]
            return httpx2.Response(502, json={}, request=request)


async def diagnose_google_access(
    settings: Settings,
    access_token: str,
    *,
    http_client: httpx2.AsyncClient,
    candidate_owner_email: str | None = None,
) -> dict[str, Any]:
    """Validate one supplied in-process access token; never refresh or authorise."""
    result: dict[str, Any] = {"stage": "google_validation", "ok": False}
    try:
        observer = _StatusOnlyClient(http_client, result, settings)
        # This is the same Google verifier + exact owner_matches predicate used
        # by OwnerGoogleVerifier. Separating them reveals which check failed;
        # it does not relax either check or return a usable authentication token.
        verifier = GoogleTokenVerifier(
            audience=settings.google_client_id,
            required_scopes=GOOGLE_SCOPES,
            http_client=observer,
        )
        with _quiet_dependencies():
            validated = await verifier.verify_token(access_token)
        result["google_validation_passed"] = validated is not None
        if validated is not None:
            claims = validated.claims or {}
            result["email_present"] = isinstance(claims.get("email"), str) and bool(claims["email"])
            verified = claims.get("email_verified")
            result["email_verified"] = verified is True or verified == "true"
            result["configured_owner_matches"] = owner_matches(validated, settings.owner_google_email)
            if candidate_owner_email is not None:
                result["candidate_owner_matches"] = owner_matches(validated, candidate_owner_email)
            result["access_token_unexpired"] = (
                validated.expires_at is not None and validated.expires_at > time.time()
            )
            result["ok"] = result["configured_owner_matches"] and result["access_token_unexpired"]
            if result["ok"]:
                result["stage"] = "google_access_valid"
            elif not result["access_token_unexpired"]:
                result["stage"] = "google_access_expired_or_expiry_missing"
            elif not result["email_present"] or not result["email_verified"]:
                result["stage"] = "google_verified_identity_unavailable"
            else:
                result["stage"] = "configured_owner_mismatch"
        elif result.get("tokeninfo_request_ok") is False:
            result["stage"] = "google_tokeninfo_request_failed"
        elif result.get("tokeninfo_status") != 200:
            result["stage"] = "google_tokeninfo_rejected"
        elif result.get("tokeninfo_json_ok") is False:
            result["stage"] = "google_tokeninfo_response_invalid"
        elif not result.get("audience_present"):
            result["stage"] = "google_audience_missing"
        elif not result.get("audience_matches"):
            result["stage"] = "google_audience_mismatch"
        elif not result.get("subject_present"):
            result["stage"] = "google_subject_missing"
        elif not result.get("required_scopes_present"):
            result["stage"] = "google_required_scopes_missing"
        else:
            result["stage"] = "google_validation_failed"
        return result
    except Exception as exc:
        result.update(_failure("google_diagnostic_failed", exc))
        return result


async def _diagnose_existing(
    settings: Settings,
    *,
    limit: int,
    candidate_owner_email: str | None,
    http_client: httpx2.AsyncClient,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "stage": "existing_auth_diagnostic",
        "ok": False,
        "authorisation_attempted": False,
        "refresh_attempted": False,
        "client_bearer_checked": False,
        "store_mutation_attempted": False,
        "records": [],
    }
    if not 1 <= limit <= 3:
        result.update(_failure("invalid_diagnostic_limit"))
        return result
    try:
        raw = ReadOnlyFileTreeStore(settings.token_store_dir)
        encrypted = FernetEncryptionWrapper(
            key_value=raw,
            fernet=Fernet(settings.token_encryption_key.encode("ascii")),
        )
        grants = PydanticAdapter(
            key_value=encrypted, pydantic_model=UpstreamTokenSet,
            default_collection=UPSTREAM_COLLECTION, raise_on_validation_error=True,
        )
        clients = PydanticAdapter(
            key_value=encrypted, pydantic_model=ProxyDCRClient,
            default_collection=CLIENT_COLLECTION, raise_on_validation_error=True,
        )
        keys = await raw.newest_keys(UPSTREAM_COLLECTION, limit)
        if not keys:
            result["stage"] = "stored_grant_unavailable"
            return result
        for key in keys:
            record: dict[str, Any] = {"stage": "stored_grant", "ok": False}
            result["records"].append(record)
            try:
                grant = await grants.get(key=key)
                record["stored_grant_available"] = grant is not None
                if grant is None:
                    record["stage"] = "stored_grant_unavailable"
                    continue
                record["refresh_token_present"] = bool(grant.refresh_token)
                record["stored_access_unexpired"] = grant.expires_at > time.time()
                try:
                    registration = await clients.get(key=grant.client_id)
                    record["client_registration_present"] = registration is not None
                except Exception as exc:
                    record["client_registration_present"] = False
                    record["registration_read_error_class"] = _failure("registration_read_failed", exc)["error_class"]
                if not record["stored_access_unexpired"]:
                    record["stage"] = "stored_access_expired"
                    continue
                record.update(await diagnose_google_access(
                    settings, grant.access_token,
                    http_client=http_client,
                    candidate_owner_email=candidate_owner_email,
                ))
            except Exception as exc:
                record.update(_failure("stored_grant_read_failed", exc))
        # This means a Google grant is valid, not that ChatGPT's bearer is valid.
        result["ok"] = any(record["ok"] for record in result["records"])
        return result
    except Exception as exc:
        result.update(_failure("storage_diagnostic_failed", exc))
        return result


async def diagnose_latest(
    settings: Settings,
    *,
    candidate_owner_email: str | None = None,
    http_client: httpx2.AsyncClient | None = None,
    limit: int = 1,
) -> dict[str, Any]:
    """Inspect the newest stored record by file modification time (default one).

    File modification time selects the most recently stored/refreshed record,
    which may not be the exact record referenced by ChatGPT's current bearer.
    Network work is bounded to two fixed Google GET requests per live record.
    """
    try:
        with _quiet_dependencies():
            if http_client is not None:
                return await asyncio.wait_for(_diagnose_existing(
                    settings, limit=limit, candidate_owner_email=candidate_owner_email,
                    http_client=http_client,
                ), timeout=12 * max(1, min(limit, 3)))
            async with httpx2.AsyncClient(timeout=5, follow_redirects=False) as client:
                return await asyncio.wait_for(_diagnose_existing(
                    settings, limit=limit, candidate_owner_email=candidate_owner_email,
                    http_client=client,
                ), timeout=12 * max(1, min(limit, 3)))
    except TimeoutError:
        return _failure("diagnostic_timeout")
    except Exception as exc:
        return _failure("diagnostic_failed", exc)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, choices=(1, 2, 3), default=1)
    args = parser.parse_args()
    try:
        settings = Settings.from_env()
        candidate = os.environ.get("AUTH_DIAGNOSTIC_CANDIDATE_EMAIL") or None
        result = asyncio.run(diagnose_latest(
            settings, limit=args.limit, candidate_owner_email=candidate,
        ))
    except Exception as exc:
        result = _failure("diagnostic_configuration_failed", exc)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
