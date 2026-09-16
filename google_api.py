"""Bounded, read-only access to the Google reporting APIs.

This module accepts an already-authorised Google access token. OAuth, refresh
tokens and user authorisation remain the responsibility of the MCP auth layer.
"""

from __future__ import annotations

import asyncio
import json
import re
from datetime import date, datetime, timezone
from typing import Any

import httpx


MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_ADS_ROWS = 1000
MAX_ANALYTICS_ROWS = 1000
REPORTING_PAGE_SIZE = 100
GOOGLE_ADS_VERSION = "v25"
_DATA_BASE = "https://www.googleapis.com/youtube/v3"
_ANALYTICS_URL = "https://youtubeanalytics.googleapis.com/v2/reports"
_REPORTING_BASE = "https://youtubereporting.googleapis.com/v1"
_ADS_BASE = f"https://googleads.googleapis.com/{GOOGLE_ADS_VERSION}"
_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,63}\Z")
_RESOURCE_ID = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_VIDEO_ID = re.compile(r"[A-Za-z0-9_-]{11}\Z")
_CANONICAL_STATUSES = frozenset({
    "OK", "CANCELLED", "UNKNOWN", "INVALID_ARGUMENT", "DEADLINE_EXCEEDED",
    "NOT_FOUND", "ALREADY_EXISTS", "PERMISSION_DENIED", "UNAUTHENTICATED",
    "RESOURCE_EXHAUSTED", "FAILED_PRECONDITION", "ABORTED", "OUT_OF_RANGE",
    "UNIMPLEMENTED", "INTERNAL", "UNAVAILABLE", "DATA_LOSS",
})
_YOUTUBE_REASONS = frozenset({
    "quotaExceeded", "dailyLimitExceeded", "insufficientPermissions",
    "forbidden", "unauthorized", "youtubeSignupRequired", "channelNotFound",
    "invalidFilters", "invalidMetrics", "invalidDimensions", "badRequest",
    "accessNotConfigured", "rateLimitExceeded", "userRateLimitExceeded",
    "invalidParameter", "notFound", "authError", "required",
})


class GoogleAPIError(RuntimeError):
    """A safe, actionable error that excludes raw Google bodies and credentials."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        google_status: str | None = None,
        google_codes: list[str] | None = None,
        request_id: str | None = None,
    ) -> None:
        self.status_code = status_code
        self.google_status = google_status
        self.google_codes = google_codes or []
        self.request_id = request_id
        details = []
        if status_code is not None:
            details.append(f"HTTP {status_code}")
        if google_status:
            details.append(google_status)
        details.extend(self.google_codes)
        if request_id:
            details.append(f"request_id={request_id}")
        super().__init__(message + (" (" + "; ".join(details) + ")" if details else ""))

    def as_dict(self) -> dict[str, Any]:
        return {
            "message": str(self),
            "status_code": self.status_code,
            "google_status": self.google_status,
            "google_codes": self.google_codes,
            "request_id": self.request_id,
        }


def _integer(value: int, name: str, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ValueError(f"{name} must be an integer between {low} and {high}.")
    return value


def _page_token(value: str | None) -> str | None:
    if value is not None and (
        not isinstance(value, str)
        or not 1 <= len(value) <= 8192
        or not all(33 <= ord(char) <= 126 for char in value)
    ):
        raise ValueError("page_token must be a non-empty Google page token without whitespace.")
    return value


def _names(values: list[str], name: str, *, maximum: int, sortable: bool = False) -> str:
    if not isinstance(values, list) or not 1 <= len(values) <= maximum:
        raise ValueError(f"{name} must contain between 1 and {maximum} field names.")
    for value in values:
        if not isinstance(value, str):
            raise ValueError(f"{name} contains an invalid field name.")
        plain = value[1:] if sortable and value.startswith("-") else value
        if not _NAME.fullmatch(plain):
            raise ValueError(f"{name} contains an invalid field name.")
    if len(set(values)) != len(values):
        raise ValueError(f"{name} must not contain duplicate field names.")
    return ",".join(values)


def _date_range(start_date: str, end_date: str) -> tuple[str, str]:
    parsed = []
    for value in (start_date, end_date):
        if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
            raise ValueError("Dates must use YYYY-MM-DD.")
        try:
            parsed.append(date.fromisoformat(value))
        except ValueError:
            raise ValueError("Dates must be valid calendar dates in YYYY-MM-DD format.") from None
    if parsed[0] > parsed[1]:
        raise ValueError("start_date must be on or before end_date.")
    if parsed[0] < date(2005, 1, 1) or parsed[1] > datetime.now(timezone.utc).date():
        raise ValueError("Dates must be between 2005-01-01 and today.")
    return start_date, end_date


def _customer_id(value: str, name: str = "customer_id") -> str:
    if not isinstance(value, str) or not re.fullmatch(r"(?:\d{10}|\d{3}-\d{3}-\d{4})", value):
        raise ValueError(f"{name} must be a 10-digit Google Ads customer ID.")
    return value.replace("-", "")


def _gaql(query: str) -> str:
    """Check a single SELECT statement; Google validates GAQL field semantics.

    Quoted strings are masked before inspecting delimiters so campaign names
    containing punctuation or words such as UPDATE remain valid. The original
    query is returned unchanged and is also included in response context.
    """
    if not isinstance(query, str) or not 1 <= len(query) <= 20000:
        raise ValueError("query must contain 1–20000 characters.")
    if any(ord(char) < 32 and char not in "\r\n\t" for char in query):
        raise ValueError("query contains unsupported control characters.")
    masked = list(query)
    quote: str | None = None
    escaped = False
    for index, char in enumerate(query):
        if quote is not None:
            masked[index] = " "
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
        elif char in "\"'":
            quote = char
            masked[index] = " "
    if quote is not None:
        raise ValueError("query has an unterminated quoted string.")
    statement = "".join(masked)
    if not re.match(r"\s*SELECT\s+", statement, re.IGNORECASE) or not re.search(
        r"\bFROM\s+[A-Za-z][A-Za-z0-9_]*\b", statement, re.IGNORECASE
    ):
        raise ValueError("Only a GAQL SELECT query with a FROM resource is supported.")
    if ";" in statement or "--" in statement or "/*" in statement or "*/" in statement:
        raise ValueError("GAQL queries must be a single SELECT statement without comments or semicolons.")
    if len(re.findall(r"\bSELECT\b", statement, re.IGNORECASE)) != 1:
        raise ValueError("Only one GAQL SELECT statement is supported.")
    return query


class GoogleReportingClient:
    """One user's short-lived reporting client; use with ``async with``."""

    def __init__(self, access_token: str, *, transport: httpx.AsyncBaseTransport | None = None) -> None:
        if (
            not isinstance(access_token, str) or not 1 <= len(access_token) <= 8192
            or not re.fullmatch(r"[A-Za-z0-9._~+/-]+=*", access_token)
        ):
            raise ValueError("A valid Google access token is required.")
        self._access_token = access_token
        self._http = httpx.AsyncClient(
            transport=transport,
            timeout=httpx.Timeout(30.0, connect=10.0),
            limits=httpx.Limits(max_connections=4, max_keepalive_connections=2),
            follow_redirects=False,
            trust_env=False,
            headers={"Accept": "application/json", "Accept-Encoding": "identity"},
        )

    async def __aenter__(self) -> GoogleReportingClient:
        await self._http.__aenter__()
        return self

    async def __aexit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> None:
        await self._http.__aexit__(exc_type, exc_value, traceback)

    def _safe_error(self, response: httpx.Response, payload: Any) -> GoogleAPIError:
        error = payload.get("error", {}) if isinstance(payload, dict) else {}
        if not isinstance(error, dict):
            error = {}
        details = error.get("details") if isinstance(error.get("details"), list) else []
        request_id = response.headers.get("request-id") or response.headers.get("x-goog-request-id")
        if not request_id:
            request_id = next((item.get("requestId") for item in details
                               if isinstance(item, dict) and isinstance(item.get("requestId"), str)), None)
        if request_id and (
            not re.fullmatch(r"[A-Za-z0-9_.+/=-]{1,128}", request_id)
            or self._access_token in request_id
        ):
            request_id = None
        status = error.get("status")
        status = status if (isinstance(status, str) and status in _CANONICAL_STATUSES
                            and self._access_token not in status) else None
        codes = []
        for item in error.get("errors", []) if isinstance(error.get("errors"), list) else []:
            reason = item.get("reason") if isinstance(item, dict) else None
            if isinstance(reason, str) and reason in _YOUTUBE_REASONS and self._access_token not in reason:
                codes.append(reason)
        for detail in details:
            if not isinstance(detail, dict):
                continue
            for item in detail.get("errors", []) if isinstance(detail.get("errors"), list) else []:
                code = item.get("errorCode") if isinstance(item, dict) else None
                if not isinstance(code, dict):
                    continue
                for category, value in code.items():
                    if (
                        isinstance(category, str) and re.fullmatch(r"[a-z][A-Za-z]{0,63}Error", category)
                        and isinstance(value, str) and re.fullmatch(r"[A-Z][A-Z0-9_]{0,79}", value)
                        and self._access_token not in category + value
                    ):
                        codes.append(f"{category}={value}")
        return GoogleAPIError(
            "Google rejected the reporting request. Check account access, enabled APIs, scopes and query fields.",
            status_code=response.status_code,
            google_status=status,
            google_codes=list(dict.fromkeys(codes))[:5],
            request_id=request_id,
        )

    async def _request(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
        login_customer_id: str | None = None,
    ) -> dict[str, Any]:
        read_get = {
            f"{_DATA_BASE}/channels", f"{_DATA_BASE}/videos", _ANALYTICS_URL,
            f"{_REPORTING_BASE}/jobs", f"{_REPORTING_BASE}/reportTypes",
            f"{_ADS_BASE}/customers:listAccessibleCustomers",
        }
        valid_get = url in read_get or re.fullmatch(
            re.escape(_REPORTING_BASE) + r"/jobs/[A-Za-z0-9_-]{1,128}/reports", url
        )
        valid_post = re.fullmatch(re.escape(_ADS_BASE) + r"/customers/\d{10}/googleAds:search", url)
        if not ((method == "GET" and valid_get) or (method == "POST" and valid_post)):
            raise ValueError("Only the connector's fixed Google reporting endpoints are available.")
        headers = {"Authorization": f"Bearer {self._access_token}"}
        if login_customer_id is not None:
            headers["login-customer-id"] = _customer_id(login_customer_id, "login_customer_id")

        async def fetch() -> dict[str, Any]:
            async with self._http.stream(method, url, params=params, json=body, headers=headers) as response:
                content_length = response.headers.get("content-length", "")
                if content_length.isdigit() and int(content_length) > MAX_RESPONSE_BYTES:
                    raise GoogleAPIError("Google response exceeds 8 MiB. Narrow the date range, fields or campaign filter.")
                chunks = bytearray()
                async for chunk in response.aiter_bytes():
                    if len(chunks) + len(chunk) > MAX_RESPONSE_BYTES:
                        raise GoogleAPIError("Google response exceeds 8 MiB. Narrow the date range, fields or campaign filter.")
                    chunks.extend(chunk)
                try:
                    payload = json.loads(chunks)
                except (ValueError, UnicodeDecodeError, RecursionError):
                    if not response.is_success:
                        raise self._safe_error(response, {}) from None
                    raise GoogleAPIError("Google returned an invalid JSON reporting response.") from None
                if not response.is_success:
                    raise self._safe_error(response, payload)
                if not isinstance(payload, dict):
                    raise GoogleAPIError("Google returned an unexpected reporting response structure.")
                return payload

        try:
            return await asyncio.wait_for(fetch(), timeout=45.0)
        except (httpx.TimeoutException, asyncio.TimeoutError):
            raise GoogleAPIError("The Google reporting request timed out. Try a narrower query or retry later.") from None
        except httpx.RequestError:
            raise GoogleAPIError("The Google reporting service could not be reached. Retry later.") from None

    @staticmethod
    def _context(payload: dict[str, Any], **details: Any) -> dict[str, Any]:
        payload["_context"] = {"read_only": True, **details}
        return payload

    async def youtube_channels(self) -> dict[str, Any]:
        payload = await self._request("GET", f"{_DATA_BASE}/channels", params={
            "part": "snippet,contentDetails,statistics", "mine": "true", "maxResults": 50,
        })
        return self._context(payload, api="YouTube Data API v3", channel_selection="Google-authorised channel",
                             notes=["Confirm this channel ID matches the intended channel.",
                                    "Subscriber counts may be rounded; channel totals are not date-range reports."])

    async def youtube_videos(self, video_ids: list[str]) -> dict[str, Any]:
        if not isinstance(video_ids, list) or not 1 <= len(video_ids) <= 50:
            raise ValueError("video_ids must contain between 1 and 50 YouTube video IDs.")
        if any(not isinstance(value, str) or not _VIDEO_ID.fullmatch(value) for value in video_ids):
            raise ValueError("Every video ID must contain exactly 11 letters, digits, underscores or hyphens.")
        if len(set(video_ids)) != len(video_ids):
            raise ValueError("video_ids must not contain duplicates.")
        payload = await self._request("GET", f"{_DATA_BASE}/videos", params={
            "part": "snippet,contentDetails,statistics,status", "id": ",".join(video_ids),
        })
        return self._context(payload, api="YouTube Data API v3", requested_video_ids=video_ids,
                             notes=["Video statistics are cumulative, not limited to a reporting date range.",
                                    "Unavailable or inaccessible IDs can be absent from the returned items."])

    async def youtube_analytics(
        self, start_date: str, end_date: str, metrics: list[str],
        dimensions: list[str] | None = None, filters: str | None = None,
        sort: list[str] | None = None, max_results: int = 200, start_index: int = 1,
    ) -> dict[str, Any]:
        start_date, end_date = _date_range(start_date, end_date)
        max_results = _integer(max_results, "max_results", 1, MAX_ANALYTICS_ROWS)
        start_index = _integer(start_index, "start_index", 1, 1_000_000)
        params: dict[str, Any] = {
            "ids": "channel==MINE", "startDate": start_date, "endDate": end_date,
            "metrics": _names(metrics, "metrics", maximum=25),
            "maxResults": max_results, "startIndex": start_index,
        }
        if dimensions is not None:
            params["dimensions"] = _names(dimensions, "dimensions", maximum=10)
        if filters is not None:
            atom = r"[A-Za-z][A-Za-z0-9_]{0,63}==[A-Za-z0-9_.~-]+(?:,[A-Za-z0-9_.~-]+)*"
            if not isinstance(filters, str) or len(filters) > 4096 or not re.fullmatch(atom + r"(?:;" + atom + ")*", filters):
                raise ValueError("filters must use field==value clauses, comma-separated values and semicolon-separated clauses.")
            params["filters"] = filters
        if sort is not None:
            params["sort"] = _names(sort, "sort", maximum=25, sortable=True)
        payload = await self._request("GET", _ANALYTICS_URL, params=params)
        rows = payload.get("rows", [])
        if not isinstance(rows, list):
            raise GoogleAPIError("Google returned an unexpected Analytics rows structure.")
        received = len(rows)
        if received > max_results:
            payload["rows"] = rows[:max_results]
        return self._context(
            payload, api="YouTube Analytics API v2", request=params,
            rows_returned=min(received, max_results), truncated=received > max_results,
            pagination={"may_have_more": received >= max_results,
                        "next_start_index": start_index + max_results if received >= max_results else None},
            notes=["Dates use YouTube's Pacific reporting time zone; recent data can be incomplete.",
                   "Google validates supported metric/dimension/filter combinations.",
                   "A full page indicates possible additional rows, not a confirmed total."])

    async def _reporting_list(self, path: str, page_token: str | None) -> dict[str, Any]:
        params: dict[str, Any] = {"pageSize": REPORTING_PAGE_SIZE}
        if (token := _page_token(page_token)) is not None:
            params["pageToken"] = token
        payload = await self._request("GET", f"{_REPORTING_BASE}/{path}", params=params)
        return self._context(payload, api="YouTube Reporting API v1", page_size=REPORTING_PAGE_SIZE,
                             has_more=bool(payload.get("nextPageToken")),
                             notes=["This returns existing reporting metadata. Reports are not downloaded and jobs are not created."])

    async def youtube_reporting_jobs(self, page_token: str | None = None) -> dict[str, Any]:
        return await self._reporting_list("jobs", page_token)

    async def youtube_reporting_report_types(self, page_token: str | None = None) -> dict[str, Any]:
        return await self._reporting_list("reportTypes", page_token)

    async def youtube_reporting_reports(self, job_id: str, page_token: str | None = None) -> dict[str, Any]:
        if not isinstance(job_id, str) or not _RESOURCE_ID.fullmatch(job_id):
            raise ValueError("job_id must be a Google Reporting job ID containing letters, digits, underscores or hyphens.")
        return await self._reporting_list(f"jobs/{job_id}/reports", page_token)

    async def google_ads_customers(self) -> dict[str, Any]:
        payload = await self._request("GET", f"{_ADS_BASE}/customers:listAccessibleCustomers")
        return self._context(payload, api=f"Google Ads API {GOOGLE_ADS_VERSION}",
                             notes=["Lists accounts directly accessible to the authorised Google identity.",
                                    "Manager-linked client accounts may need a customer_client query against the manager."])

    async def google_ads_search(
        self, customer_id: str, query: str, login_customer_id: str | None = None,
        page_token: str | None = None, *, max_rows: int = MAX_ADS_ROWS,
    ) -> dict[str, Any]:
        customer_id = _customer_id(customer_id)
        if login_customer_id is not None:
            login_customer_id = _customer_id(login_customer_id, "login_customer_id")
        max_rows = _integer(max_rows, "max_rows", 1, MAX_ADS_ROWS)
        query = _gaql(query)
        body: dict[str, Any] = {"query": query}
        if (token := _page_token(page_token)) is not None:
            body["pageToken"] = token
        payload = await self._request("POST", f"{_ADS_BASE}/customers/{customer_id}/googleAds:search",
                                      body=body, login_customer_id=login_customer_id)
        rows = payload.get("results", [])
        if not isinstance(rows, list):
            raise GoogleAPIError("Google returned an unexpected Google Ads results structure.")
        received = len(rows)
        truncated = received > max_rows
        upstream_has_more = bool(payload.get("nextPageToken"))
        if truncated:
            payload["results"] = rows[:max_rows]
            # A page token advances beyond the entire Google page. Returning it
            # after removing rows would silently skip the omitted records.
            payload.pop("nextPageToken", None)
        return self._context(
            payload, api=f"Google Ads API {GOOGLE_ADS_VERSION}", customer_id=customer_id,
            login_customer_id=login_customer_id, query=query,
            max_rows=max_rows, rows_received=received, rows_returned=min(received, max_rows),
            truncated=truncated, upstream_has_more=upstream_has_more,
            next_page_available=upstream_has_more and not truncated,
            notes=[
                "Search uses HTTP POST for a read-only GAQL SELECT request.",
                "Values ending in _micros / Micros use one million units per account-currency unit.",
                "Select customer.currency_code and customer.time_zone when interpreting costs and dates; do not assume GBP or UTC.",
                "Conversions and conversion values can change after the reporting date; recent results may be incomplete.",
                ("Rows were omitted from this Google page. No continuation token is returned: narrow the date/campaign filter or selected fields before retrying. Do not treat this as a complete report."
                 if truncated else "Reuse the exact query and account IDs with nextPageToken to retrieve another page when present."),
            ])
