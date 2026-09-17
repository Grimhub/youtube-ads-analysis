"""Bounded, read-only Meta Marketing API reporting for one configured account.

Field names follow Meta's official facebook-python-business-sdk definitions:
https://github.com/facebook/facebook-python-business-sdk/tree/main/facebook_business/adobjects
The caller supplies the credential; this module never reads environment files.
"""

from __future__ import annotations

import asyncio
import json
import re
from datetime import date
from typing import Any

import httpx


META_API_VERSION = "v26.0"
MAX_PAGE_SIZE = 100
MAX_DATE_RANGE_DAYS = 366
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
_GRAPH_ORIGIN = "https://graph.facebook.com"
_ACCOUNT_ID = re.compile(r"(?:act_)?([1-9][0-9]{0,31})\Z")
_VERSION = re.compile(r"v[1-9][0-9]{0,2}\.[0-9]{1,2}\Z")
_CURSOR = re.compile(r"[A-Za-z0-9._~+/-]+=*\Z")
_RESOURCES = frozenset({"account", "campaigns", "adsets", "ads", "insights"})
_PARAMETERS = frozenset({"fields", "after", "limit", "time_range", "level", "time_increment", "breakdowns"})

ACCOUNT_FIELDS = (
    "id", "account_id", "name", "currency", "timezone_name",
    "timezone_offset_hours_utc", "account_status",
)
CAMPAIGN_FIELDS = (
    "id", "account_id", "name", "status", "effective_status", "objective",
    "buying_type", "daily_budget", "lifetime_budget", "budget_remaining",
    "start_time", "stop_time", "created_time", "updated_time",
)
ADSET_FIELDS = (
    "id", "account_id", "campaign_id", "name", "status", "effective_status",
    "daily_budget", "lifetime_budget", "budget_remaining", "billing_event",
    "optimization_goal", "start_time", "end_time", "created_time", "updated_time",
)
AD_FIELDS = (
    "id", "account_id", "campaign_id", "adset_id", "name", "status",
    "effective_status", "created_time", "updated_time", "creative",
)
INSIGHTS_FIELDS = frozenset({
    "account_id", "account_name", "account_currency", "campaign_id", "campaign_name",
    "adset_id", "adset_name", "ad_id", "ad_name", "date_start", "date_stop",
    "spend", "impressions", "clicks", "inline_link_clicks", "inline_link_click_ctr",
    "ctr", "cpc", "cpm", "reach", "frequency", "actions", "action_values",
    "cost_per_action_type", "purchase_roas", "website_purchase_roas",
    "outbound_clicks", "outbound_clicks_ctr", "cost_per_inline_link_click",
    "video_play_actions", "video_p25_watched_actions", "video_p50_watched_actions",
    "video_p75_watched_actions", "video_p95_watched_actions", "video_p100_watched_actions",
    "video_thruplay_watched_actions", "video_avg_time_watched_actions",
    "objective", "optimization_goal",
})
INSIGHTS_BREAKDOWNS = frozenset({
    "age", "gender", "country", "region", "publisher_platform", "platform_position",
    "impression_device", "device_platform",
})
DEFAULT_INSIGHTS_FIELDS = (
    "spend", "impressions", "clicks", "inline_link_clicks", "ctr", "cpc", "cpm",
    "reach", "frequency", "actions", "action_values", "cost_per_action_type", "purchase_roas",
)
_LEVEL_IDENTITIES = {
    "account": (),
    "campaign": ("campaign_id", "campaign_name"),
    "adset": ("campaign_id", "campaign_name", "adset_id", "adset_name"),
    "ad": ("campaign_id", "campaign_name", "adset_id", "adset_name", "ad_id", "ad_name"),
}
_BUDGET_NOTE = (
    "Budget fields retain Meta's integer currency units. Apply Meta's currency offset "
    "before conversion (for GBP and USD, 100 budget units equal 1.00). "
    "Insights spend and monetary metrics are already expressed in the account currency."
)


class MetaAPIError(RuntimeError):
    """A controlled diagnostic that excludes response bodies, URLs and credentials."""

    def __init__(
        self, message: str, *, status_code: int | None = None,
        meta_code: int | None = None, meta_subcode: int | None = None,
        retryable: bool = False,
    ) -> None:
        self.status_code = status_code
        self.meta_code = meta_code
        self.meta_subcode = meta_subcode
        self.retryable = retryable
        details = []
        if status_code is not None:
            details.append(f"HTTP {status_code}")
        if meta_code is not None:
            details.append(f"Meta code {meta_code}")
        if meta_subcode is not None:
            details.append(f"subcode {meta_subcode}")
        super().__init__(message + (" (" + "; ".join(details) + ")" if details else ""))

    def as_dict(self) -> dict[str, Any]:
        return {
            "message": str(self), "status_code": self.status_code,
            "meta_code": self.meta_code, "meta_subcode": self.meta_subcode,
            "retryable": self.retryable,
        }


def _limit(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= MAX_PAGE_SIZE:
        raise ValueError(f"limit must be an integer between 1 and {MAX_PAGE_SIZE}.")
    return value


def _cursor(value: str | None) -> str | None:
    if value is not None and (
        not isinstance(value, str) or not 1 <= len(value) <= 4096 or not _CURSOR.fullmatch(value)
    ):
        raise ValueError("after must be an opaque Meta cursor of at most 4096 characters, not a URL.")
    return value


def _date_range(start_date: str, end_date: str) -> tuple[str, str]:
    parsed = []
    for value in (start_date, end_date):
        if not isinstance(value, str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value):
            raise ValueError("Dates must use YYYY-MM-DD.")
        try:
            parsed.append(date.fromisoformat(value))
        except ValueError:
            raise ValueError("Dates must be valid calendar dates in YYYY-MM-DD format.") from None
    if parsed[0] > parsed[1]:
        raise ValueError("start_date must be on or before end_date.")
    if (parsed[1] - parsed[0]).days + 1 > MAX_DATE_RANGE_DAYS:
        raise ValueError(f"An insights request may cover at most {MAX_DATE_RANGE_DAYS} days, inclusive.")
    return start_date, end_date


def _selected(values: list[str], allowed: frozenset[str], name: str, maximum: int) -> list[str]:
    if not isinstance(values, list) or not 1 <= len(values) <= maximum:
        raise ValueError(f"{name} must contain between 1 and {maximum} allowed names.")
    if any(not isinstance(value, str) or value not in allowed for value in values):
        raise ValueError(f"{name} contains an unsupported name; field expansions and arbitrary parameters are unavailable.")
    if len(values) != len(set(values)):
        raise ValueError(f"{name} must not contain duplicates.")
    return list(values)


class MetaReportingClient:
    """One account's reporting client; use with ``async with``.

    Each list operation returns one page. Pass its ``paging.next_cursor`` as
    ``after`` with the same other arguments to continue. No automatic paging or
    write operation is available.
    """

    def __init__(
        self, access_token: str, account_id: str, *, api_version: str = META_API_VERSION,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if (
            not isinstance(access_token, str) or not 1 <= len(access_token) <= 8192
            or not re.fullmatch(r"[A-Za-z0-9._~+/-]+=*", access_token)
        ):
            raise ValueError("A valid Meta access token is required.")
        match = _ACCOUNT_ID.fullmatch(account_id) if isinstance(account_id, str) else None
        if match is None:
            raise ValueError("account_id must be a numeric Meta ad account ID, optionally prefixed with act_.")
        if not isinstance(api_version, str) or not _VERSION.fullmatch(api_version):
            raise ValueError("api_version must be a version such as v26.0.")
        self._access_token = access_token
        self._account_id = "act_" + match.group(1)
        self._api_version = api_version
        self._http = httpx.AsyncClient(
            transport=transport, timeout=httpx.Timeout(30.0, connect=10.0),
            limits=httpx.Limits(max_connections=4, max_keepalive_connections=2),
            follow_redirects=False, trust_env=False,
            headers={"Accept": "application/json", "Accept-Encoding": "identity"},
        )

    async def __aenter__(self) -> MetaReportingClient:
        await self._http.__aenter__()
        return self

    async def __aexit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> None:
        await self._http.__aexit__(exc_type, exc_value, traceback)

    @staticmethod
    def _safe_error(response: httpx.Response, payload: Any) -> MetaAPIError:
        error = payload.get("error") if isinstance(payload, dict) else None
        error = error if isinstance(error, dict) else {}
        code = error.get("code")
        subcode = error.get("error_subcode")
        code = code if type(code) is int and 0 <= code <= 999_999_999 else None
        subcode = subcode if type(subcode) is int and 0 <= subcode <= 999_999_999 else None
        retryable = (
            error.get("is_transient") is True or response.status_code == 429
            or response.status_code >= 500 or code in {4, 17, 32, 613}
        )
        if code == 190 or response.status_code == 401:
            message = "Meta could not authenticate the reporting credential. Check its validity and expiry."
        elif code in {10, 200} or response.status_code == 403:
            message = "Meta denied reporting access. Check ads_read permission and access to the configured ad account."
        elif retryable:
            message = "Meta could not complete the reporting request. Retry later or narrow the report."
        else:
            message = "Meta rejected the reporting request. Check account access and the requested fields or breakdown combination."
        return MetaAPIError(
            message, status_code=response.status_code, meta_code=code,
            meta_subcode=subcode, retryable=retryable,
        )

    async def _request(self, resource: str, params: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(resource, str) or resource not in _RESOURCES or set(params) - _PARAMETERS:
            raise ValueError("Only the connector's fixed Meta reporting endpoints and parameters are available.")
        suffix = "" if resource == "account" else "/" + resource
        url = f"{_GRAPH_ORIGIN}/{self._api_version}/{self._account_id}{suffix}"

        async def fetch() -> dict[str, Any]:
            async with self._http.stream(
                "GET", url, params=params, headers={"Authorization": f"Bearer {self._access_token}"},
                follow_redirects=False,
            ) as response:
                content_length = response.headers.get("content-length", "")
                if content_length.isdigit() and (
                    len(content_length) > 12 or int(content_length) > MAX_RESPONSE_BYTES
                ):
                    raise MetaAPIError("Meta response exceeds 8 MiB. Narrow the fields, date range or page limit.")
                content = bytearray()
                async for chunk in response.aiter_bytes():
                    if len(content) + len(chunk) > MAX_RESPONSE_BYTES:
                        raise MetaAPIError("Meta response exceeds 8 MiB. Narrow the fields, date range or page limit.")
                    content.extend(chunk)
                try:
                    payload = json.loads(content)
                except (ValueError, UnicodeDecodeError, RecursionError):
                    if not response.is_success:
                        raise self._safe_error(response, {}) from None
                    raise MetaAPIError("Meta returned an invalid JSON reporting response.") from None
                if not response.is_success or (isinstance(payload, dict) and "error" in payload):
                    raise self._safe_error(response, payload)
                if not isinstance(payload, dict):
                    raise MetaAPIError("Meta returned an unexpected reporting response structure.")
                return payload

        try:
            return await asyncio.wait_for(fetch(), timeout=45.0)
        except (httpx.TimeoutException, asyncio.TimeoutError):
            raise MetaAPIError("The Meta reporting request timed out. Retry later or narrow the report.", retryable=True) from None
        except httpx.RequestError:
            raise MetaAPIError("The Meta reporting service could not be reached. Retry later.", retryable=True) from None

    def _clean(self, value: Any, depth: int = 0) -> Any:
        """Defence in depth for selected data, without exposing raw paging URLs."""
        if depth > 32:
            raise MetaAPIError("Meta returned an unexpectedly nested reporting response.")
        if isinstance(value, str):
            return value.replace(self._access_token, "[redacted]")
        if isinstance(value, list):
            return [self._clean(item, depth + 1) for item in value]
        if isinstance(value, dict):
            return {
                self._clean(key, depth + 1): self._clean(item, depth + 1)
                for key, item in value.items()
                if key.lower() not in {"paging", "next", "previous", "access_token", "authorization"}
            }
        return value

    def _context(self, resource: str, fields: tuple[str, ...] | list[str], **details: Any) -> dict[str, Any]:
        return {
            "read_only": True, "api": "Meta Marketing API", "api_version": self._api_version,
            "account_id": self._account_id, "resource": resource, "fields": list(fields), **details,
        }

    async def account(self) -> dict[str, Any]:
        payload = await self._request("account", {"fields": ",".join(ACCOUNT_FIELDS)})
        if payload.get("id") != self._account_id:
            raise MetaAPIError("Meta returned an unexpected account identity.")
        result = {key: self._clean(payload[key]) for key in ACCOUNT_FIELDS if key in payload}
        result["_context"] = self._context(
            "account", ACCOUNT_FIELDS, notes=[
                "Use timezone_name for reporting dates; its UTC offset may change with daylight saving time.",
                "currency is the account's billing and reporting currency.",
            ],
        )
        return result

    async def _page(
        self, resource: str, fields: tuple[str, ...] | list[str], *, after: str | None,
        limit: int, extra_params: dict[str, Any] | None = None,
        output_fields: list[str] | None = None, **details: Any,
    ) -> dict[str, Any]:
        after, limit = _cursor(after), _limit(limit)
        if after is not None and self._access_token in after:
            raise ValueError("after must be a pagination cursor, not an access token.")
        params = {"fields": ",".join(fields), "limit": limit, **(extra_params or {})}
        if after is not None:
            params["after"] = after
        payload = await self._request(resource, params)
        rows = payload.get("data")
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise MetaAPIError("Meta returned an unexpected reporting rows structure.")
        paging = payload.get("paging", {})
        if not isinstance(paging, dict):
            raise MetaAPIError("Meta returned an unexpected pagination structure.")
        raw_next = paging.get("next")
        if raw_next is not None and not isinstance(raw_next, str):
            raise MetaAPIError("Meta returned an unexpected pagination structure.")
        upstream_has_more = bool(raw_next)
        cursors = paging.get("cursors", {})
        if not isinstance(cursors, dict):
            raise MetaAPIError("Meta returned an unexpected pagination structure.")
        next_cursor = None
        if upstream_has_more:
            try:
                next_cursor = _cursor(cursors.get("after"))
            except ValueError:
                pass
            if next_cursor is not None and (self._access_token in next_cursor or next_cursor == after):
                next_cursor = None
        local_truncated = len(rows) > limit
        if local_truncated:
            # A cursor after the whole upstream page would skip the discarded rows.
            next_cursor = None
        has_more = upstream_has_more or local_truncated
        allowed_output = set(output_fields or fields)
        result_rows = [
            {key: self._clean(value) for key, value in row.items() if key in allowed_output}
            for row in rows[:limit]
        ]
        notes = [
            "This response contains one page. Keep all report arguments unchanged when continuing with next_cursor.",
            "An empty page means no matching rows were returned, not that every metric is zero.",
        ]
        if has_more and next_cursor is None:
            notes.append("More data exists but this page has no usable continuation cursor. Narrow the report or reduce the page limit.")
        supplied_notes = details.pop("notes", [])
        return {
            "data": result_rows,
            "paging": {"next_cursor": next_cursor, "has_more": has_more},
            "_context": self._context(
                resource, fields, limit=limit, page_rows=len(result_rows), rows_received=len(rows),
                has_more=has_more, upstream_has_more=upstream_has_more, next_cursor=next_cursor,
                truncated=has_more, local_truncated=local_truncated, is_first_page=after is None,
                query_complete=after is None and not has_more, notes=notes + supplied_notes, **details,
            ),
        }

    async def campaigns(self, after: str | None = None, limit: int = MAX_PAGE_SIZE) -> dict[str, Any]:
        return await self._page("campaigns", CAMPAIGN_FIELDS, after=after, limit=limit, notes=[
            "Campaign settings are current metadata, not historical performance or historical budget values.", _BUDGET_NOTE,
        ])

    async def adsets(self, after: str | None = None, limit: int = MAX_PAGE_SIZE) -> dict[str, Any]:
        return await self._page("adsets", ADSET_FIELDS, after=after, limit=limit, notes=[
            "Ad set settings are current metadata; budgets may be configured at campaign or ad set level.", _BUDGET_NOTE,
        ])

    async def ads(self, after: str | None = None, limit: int = MAX_PAGE_SIZE) -> dict[str, Any]:
        return await self._page("ads", AD_FIELDS, after=after, limit=limit, notes=[
            "Ad settings are current metadata, not date-range performance.",
        ])

    async def insights(
        self, start_date: str, end_date: str, level: str = "campaign",
        time_increment: str | int = "all_days", fields: list[str] | None = None,
        breakdowns: list[str] | None = None, after: str | None = None, limit: int = MAX_PAGE_SIZE,
    ) -> dict[str, Any]:
        start_date, end_date = _date_range(start_date, end_date)
        if not isinstance(level, str) or level not in _LEVEL_IDENTITIES:
            raise ValueError("level must be account, campaign, adset or ad.")
        if not (time_increment == "all_days" or (type(time_increment) is int and time_increment == 1)):
            raise ValueError("time_increment must be all_days or the integer 1 for daily rows.")
        requested_fields = list(DEFAULT_INSIGHTS_FIELDS) if fields is None else _selected(
            fields, INSIGHTS_FIELDS, "fields", len(INSIGHTS_FIELDS),
        )
        finer_identities = set(_LEVEL_IDENTITIES["ad"]) - set(_LEVEL_IDENTITIES[level])
        if finer_identities.intersection(requested_fields):
            raise ValueError("Identity fields must match the requested reporting level or a coarser level.")
        selected_fields = list(dict.fromkeys([
            "account_id", "account_name", "account_currency", *_LEVEL_IDENTITIES[level],
            "date_start", "date_stop", *requested_fields,
        ]))
        selected_breakdowns = [] if breakdowns is None or breakdowns == [] else _selected(
            breakdowns, INSIGHTS_BREAKDOWNS, "breakdowns", 3,
        )
        params: dict[str, Any] = {
            "time_range": json.dumps({"since": start_date, "until": end_date}, separators=(",", ":")),
            "level": level, "time_increment": time_increment,
        }
        if selected_breakdowns:
            params["breakdowns"] = ",".join(selected_breakdowns)
        return await self._page(
            "insights", selected_fields, after=after, limit=limit, extra_params=params,
            output_fields=selected_fields + selected_breakdowns,
            start_date=start_date, end_date=end_date, level=level, time_increment=time_increment,
            breakdowns=selected_breakdowns, notes=[
                "Dates are inclusive and use the ad account's reporting time zone; read account() for timezone_name and currency.",
                "Meta validates field and breakdown combinations. Recent data and attributed conversions may change.",
                "Monetary metrics use account_currency; numeric strings and action arrays are preserved as returned by Meta.",
                "Attribution parameters are not overridden; results use Meta's API defaults. Compare reports with the same attribution settings.",
                "Reach and frequency are not additive across dates or breakdowns; action types can overlap and should not be summed indiscriminately.",
            ],
        )
