import json
from datetime import date, timedelta

import httpx
import pytest

import google_api
from google_api import GoogleAPIError, GoogleReportingClient


TOKEN = "ya29.private-token-for-tests"


@pytest.mark.asyncio
async def test_google_ads_search_preserves_query_and_manager_header():
    query = " SELECT campaign.id, metrics.cost_micros FROM campaign WHERE campaign.name = 'Update; summer -- sale' LIMIT 20 "
    calls = []

    def handler(request):
        calls.append(request)
        assert request.method == "POST"
        assert str(request.url) == "https://googleads.googleapis.com/v25/customers/1234567890/googleAds:search"
        assert request.headers["authorization"] == f"Bearer {TOKEN}"
        assert request.headers["login-customer-id"] == "9876543210"
        assert "developer-token" not in request.headers
        assert json.loads(request.content) == {"query": query, "pageToken": "next/page+token="}
        return httpx.Response(200, json={"results": [{"campaign": {"id": "5"}}], "nextPageToken": "page2"})

    async with GoogleReportingClient(TOKEN, transport=httpx.MockTransport(handler)) as client:
        result = await client.google_ads_search("123-456-7890", query, "987-654-3210", "next/page+token=")
    assert len(calls) == 1
    assert result["_context"]["query"] == query
    assert result["nextPageToken"] == "page2"
    assert result["_context"]["next_page_available"] is True
    assert client._http.is_closed


@pytest.mark.asyncio
async def test_ads_truncation_never_skips_rows_via_next_page_token():
    def handler(request):
        return httpx.Response(200, json={"results": [{"id": i} for i in range(4)], "nextPageToken": "would-skip-rows"})

    async with GoogleReportingClient(TOKEN, transport=httpx.MockTransport(handler)) as client:
        result = await client.google_ads_search("1234567890", "SELECT campaign.id FROM campaign", max_rows=2)
    assert result["results"] == [{"id": 0}, {"id": 1}]
    assert "nextPageToken" not in result
    assert result["_context"]["truncated"] is True
    assert result["_context"]["rows_received"] == 4
    assert result["_context"]["rows_returned"] == 2
    assert result["_context"]["upstream_has_more"] is True
    assert result["_context"]["next_page_available"] is False


@pytest.mark.asyncio
async def test_youtube_endpoints_and_analytics_pagination():
    calls = []

    def handler(request):
        calls.append(request)
        assert request.method == "GET"
        assert request.headers["authorization"] == f"Bearer {TOKEN}"
        assert not request.content
        if request.url.host == "youtubeanalytics.googleapis.com":
            assert dict(request.url.params) == {
                "ids": "channel==MINE", "startDate": "2026-01-01", "endDate": "2026-01-31",
                "metrics": "views,estimatedMinutesWatched", "dimensions": "day", "filters": "country==GB;video==abcdefghijk",
                "sort": "-views", "maxResults": "2", "startIndex": "3",
            }
            return httpx.Response(200, json={"columnHeaders": [{"name": "views"}], "rows": [[4], [5]]})
        return httpx.Response(200, json={"items": []})

    async with GoogleReportingClient(TOKEN, transport=httpx.MockTransport(handler)) as client:
        await client.youtube_channels()
        await client.youtube_videos(["abcdefghijk", "lmnopqrstuv"])
        result = await client.youtube_analytics(
            "2026-01-01", "2026-01-31", ["views", "estimatedMinutesWatched"], ["day"],
            "country==GB;video==abcdefghijk", ["-views"], 2, 3,
        )
    assert calls[0].url.path == "/youtube/v3/channels"
    assert calls[0].url.params["mine"] == "true"
    assert calls[1].url.params["id"] == "abcdefghijk,lmnopqrstuv"
    assert result["_context"]["pagination"] == {"may_have_more": True, "next_start_index": 5}
    assert result["_context"]["truncated"] is False


@pytest.mark.asyncio
async def test_reporting_metadata_and_ads_discovery_use_fixed_get_endpoints():
    calls = []

    def handler(request):
        calls.append(request)
        assert request.method == "GET"
        return httpx.Response(200, json={"nextPageToken": "next"})

    async with GoogleReportingClient(TOKEN, transport=httpx.MockTransport(handler)) as client:
        await client.youtube_reporting_jobs("page1")
        await client.youtube_reporting_report_types()
        await client.youtube_reporting_reports("job_123-Ab", "page2")
        await client.google_ads_customers()
    assert [request.url.path for request in calls] == [
        "/v1/jobs", "/v1/reportTypes", "/v1/jobs/job_123-Ab/reports", "/v25/customers:listAccessibleCustomers",
    ]
    assert dict(calls[0].url.params) == {"pageSize": "100", "pageToken": "page1"}
    assert not calls[-1].url.params


@pytest.mark.asyncio
@pytest.mark.parametrize("query", [
    "DELETE FROM campaign", "UPDATE campaign SET name = 'x'", "SELECT campaign.id FROM campaign; DELETE FROM campaign",
    "SELECT campaign.id FROM campaign -- comment", "SELECT campaign.id FROM campaign /* comment */",
    "SELECT campaign.id FROM campaign SELECT campaign.id FROM campaign", "SELECT campaign.id FROM campaign WHERE campaign.name = 'unfinished",
    "SELECT campaign.id\x00 FROM campaign", "SELECT campaign.id", "",
])
async def test_rejects_non_single_gaql_select_before_network(query):
    def handler(request):
        pytest.fail("Invalid input reached the network")

    async with GoogleReportingClient(TOKEN, transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(ValueError):
            await client.google_ads_search("1234567890", query)


@pytest.mark.asyncio
@pytest.mark.parametrize("method,args,kwargs", [
    ("youtube_videos", (["../secret"],), {}),
    ("youtube_videos", ([],), {}),
    ("youtube_videos", (["abcdefghijk"] * 51,), {}),
    ("youtube_reporting_reports", ("../reportTypes",), {}),
    ("youtube_reporting_reports", ("https://evil.test",), {}),
    ("youtube_reporting_jobs", ("bad\r\nheader",), {}),
    ("google_ads_search", ("1234567890/../other", "SELECT campaign.id FROM campaign"), {}),
    ("google_ads_search", ("1234567890", "SELECT campaign.id FROM campaign"), {"login_customer_id": "bad"}),
    ("google_ads_search", ("1234567890", "SELECT campaign.id FROM campaign"), {"max_rows": 1001}),
    ("youtube_analytics", ("2026-02-02", "2026-02-01", ["views"]), {}),
    ("youtube_analytics", ("2026-02-30", "2026-03-01", ["views"]), {}),
    ("youtube_analytics", ("2000-01-01", "2026-01-01", ["views"]), {}),
    ("youtube_analytics", ("2026-01-01", "2026-01-31", ["views&key=evil"]), {}),
    ("youtube_analytics", ("2026-01-01", "2026-01-31", ["views"]), {"max_results": True}),
    ("youtube_analytics", ("2026-01-01", "2026-01-31", ["views"]), {"start_index": 0}),
    ("youtube_analytics", ("2026-01-01", "2026-01-31", ["views"]), {"filters": "country==GB&key=evil"}),
])
async def test_input_boundaries_reject_before_network(method, args, kwargs):
    def handler(request):
        pytest.fail("Invalid input reached the network")

    async with GoogleReportingClient(TOKEN, transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(ValueError):
            await getattr(client, method)(*args, **kwargs)


@pytest.mark.asyncio
async def test_future_dates_rejected():
    async with GoogleReportingClient(TOKEN, transport=httpx.MockTransport(lambda request: pytest.fail("network"))) as client:
        with pytest.raises(ValueError):
            await client.youtube_analytics("2026-01-01", (date.today() + timedelta(days=2)).isoformat(), ["views"])


@pytest.mark.asyncio
async def test_redirect_is_not_followed_and_does_not_leak_token():
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(302, headers={"location": "https://evil.test/collect"}, text=TOKEN)

    async with GoogleReportingClient(TOKEN, transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(GoogleAPIError) as error:
            await client.youtube_channels()
    assert len(calls) == 1
    assert TOKEN not in str(error.value)
    assert error.value.status_code == 302


@pytest.mark.asyncio
async def test_safe_google_error_keeps_codes_and_request_id_without_raw_message():
    def handler(request):
        return httpx.Response(403, headers={"request-id": "request_123-Ab"}, json={"error": {
            "code": 403, "status": "PERMISSION_DENIED", "message": f"secret {TOKEN}",
            "details": [{"errors": [{"errorCode": {"authorizationError": "USER_PERMISSION_DENIED"}, "message": TOKEN}]}],
        }})

    async with GoogleReportingClient(TOKEN, transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(GoogleAPIError) as error:
            await client.google_ads_customers()
    assert error.value.google_status == "PERMISSION_DENIED"
    assert error.value.google_codes == ["authorizationError=USER_PERMISSION_DENIED"]
    assert error.value.request_id == "request_123-Ab"
    assert TOKEN not in json.dumps(error.value.as_dict())


@pytest.mark.asyncio
async def test_error_header_and_invalid_json_are_sanitised():
    def handler(request):
        return httpx.Response(500, headers={"request-id": TOKEN}, content=(TOKEN + " not JSON").encode())

    async with GoogleReportingClient(TOKEN, transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(GoogleAPIError) as error:
            await client.youtube_channels()
    assert TOKEN not in str(error.value)
    assert error.value.request_id is None


@pytest.mark.asyncio
async def test_malformed_error_fields_and_body_request_id_are_safe():
    def handler(request):
        return httpx.Response(403, json={"error": {
            "status": {"malformed": TOKEN},
            "errors": [{"reason": [TOKEN]}, "invalid"],
            "details": [{"requestId": "body-request_12", "errors": [{"errorCode": "bad"}]}],
        }})

    async with GoogleReportingClient(TOKEN, transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(GoogleAPIError) as error:
            await client.youtube_channels()
    assert error.value.request_id == "body-request_12"
    assert error.value.google_status is None
    assert error.value.google_codes == []
    assert TOKEN not in str(error.value)


class Chunks(httpx.AsyncByteStream):
    async def __aiter__(self):
        yield b"{" + b" " * 32
        yield b" " * 32 + b"}"


@pytest.mark.asyncio
@pytest.mark.parametrize("declared_size", [False, True])
async def test_response_limit_applies_with_and_without_content_length(monkeypatch, declared_size):
    monkeypatch.setattr(google_api, "MAX_RESPONSE_BYTES", 50)

    def handler(request):
        return httpx.Response(200, headers={"content-length": "66"} if declared_size else {}, stream=Chunks())

    async with GoogleReportingClient(TOKEN, transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(GoogleAPIError, match="response exceeds"):
            await client.youtube_channels()


@pytest.mark.asyncio
async def test_network_exception_does_not_expose_token():
    def handler(request):
        raise httpx.ConnectError(f"sensitive detail {TOKEN}", request=request)

    async with GoogleReportingClient(TOKEN, transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(GoogleAPIError) as error:
            await client.youtube_channels()
    assert TOKEN not in str(error.value)


@pytest.mark.asyncio
async def test_internal_endpoint_guard_blocks_arbitrary_destinations_and_mutations():
    async with GoogleReportingClient(TOKEN, transport=httpx.MockTransport(lambda request: pytest.fail("network"))) as client:
        with pytest.raises(ValueError):
            await client._request("GET", "https://evil.test/collect")
        with pytest.raises(ValueError):
            await client._request("DELETE", "https://youtubereporting.googleapis.com/v1/jobs")
