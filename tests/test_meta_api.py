import json
from datetime import date, timedelta

import httpx
import pytest

import meta_api
from meta_api import MetaAPIError, MetaReportingClient


TOKEN = "EA-test-private-token-not-a-real-credential"
ACCOUNT = "act_1234567890123456"


@pytest.mark.asyncio
async def test_account_uses_fixed_https_get_bearer_and_returns_currency_timezone():
    calls = []

    def handler(request):
        calls.append(request)
        assert request.method == "GET"
        assert request.url.scheme == "https"
        assert request.url.host == "graph.facebook.com"
        assert request.url.path == f"/v26.0/{ACCOUNT}"
        assert request.headers["authorization"] == f"Bearer {TOKEN}"
        assert TOKEN not in str(request.url)
        assert not request.content
        assert set(request.url.params) == {"fields"}
        return httpx.Response(200, json={
            "id": ACCOUNT, "account_id": ACCOUNT[4:], "name": "Test account",
            "currency": "GBP", "timezone_name": "Europe/London", "timezone_offset_hours_utc": 1,
            "account_status": 1, "access_token": TOKEN,
            "paging": {"next": f"https://evil.test/?access_token={TOKEN}"},
        })

    async with MetaReportingClient(TOKEN, ACCOUNT[4:], transport=httpx.MockTransport(handler)) as client:
        result = await client.account()
    assert len(calls) == 1
    assert result["id"] == ACCOUNT
    assert result["currency"] == "GBP"
    assert result["timezone_name"] == "Europe/London"
    assert result["_context"]["account_id"] == ACCOUNT
    assert result["_context"]["read_only"] is True
    assert "access_token" not in result
    assert "paging" not in result
    assert TOKEN not in json.dumps(result)
    assert client._http.is_closed


@pytest.mark.asyncio
async def test_metadata_is_bounded_and_uses_only_configured_account_endpoints():
    calls = []

    def handler(request):
        calls.append(request)
        assert request.method == "GET"
        assert request.url.host == "graph.facebook.com"
        assert request.headers["authorization"] == f"Bearer {TOKEN}"
        assert not request.content
        return httpx.Response(200, json={"data": [{"id": "12", "name": "Campaign", "daily_budget": "2500", "creative": {"id": "34"}}]})

    async with MetaReportingClient(TOKEN, ACCOUNT, transport=httpx.MockTransport(handler)) as client:
        campaign_result = await client.campaigns("opaque+cursor/==", 25)
        await client.adsets()
        ads_result = await client.ads()
    assert [request.url.path for request in calls] == [
        f"/v26.0/{ACCOUNT}/campaigns", f"/v26.0/{ACCOUNT}/adsets", f"/v26.0/{ACCOUNT}/ads",
    ]
    assert calls[0].url.params["after"] == "opaque+cursor/=="
    assert calls[0].url.params["limit"] == "25"
    assert calls[1].url.params["limit"] == "100"
    assert "creative" in calls[2].url.params["fields"].split(",")
    assert ads_result["data"][0]["creative"] == {"id": "34"}
    assert campaign_result["data"][0]["daily_budget"] == "2500"
    assert "100 budget units equal 1.00" in " ".join(campaign_result["_context"]["notes"])
    assert campaign_result["_context"]["query_complete"] is False


@pytest.mark.asyncio
async def test_insights_dates_level_breakdowns_and_action_values_are_preserved():
    requested_fields = ["spend", "actions", "action_values", "purchase_roas", "video_p95_watched_actions"]
    actions = [{"action_type": "purchase", "value": "4", "1d_click": "2"}]

    def handler(request):
        assert request.url.path == f"/v26.0/{ACCOUNT}/insights"
        assert request.url.params["level"] == "ad"
        assert request.url.params["time_increment"] == "1"
        assert request.url.params["breakdowns"] == "publisher_platform,platform_position"
        assert json.loads(request.url.params["time_range"]) == {"since": "2026-08-01", "until": "2026-08-31"}
        fields = request.url.params["fields"].split(",")
        assert set(requested_fields).issubset(fields)
        assert {"account_id", "account_currency", "campaign_id", "adset_id", "ad_id", "date_start", "date_stop"}.issubset(fields)
        assert len(fields) == len(set(fields))
        return httpx.Response(200, json={"data": [{
            "account_id": ACCOUNT[4:], "account_currency": "GBP", "ad_id": "9",
            "date_start": "2026-08-01", "date_stop": "2026-08-01", "spend": "12.34",
            "actions": actions, "action_values": [{"action_type": "purchase", "value": "123.40"}],
            "publisher_platform": "instagram", "platform_position": "story",
            "unrequested_secret": TOKEN,
        }]})

    async with MetaReportingClient(TOKEN, ACCOUNT, transport=httpx.MockTransport(handler)) as client:
        result = await client.insights(
            "2026-08-01", "2026-08-31", level="ad", time_increment=1, fields=requested_fields,
            breakdowns=["publisher_platform", "platform_position"],
        )
    assert result["data"][0]["spend"] == "12.34"
    assert result["data"][0]["actions"] == actions
    assert result["data"][0]["publisher_platform"] == "instagram"
    assert result["_context"]["page_rows"] == 1
    assert result["_context"]["query_complete"] is True
    assert result["_context"]["start_date"] == "2026-08-01"
    assert result["_context"]["breakdowns"] == ["publisher_platform", "platform_position"]
    assert "unrequested_secret" not in result["data"][0]


@pytest.mark.asyncio
async def test_default_report_and_inclusive_366_day_boundary():
    def handler(request):
        assert request.url.params["level"] == "campaign"
        assert request.url.params["time_increment"] == "all_days"
        assert "breakdowns" not in request.url.params
        assert "purchase_roas" in request.url.params["fields"].split(",")
        return httpx.Response(200, json={"data": []})

    async with MetaReportingClient(TOKEN, ACCOUNT, transport=httpx.MockTransport(handler)) as client:
        result = await client.insights("2024-01-01", "2024-12-31")
    assert result["data"] == []
    assert result["_context"]["page_rows"] == 0
    assert result["_context"]["query_complete"] is True
    assert "not that every metric is zero" in " ".join(result["_context"]["notes"])


@pytest.mark.asyncio
async def test_pagination_returns_only_opaque_cursor_and_never_follows_or_leaks_next_url():
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json={
            "data": [{"id": "1"}], "summary": {"access_token": TOKEN},
            "paging": {
                "cursors": {"before": "previous-private-cursor", "after": "next+opaque/="},
                "next": f"https://evil.test/collect?access_token={TOKEN}&after=next",
                "previous": f"https://graph.facebook.com/x?access_token={TOKEN}",
            },
        })

    async with MetaReportingClient(TOKEN, ACCOUNT, transport=httpx.MockTransport(handler)) as client:
        result = await client.campaigns()
    assert len(calls) == 1
    assert result["paging"] == {"next_cursor": "next+opaque/=", "has_more": True}
    assert result["_context"]["page_rows"] == 1
    assert result["_context"]["truncated"] is True
    assert result["_context"]["query_complete"] is False
    encoded = json.dumps(result)
    assert TOKEN not in encoded
    assert "https://" not in encoded
    assert "previous-private-cursor" not in encoded


@pytest.mark.asyncio
@pytest.mark.parametrize("bad_cursor", [None, "https://evil.test/?secret=1", TOKEN, "already-used", [TOKEN]])
async def test_unusable_next_cursor_keeps_response_explicitly_incomplete(bad_cursor):
    def handler(request):
        return httpx.Response(200, json={"data": [], "paging": {
            "next": "https://graph.facebook.com/next", "cursors": {"after": bad_cursor},
        }})

    async with MetaReportingClient(TOKEN, ACCOUNT, transport=httpx.MockTransport(handler)) as client:
        result = await client.campaigns(after="already-used")
    assert result["paging"] == {"next_cursor": None, "has_more": True}
    assert result["_context"]["truncated"] is True
    assert result["_context"]["query_complete"] is False
    assert "no usable continuation cursor" in " ".join(result["_context"]["notes"])
    assert TOKEN not in json.dumps(result)


@pytest.mark.asyncio
async def test_last_page_after_cursor_does_not_claim_whole_query_is_complete():
    def handler(request):
        return httpx.Response(200, json={"data": [], "paging": {"cursors": {"after": "last"}}})

    async with MetaReportingClient(TOKEN, ACCOUNT, transport=httpx.MockTransport(handler)) as client:
        result = await client.ads(after="prior-page")
    assert result["paging"] == {"next_cursor": None, "has_more": False}
    assert result["_context"]["is_first_page"] is False
    assert result["_context"]["query_complete"] is False
    assert result["_context"]["truncated"] is False


@pytest.mark.asyncio
async def test_overfull_upstream_page_is_bounded_without_cursor_that_would_skip_rows():
    def handler(request):
        return httpx.Response(200, json={"data": [{"id": str(n)} for n in range(4)], "paging": {
            "cursors": {"after": "would-skip-discarded-rows"}, "next": "https://graph.facebook.com/next",
        }})

    async with MetaReportingClient(TOKEN, ACCOUNT, transport=httpx.MockTransport(handler)) as client:
        result = await client.ads(limit=2)
    assert result["data"] == [{"id": "0"}, {"id": "1"}]
    assert result["paging"] == {"next_cursor": None, "has_more": True}
    assert result["_context"]["local_truncated"] is True
    assert result["_context"]["rows_received"] == 4
    assert result["_context"]["page_rows"] == 2


@pytest.mark.parametrize("account_id", [
    "", "0", "act_", "act_act_123", "-1", "123/../456", "https://evil.test/123", "123?access_token=x",
    "123\r\n", "１２３", "1" * 33, 123, True, None,
])
def test_account_id_validation(account_id):
    with pytest.raises(ValueError, match="account_id"):
        MetaReportingClient(TOKEN, account_id)


@pytest.mark.parametrize("version", ["26.0", "v26.0/../me", "v26.0?token=x", "https://evil.test", "v0.0", None])
def test_version_validation(version):
    with pytest.raises(ValueError, match="api_version"):
        MetaReportingClient(TOKEN, ACCOUNT, api_version=version)


@pytest.mark.parametrize("token", ["", "token\r\nX-Key: value", " token ", "x" * 8193, None])
def test_credential_validation(token):
    with pytest.raises(ValueError, match="valid Meta access token"):
        MetaReportingClient(token, ACCOUNT)


@pytest.mark.asyncio
@pytest.mark.parametrize("method,args,kwargs", [
    ("campaigns", (), {"limit": 0}), ("adsets", (), {"limit": 101}),
    ("ads", (), {"limit": True}), ("ads", (), {"limit": 1.5}), ("campaigns", (), {"limit": "10"}),
    ("campaigns", (), {"after": ""}), ("adsets", (), {"after": "a\r\nb"}),
    ("ads", (), {"after": "https://evil.test/?access_token=secret"}),
    ("ads", (), {"after": "abc&access_token=secret"}), ("ads", (), {"after": "x" * 4097}),
    ("ads", (), {"after": TOKEN}),
    ("insights", ("2026-01-02", "2026-01-01"), {}),
    ("insights", ("2026-02-30", "2026-03-01"), {}),
    ("insights", ("20260101", "2026-01-01"), {}),
    ("insights", ("2026-1-1", "2026-01-01"), {}),
    ("insights", (date(2026, 1, 1), "2026-01-01"), {}),
    ("insights", ("2024-01-01", "2025-01-01"), {}),
    ("insights", ("2026-01-01", "2026-01-02"), {"level": "ad/../campaigns"}),
    ("insights", ("2026-01-01", "2026-01-02"), {"level": []}),
    ("insights", ("2026-01-01", "2026-01-02"), {"time_increment": "1"}),
    ("insights", ("2026-01-01", "2026-01-02"), {"time_increment": True}),
    ("insights", ("2026-01-01", "2026-01-02"), {"time_increment": 7}),
    ("insights", ("2026-01-01", "2026-01-02"), {"fields": []}),
    ("insights", ("2026-01-01", "2026-01-02"), {"fields": "spend"}),
    ("insights", ("2026-01-01", "2026-01-02"), {"fields": ["spend", "spend"]}),
    ("insights", ("2026-01-01", "2026-01-02"), {"fields": ["actions.limit(1000)"]}),
    ("insights", ("2026-01-01", "2026-01-02"), {"fields": ["spend&access_token=x"]}),
    ("insights", ("2026-01-01", "2026-01-02"), {"fields": [123]}),
    ("insights", ("2026-01-01", "2026-01-02"), {"fields": ["ad_id"], "level": "campaign"}),
    ("insights", ("2026-01-01", "2026-01-02"), {"breakdowns": ["age", "gender", "country", "region"]}),
    ("insights", ("2026-01-01", "2026-01-02"), {"breakdowns": ["age", "age"]}),
    ("insights", ("2026-01-01", "2026-01-02"), {"breakdowns": ["user_id"]}),
    ("insights", ("2026-01-01", "2026-01-02"), {"breakdowns": "country"}),
])
async def test_invalid_report_inputs_fail_before_network_without_echoing_input(method, args, kwargs):
    async with MetaReportingClient(TOKEN, ACCOUNT, transport=httpx.MockTransport(lambda request: pytest.fail("network"))) as client:
        with pytest.raises(ValueError) as error:
            await getattr(client, method)(*args, **kwargs)
    assert TOKEN not in str(error.value)
    assert "https://" not in str(error.value)


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [200, 400, 403, 500])
async def test_api_errors_keep_numeric_codes_and_never_echo_raw_fields(status):
    def handler(request):
        return httpx.Response(status, json={"error": {
            "code": 190, "error_subcode": 463, "message": f"secret={TOKEN}",
            "type": f"https://evil.test/{TOKEN}", "error_user_msg": TOKEN, "fbtrace_id": TOKEN,
        }})

    async with MetaReportingClient(TOKEN, ACCOUNT, transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(MetaAPIError) as error:
            await client.ads()
    assert error.value.status_code == status
    assert error.value.meta_code == 190
    assert error.value.meta_subcode == 463
    assert TOKEN not in json.dumps(error.value.as_dict())
    assert "https://" not in str(error.value)
    assert "validity and expiry" in str(error.value)


@pytest.mark.asyncio
async def test_malformed_error_codes_and_invalid_json_are_sanitised():
    replies = [
        httpx.Response(403, json={"error": {"code": TOKEN, "error_subcode": [TOKEN], "message": TOKEN}}),
        httpx.Response(500, content=(TOKEN + " not json").encode()),
        httpx.Response(200, content=(TOKEN + " not json").encode()),
    ]
    async with MetaReportingClient(TOKEN, ACCOUNT, transport=httpx.MockTransport(lambda request: replies.pop(0))) as client:
        for _ in range(3):
            with pytest.raises(MetaAPIError) as error:
                await client.ads()
            assert TOKEN not in json.dumps(error.value.as_dict())
            assert error.value.meta_code is None
            assert error.value.meta_subcode is None


@pytest.mark.asyncio
async def test_redirects_are_never_followed():
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(302, headers={"location": f"https://evil.test/?access_token={TOKEN}"}, text=TOKEN)

    async with MetaReportingClient(TOKEN, ACCOUNT, transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(MetaAPIError) as error:
            await client.ads()
    assert len(calls) == 1
    assert error.value.status_code == 302
    assert TOKEN not in str(error.value)
    assert "evil.test" not in str(error.value)


@pytest.mark.asyncio
@pytest.mark.parametrize("exception", [httpx.ConnectError, httpx.ReadTimeout, httpx.RemoteProtocolError])
async def test_network_failures_are_controlled_and_secret_free(exception):
    def handler(request):
        raise exception(f"https://evil.test/?secret={TOKEN}", request=request)

    async with MetaReportingClient(TOKEN, ACCOUNT, transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(MetaAPIError) as error:
            await client.ads()
    assert error.value.retryable is True
    assert TOKEN not in json.dumps(error.value.as_dict())
    assert "https://" not in str(error.value)
    assert error.value.__suppress_context__ is True


class Chunks(httpx.AsyncByteStream):
    async def __aiter__(self):
        yield b"{" + b" " * 32
        yield b" " * 32 + b"}"


@pytest.mark.asyncio
@pytest.mark.parametrize("declared_size", [False, True])
async def test_response_byte_limit_with_or_without_declared_length(monkeypatch, declared_size):
    monkeypatch.setattr(meta_api, "MAX_RESPONSE_BYTES", 50)

    def handler(request):
        return httpx.Response(200, headers={"content-length": "66"} if declared_size else {}, stream=Chunks())

    async with MetaReportingClient(TOKEN, ACCOUNT, transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(MetaAPIError, match="response exceeds"):
            await client.ads()


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", [
    [], {}, {"data": "bad"}, {"data": ["bad"]}, {"data": [], "paging": []},
    {"data": [], "paging": {"next": 3}}, {"data": [], "paging": {"cursors": []}},
])
async def test_malformed_response_does_not_masquerade_as_complete_empty_data(payload):
    async with MetaReportingClient(TOKEN, ACCOUNT, transport=httpx.MockTransport(lambda request: httpx.Response(200, json=payload))) as client:
        with pytest.raises(MetaAPIError, match="unexpected"):
            await client.ads()


@pytest.mark.asyncio
async def test_selected_data_is_redacted_and_nested_paging_is_removed():
    def handler(request):
        return httpx.Response(200, json={"data": [{
            "name": f"Campaign {TOKEN}", "id": "1", "access_token": TOKEN,
            "daily_budget": {"value": "2500", "paging": {"next": f"https://example.test/{TOKEN}"}},
        }]})

    async with MetaReportingClient(TOKEN, ACCOUNT, transport=httpx.MockTransport(handler)) as client:
        result = await client.campaigns()
    assert result["data"][0]["name"] == "Campaign [redacted]"
    assert result["data"][0]["daily_budget"] == {"value": "2500"}
    assert TOKEN not in json.dumps(result)


@pytest.mark.asyncio
async def test_unexpected_account_identity_fails_without_echo():
    async with MetaReportingClient(TOKEN, ACCOUNT, transport=httpx.MockTransport(lambda request: httpx.Response(200, json={"id": TOKEN}))) as client:
        with pytest.raises(MetaAPIError, match="unexpected account identity") as error:
            await client.account()
    assert TOKEN not in str(error.value)


@pytest.mark.asyncio
async def test_internal_endpoint_and_parameter_guards_prevent_arbitrary_targets():
    async with MetaReportingClient(TOKEN, ACCOUNT, transport=httpx.MockTransport(lambda request: pytest.fail("network"))) as client:
        for resource in ["https://evil.test", "../me", "act_9876/insights", "DELETE", "insights?access_token=x"]:
            with pytest.raises(ValueError):
                await client._request(resource, {})
        with pytest.raises(ValueError):
            await client._request("ads", {"access_token": TOKEN})
        with pytest.raises(ValueError):
            await client._request("ads", {"redirect_uri": "https://evil.test"})
