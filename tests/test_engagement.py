import json

import httpx
import pytest
from hypothesis_pt.engagement import Engagement, run_read_only, sanitized_plan


def manifest():
    return {
        "title": "Approved staging read-only regression",
        "base_url": "https://staging.bank.example",
        "environment": "UAT",
        "approved_by": "Bank security lead",
        "approval_reference": "ROE-2026-01",
        "probes": [
            {"id": "BOLA-1", "path": "/api/accounts/ACC-100", "requester_profile": "USER_B"},
            {"id": "RBAC-1", "path": "/api/admin/reports", "requester_profile": "USER_B"},
        ],
    }


@pytest.mark.parametrize("unsafe", ["https://example.org/a", "http://example.org",
                                   "https://name:password@example.org", "https://example.org:8443"])
def test_rejects_invalid_origins(unsafe):
    data = manifest()
    data["base_url"] = unsafe
    with pytest.raises(Exception):
        Engagement.model_validate(data)


@pytest.mark.parametrize("unsafe_path", ["//external", "/abc/../admin", "/abc?query=1",
                                           "/abc%2fadmin", "/a//b", "https://example.org"])
def test_rejects_unsafe_paths(unsafe_path):
    data = manifest()
    data["probes"][0]["path"] = unsafe_path
    with pytest.raises(Exception):
        Engagement.model_validate(data)


@pytest.mark.asyncio
async def test_read_only_execution_is_allowlisted_silent_and_auditable(monkeypatch):
    data = manifest()
    config = Engagement.model_validate(data)
    monkeypatch.setenv("HYPOTHESIS_ENABLE_READONLY_PT", "1")
    monkeypatch.setenv("HYPOTHESIS_ROE_APPROVED", "1")
    monkeypatch.setenv("HYPOTHESIS_TOKEN_USER_B", "super-secret-fixture")
    calls = []

    def respond(request):
        calls.append(request)
        assert request.method == "GET"
        assert request.url.host == "staging.bank.example"
        assert request.headers["authorization"] == "Bearer super-secret-fixture"
        if request.url.path.endswith("ACC-100"):
            return httpx.Response(200, text="should-not-be-saved")
        return httpx.Response(403, text="denied")

    result = await run_read_only(config, transport=httpx.MockTransport(respond))
    assert len(calls) == 2
    assert result["summary"]["potential_findings"] == 1
    assert result["summary"]["passed"] == 1
    assert "super-secret" not in str(result)
    assert "should-not-be-saved" not in str(result)
    assert "Authorization" not in str(result)
    assert "USER_B" in str(sanitized_plan(config))


@pytest.mark.asyncio
async def test_read_only_fails_closed_without_roe_and_secrets(monkeypatch):
    cfg = Engagement.model_validate(manifest())
    monkeypatch.delenv("HYPOTHESIS_ENABLE_READONLY_PT", raising=False)
    monkeypatch.delenv("HYPOTHESIS_TOKEN_USER_B", raising=False)
    with pytest.raises(PermissionError):
        await run_read_only(cfg)
    monkeypatch.setenv("HYPOTHESIS_ENABLE_READONLY_PT", "1")
    monkeypatch.setenv("HYPOTHESIS_ROE_APPROVED", "1")
    with pytest.raises(PermissionError):
        await run_read_only(cfg)
