import json

import httpx
import pytest
from hypothesis_pt.reasoning import local_hypotheses


@pytest.mark.asyncio
async def test_model_disabled_by_default(monkeypatch):
    monkeypatch.delenv("HYPOTHESIS_ALLOW_LOCAL_AI", raising=False)
    with pytest.raises(PermissionError):
        await local_hypotheses([])


@pytest.mark.asyncio
async def test_model_cannot_add_out_of_scope_operations(monkeypatch):
    monkeypatch.setenv("HYPOTHESIS_ALLOW_LOCAL_AI", "1")
    monkeypatch.setenv("HYPOTHESIS_LOCAL_MODEL_URL", "http://127.0.0.1:11434")
    ops = [{"method": "GET", "path": "/accounts/{id}", "category": "banking_business", "summary": "Read"}]

    def respond(request):
        assert request.url.host == "127.0.0.1"
        assert "/api/generate" == request.url.path
        return httpx.Response(200, json={"response": json.dumps({"hypotheses": [
            {"title": "Ownership", "method": "GET", "path": "/accounts/{id}",
             "expected_security_invariant": "Only owner can read", "rationale": "Potential BOLA"},
            {"title": "Unsafe", "method": "POST", "path": "/internal/transfer",
             "expected_security_invariant": "No check", "rationale": "Out of scope"},
        ]})})

    result = await local_hypotheses(ops, transport=httpx.MockTransport(respond))
    assert len(result["hypotheses"]) == 1
    assert result["hypotheses"][0]["state"] == "unverified_model_suggestion"


@pytest.mark.asyncio
async def test_reject_nonlocal_inference(monkeypatch):
    monkeypatch.setenv("HYPOTHESIS_ALLOW_LOCAL_AI", "1")
    monkeypatch.setenv("HYPOTHESIS_LOCAL_MODEL_URL", "https://api.public.example")
    with pytest.raises(ValueError):
        await local_hypotheses([])
