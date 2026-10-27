import os
from fastapi.testclient import TestClient
from hypothesis_pt import web


def test_import_openapi_generate_candidates_and_get_history(tmp_path, monkeypatch):
    monkeypatch.setenv("HYPOTHESIS_DB", str(tmp_path / "runs.db"))
    web.get_store.cache_clear()
    doc = {"paths": {
        "/accounts/{accountId}": {"get": {"summary": "Read account", "security": [{"bearer": []}]}},
        "/payments/{paymentId}/approve": {"post": {"summary": "Authorize transaction"}},
    }, "servers": [{"url": "https://do-not-store.example"}]}
    with TestClient(web.app) as client:
        imported = client.post("/api/specs", json={"source": "openapi", "document": doc})
        assert imported.status_code == 201
        spec_id = imported.json()["id"]
        spec = client.get(f"/api/specs/{spec_id}").json()
        assert spec["operations"][0]["path"] == "/accounts/{accountId}"
        assert "do-not-store" not in str(spec)
        plan = client.get(f"/api/specs/{spec_id}/hypotheses").json()
        assert plan["count"] >= 3
        assert all(h["state"] == "proposed_unverified" for h in plan["candidates"])
        assert len(client.get("/api/specs").json()) == 1
        assert client.get("/api/specs/missing").status_code == 404
        assert client.post(f"/api/specs/{spec_id}/reason").status_code == 403
    web.get_store.cache_clear()


def test_readonly_execution_requires_config_approval_and_local_token(tmp_path, monkeypatch):
    monkeypatch.setenv("HYPOTHESIS_DB", str(tmp_path / "runs.db"))
    monkeypatch.setenv("HYPOTHESIS_ENABLE_READONLY_PT", "1")
    monkeypatch.setenv("HYPOTHESIS_ROE_APPROVED", "1")
    monkeypatch.setenv("HYPOTHESIS_ADMIN_TOKEN", "test-token-longer-than-24-chars")
    monkeypatch.delenv("HYPOTHESIS_ENGAGEMENT_PATH", raising=False)
    web.get_store.cache_clear()
    with TestClient(web.app) as client:
        assert client.get("/api/engagement").json()["configured"] is False
        assert client.post("/api/engagement/execute").status_code == 403
        assert client.post("/api/engagement/execute",
                           headers={"x-hypothesis-admin-token": "wrong"}).status_code == 403
        assert client.post("/api/engagement/execute",
                           headers={"x-hypothesis-admin-token": "test-token-longer-than-24-chars"}).status_code == 403
    web.get_store.cache_clear()


def test_engagement_manifest_only_from_local_file(tmp_path, monkeypatch):
    import json
    import pathlib
    from hypothesis_pt.engagement import Engagement
    manifest = {
        "title": "Synthetic UAT",
        "base_url": "https://staging.example.test",
        "approved_by": "Security team",
        "approval_reference": "ROE-123",
        "environment": "UAT",
        "probes": [{"id": "SAFE-GET", "path": "/api/accounts/TEST1",
                    "requester_profile": "TEST_USER_B"}]
    }
    file = tmp_path / "manifest.json"
    file.write_text(json.dumps(manifest))
    monkeypatch.setenv("HYPOTHESIS_ENGAGEMENT_PATH", str(file))
    monkeypatch.delenv("HYPOTHESIS_ENABLE_READONLY_PT", raising=False)
    with TestClient(web.app) as client:
        r = client.get("/api/engagement")
        assert r.status_code == 200
        assert r.json()["configured"] is True
        assert r.json()["probes"][0]["id"] == "SAFE-GET"
        assert r.json()["execution_enabled"] is False
