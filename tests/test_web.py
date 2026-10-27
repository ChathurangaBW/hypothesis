from fastapi.testclient import TestClient

from hypothesis_pt import web


def test_api_run_and_verify(tmp_path, monkeypatch):
    monkeypatch.setenv("HYPOTHESIS_DB", str(tmp_path / "runs.sqlite3"))
    web.get_store.cache_clear()
    with TestClient(web.app) as client:
        health = client.get("/api/health")
        assert health.status_code == 200
        assert health.json()["live_target_execution"] is False
        response = client.post("/api/runs", json={"scenario": "vulnerable"})
        assert response.status_code == 201
        run = response.json()
        assert len(run["findings"]) == 2
        assert client.get("/api/runs/" + run["id"]).status_code == 200
        assert client.get("/api/runs/" + run["id"] + "/verify").json()["verified"] is True
        assert len(client.get("/api/runs").json()) == 1
    web.get_store.cache_clear()


def test_api_does_not_allow_live_targets(tmp_path, monkeypatch):
    monkeypatch.setenv("HYPOTHESIS_DB", str(tmp_path / "runs.sqlite3"))
    web.get_store.cache_clear()
    with TestClient(web.app) as client:
        assert client.post("/api/runs", json={"scenario": "production"}).status_code == 422
        assert client.post("/api/runs", json={"scenario": "secure", "url": "https://example.com"}).status_code == 422
        assert client.get("/api/runs/no-such-id").status_code == 404
    web.get_store.cache_clear()
