from copy import deepcopy
import sqlite3

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from hypothesis_pt.capture import WorkflowCapture, build_graph, capture_record, example_capture
from hypothesis_pt.storage import RunStore
from hypothesis_pt import web


def test_graph_keeps_identities_and_evidence_separate():
    source = example_capture()
    # Same principal in two roles must remain one principal, with two sessions.
    source["sessions"][1]["principal"] = "person-a"
    capture = WorkflowCapture.model_validate(source)
    graph = build_graph(capture)
    kinds = [node["kind"] for node in graph["nodes"]]
    assert kinds.count("principal") == 1
    assert kinds.count("session") == 2
    assert kinds.count("role") == 2
    labels = {node["id"]: node["label"] for node in graph["nodes"]}
    transitions = [edge for edge in graph["edges"] if edge["label"] == "observed_transition"]
    assert {(labels[e["from"]], labels[e["to"]]) for e in transitions} == {
        ("absent", "draft"), ("draft", "pending"), ("pending", "approved")}
    assert {e["evidence"][0] for e in transitions} == {"obs-1", "obs-2", "obs-3"}
    assert graph["invariants"] == []
    assert all(e["basis"] == "observed" for e in graph["edges"])
    assert graph == build_graph(capture)


def test_synthetic_self_approval_example_has_two_roles_for_one_principal():
    source = example_capture(self_approval=True)
    assert source["sessions"][0]["principal"] == source["sessions"][1]["principal"]
    assert source["sessions"][0]["role"] != source["sessions"][1]["role"]
    assert WorkflowCapture.model_validate(source)


def test_denied_transition_is_only_an_attempt():
    source = example_capture()
    source["observations"][-1]["status"] = 403
    graph = build_graph(WorkflowCapture.model_validate(source))
    assert len([e for e in graph["edges"] if e["label"] == "observed_transition"]) == 2
    assert any("obs-3" in e["evidence"] and e["label"] == "attempted" for e in graph["edges"])


def test_tenants_and_origins_do_not_merge_objects():
    source = example_capture()
    source["sessions"][1]["tenant"] = "other-tenant"
    graph = build_graph(WorkflowCapture.model_validate(source))
    assert len([n for n in graph["nodes"] if n["kind"] == "object"]) == 2
    source["sessions"][1]["tenant"] = "staff"
    source["scope"]["approved_origins"].append("https://other.example")
    source["observations"][-1]["origin"] = "https://other.example"
    graph = build_graph(WorkflowCapture.model_validate(source))
    assert len([n for n in graph["nodes"] if n["kind"] == "object"]) == 2


@pytest.mark.parametrize("change", [
    lambda x: x["observations"][0].update(origin="https://bank.example.evil"),
    lambda x: x["observations"][0].update(origin="https://bank.example:444"),
    lambda x: x["observations"][0].update(session_id="missing"),
    lambda x: x["observations"][0].update(id="obs-2"),
    lambda x: x["sessions"][0].update(id="checker-session"),
    lambda x: x["observations"][0].update(headers={"Authorization": "secret"}),
    lambda x: x["observations"][0].update(route="/payments?token=secret"),
    lambda x: x["observations"][0].update(route="https://bank.example/payments"),
    lambda x: x["observations"][0].update(route="/../admin"),
    lambda x: x["observations"][0].update(status="200"),
    lambda x: x["observations"][0].update(status=999),
    lambda x: x["observations"][0].update(state_before=None),
    lambda x: x["scope"].update(environment="production"),
    lambda x: x["scope"].update(approval_reference=""),
    lambda x: x["scope"].update(approved_origins=["https://user:password@bank.example"]),
    lambda x: x["scope"].update(approved_origins=["https://bank.example/path"]),
])
def test_invalid_or_out_of_scope_capture_is_rejected(change):
    source = deepcopy(example_capture())
    change(source)
    with pytest.raises(ValidationError):
        WorkflowCapture.model_validate(source)


def test_origin_canonicalization():
    source = example_capture()
    source["scope"]["approved_origins"] = ["https://BANK.EXAMPLE:443/"]
    capture = WorkflowCapture.model_validate(source)
    assert capture.scope.approved_origins == ["https://bank.example"]


def test_workflow_survives_restart_and_detects_tampering(tmp_path):
    path = str(tmp_path / "captures.db")
    record = capture_record(WorkflowCapture.model_validate(example_capture()))
    RunStore(path).save_workflow(record)
    store = RunStore(path)
    assert store.get_workflow(record["id"]) == record
    assert store.list_workflows()[0]["summary"]["observations"] == 3
    assert store.list_runs() == []
    with sqlite3.connect(path) as db:
        db.execute("UPDATE workflows SET payload='{}' WHERE id=?", (record["id"],))
    with pytest.raises(ValueError, match="integrity"):
        store.get_workflow(record["id"])
    with pytest.raises(ValueError, match="integrity"):
        store.list_workflows()


def test_workflow_api_roundtrip_and_rejected_import_is_not_saved(tmp_path):
    store = RunStore(str(tmp_path / "api.db"))
    web.app.dependency_overrides[web.get_store] = lambda: store
    try:
        with TestClient(web.app) as client:
            source = client.get("/api/workflows/example").json()
            response = client.post("/api/workflows", json=source)
            assert response.status_code == 201
            record = response.json()
            assert client.get("/api/workflows/" + record["id"]).json() == record
            source["observations"][0]["origin"] = "https://outside.example"
            assert client.post("/api/workflows", json=source).status_code == 422
            assert len(client.get("/api/workflows").json()) == 1
            assert client.get("/api/workflows/missing").status_code == 404
            with sqlite3.connect(store.db_path) as db:
                db.execute("UPDATE workflows SET payload='{}'")
            assert client.get("/api/workflows/" + record["id"]).status_code == 409
    finally:
        web.app.dependency_overrides.clear()
