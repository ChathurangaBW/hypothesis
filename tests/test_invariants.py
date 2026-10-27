from copy import deepcopy
import sqlite3

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from hypothesis_pt import web
from hypothesis_pt.capture import WorkflowCapture, capture_record, example_capture
from hypothesis_pt.core import digest
from hypothesis_pt.invariants import InvariantPolicy, assess_workflow, example_policy
from hypothesis_pt.storage import RunStore


def fixture_workflow(*, same_principal=False, approval_status=200):
    source = example_capture()
    if same_principal:
        source["sessions"][1]["principal"] = "person-a"
    source["observations"][-1]["status"] = approval_status
    return capture_record(WorkflowCapture.model_validate(source))


def test_sod_only_flags_same_principal_after_successful_initiation():
    safe = fixture_workflow()
    safe_result = assess_workflow(safe, InvariantPolicy.model_validate(example_policy(safe)))
    assert safe_result["summary"]["not_tested"] == 1
    assert safe_result["findings"] == []

    workflow = fixture_workflow(same_principal=True)
    policy = InvariantPolicy.model_validate(example_policy(workflow))
    result = assess_workflow(workflow, policy)
    assert result["summary"]["potential_violation"] == 1
    assert result["findings"][0]["status"] == "requires_human_validation"
    evidence = result["evaluations"][0]["evidence"]
    assert evidence["observation_ids"] == ["obs-1", "obs-3"]
    assert digest({k: v for k, v in evidence.items() if k != "sha256"}) == evidence["sha256"]
    assert result["workflow_source_sha256"] == workflow["source_sha256"]


@pytest.mark.parametrize(("status", "outcome"), [(403, "protected"), (500, "inconclusive"),
                                                 (302, "inconclusive"), (200, "potential_violation")])
def test_sod_approval_status_classification(status, outcome):
    workflow = fixture_workflow(same_principal=True, approval_status=status)
    result = assess_workflow(workflow, InvariantPolicy.model_validate(example_policy(workflow)))
    assert result["evaluations"][0]["outcome"] == outcome


def test_sod_does_not_join_wrong_identity_or_reverse_time():
    source = example_capture()
    source["sessions"][1]["principal"] = "person-a"
    source["observations"] = list(reversed(source["observations"]))
    workflow = capture_record(WorkflowCapture.model_validate(source))
    result = assess_workflow(workflow, InvariantPolicy.model_validate(example_policy(workflow)))
    assert result["summary"]["not_tested"] == 1

    source = example_capture()
    source["sessions"][1].update(principal="person-a", tenant="different")
    workflow = capture_record(WorkflowCapture.model_validate(source))
    result = assess_workflow(workflow, InvariantPolicy.model_validate(example_policy(workflow)))
    assert result["summary"]["not_tested"] == 1


def deny_policy(workflow):
    return {"schema_version": "1", "workflow_id": workflow["id"],
            "workflow_source_sha256": workflow["source_sha256"], "author": "bank-sme",
            "specification_reference": "APPROVED-ROLE-MATRIX-1", "rules": [
                {"id": "DENY-CHECKER", "kind": "deny_operation",
                 "title": "This checker is not authorized to approve this object",
                 "operation": {"origin": "https://bank.example", "method": "POST",
                               "route": "/payments/{payment}/approve", "action": "approve"},
                 "actor": {"principal": "person-b", "role": "checker", "tenant": "staff"},
                 "object": {"kind": "payment", "alias": "payment-a"}}]}


@pytest.mark.parametrize(("status", "outcome"), [(200, "potential_violation"),
                                                 (401, "protected"), (403, "protected"),
                                                 (409, "inconclusive")])
def test_explicit_denial_oracle(status, outcome):
    workflow = fixture_workflow(approval_status=status)
    policy = InvariantPolicy.model_validate(deny_policy(workflow))
    result = assess_workflow(workflow, policy)
    assert result["evaluations"][0]["outcome"] == outcome
    assert result["evaluations"][0]["evidence"]["observation_ids"] == ["obs-3"]


def test_rule_no_match_is_not_claimed_as_protected():
    workflow = fixture_workflow()
    rule = deny_policy(workflow)
    rule["rules"][0]["actor"]["principal"] = "unknown"
    result = assess_workflow(workflow, InvariantPolicy.model_validate(rule))
    assert result["summary"]["not_tested"] == 1


def test_policy_binds_to_exact_workflow_and_scope():
    workflow = fixture_workflow()
    policy = deny_policy(workflow)
    policy["workflow_source_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="fingerprint"):
        assess_workflow(workflow, InvariantPolicy.model_validate(policy))
    policy = deny_policy(workflow)
    policy["rules"][0]["operation"]["origin"] = "https://outside.example"
    with pytest.raises(ValueError, match="scope"):
        assess_workflow(workflow, InvariantPolicy.model_validate(policy))


@pytest.mark.parametrize("mutation", [
    lambda p: p["rules"][0]["operation"].update(route="/payments?secret=value"),
    lambda p: p["rules"][0]["operation"].update(method="TRACE"),
    lambda p: p["rules"][0]["actor"].update(principal=None, role=None),
    lambda p: p["rules"][0].update(unexpected="secret"),
    lambda p: p["rules"].append(deepcopy(p["rules"][0])),
])
def test_policy_validation_rejects_unsafe_or_ambiguous_specs(mutation):
    workflow = fixture_workflow()
    policy = deny_policy(workflow)
    mutation(policy)
    with pytest.raises(ValidationError):
        InvariantPolicy.model_validate(policy)


def test_assessment_persists_and_detects_tampering(tmp_path):
    store = RunStore(str(tmp_path / "investigations.db"))
    workflow = fixture_workflow(same_principal=True)
    store.save_workflow(workflow)
    assessment = assess_workflow(workflow, InvariantPolicy.model_validate(example_policy(workflow)))
    store.save_assessment(assessment)
    reopened = RunStore(store.db_path)
    assert reopened.get_assessment(assessment["id"]) == assessment
    assert reopened.list_assessments(workflow["id"])[0]["summary"]["potential_violation"] == 1
    with sqlite3.connect(store.db_path) as db:
        db.execute("UPDATE assessments SET payload='{}' WHERE id=?", (assessment["id"],))
    with pytest.raises(ValueError, match="integrity"):
        reopened.get_assessment(assessment["id"])
    with pytest.raises(ValueError, match="integrity"):
        reopened.list_assessments(workflow["id"])


def test_assessment_api_and_untrusted_policy_refusal(tmp_path):
    store = RunStore(str(tmp_path / "api.db"))
    web.app.dependency_overrides[web.get_store] = lambda: store
    try:
        with TestClient(web.app) as client:
            assert client.get("/api/workflows/example?scenario=self_approval").json()["sessions"][1]["principal"] == "person-a"
            assert client.get("/api/workflows/example?scenario=production").status_code == 422
            workflow = fixture_workflow(same_principal=True)
            store.save_workflow(workflow)
            path = "/api/workflows/" + workflow["id"]
            policy = client.get(path + "/policy-example")
            assert policy.status_code == 200
            result = client.post(path + "/assessments", json=policy.json()).json()
            assert result["summary"]["potential_violation"] == 1
            assert client.get("/api/assessments/" + result["id"]).json() == result
            assert len(client.get(path + "/assessments").json()) == 1
            invalid = policy.json()
            invalid["workflow_source_sha256"] = "f" * 64
            assert client.post(path + "/assessments", json=invalid).status_code == 422
            assert client.post(path + "/assessments", json={"url": "https://anywhere"}).status_code == 422
            assert client.get("/api/assessments/missing").status_code == 404
            assert len(client.get(path + "/assessments").json()) == 1
    finally:
        web.app.dependency_overrides.clear()


def test_policy_example_only_allowed_for_synthetic(tmp_path):
    store = RunStore(str(tmp_path / "api.db"))
    source = example_capture()
    source["scope"]["environment"] = "staging"
    workflow = capture_record(WorkflowCapture.model_validate(source))
    store.save_workflow(workflow)
    web.app.dependency_overrides[web.get_store] = lambda: store
    try:
        with TestClient(web.app) as client:
            assert client.get("/api/workflows/" + workflow["id"] + "/policy-example").status_code == 422
    finally:
        web.app.dependency_overrides.clear()
