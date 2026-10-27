from hypothesis_pt.core import BANK_GRAPH, HypothesisPlanner, SyntheticBank, Identity, digest, run_assessment


def test_graph_has_explicit_invariants():
    assert {i["id"] for i in BANK_GRAPH["invariants"]} == {"INV-OWNERSHIP", "INV-SOD"}
    assert len(HypothesisPlanner().generate()) == 2


def test_secure_sandbox_denies_cross_customer():
    bank = SyntheticBank()
    assert bank.read_statement(Identity("customer-b", "customer", "retail"), "ACC-100")["status"] == 403


def test_secure_sandbox_denies_self_approval_across_roles():
    bank = SyntheticBank()
    maker = Identity("staff-1", "maker", "staff")
    created = bank.create_payment(maker, "ACC-100")
    assert bank.submit_payment(maker, created["payment"])["status"] == 200
    assert bank.approve_payment(Identity("staff-1", "checker", "staff"), created["payment"])["status"] == 403
    assert bank.approve_payment(Identity("staff-2", "checker", "staff"), created["payment"])["status"] == 200


def test_secure_scenario_no_findings():
    result = run_assessment("secure")
    assert result["summary"]["potential_findings"] == 0
    assert result["summary"]["passed"] == 2


def test_vulnerable_scenario_finds_two_distinct_invariant_violations():
    result = run_assessment("vulnerable")
    assert {x["hypothesis_id"] for x in result["findings"]} == {"HYP-OWNERSHIP-001", "HYP-SOD-001"}
    assert all(x["status"] == "requires_human_validation" for x in result["findings"])
    for item in result["observations"]:
        evidence = item["evidence"].copy()
        signature = evidence.pop("sha256")
        assert digest(evidence) == signature


def test_rejects_external_execution_modes():
    import pytest
    with pytest.raises(ValueError):
        run_assessment("production")
