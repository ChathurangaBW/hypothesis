"""Stateful security-invariant investigation using a synthetic banking environment.

There is deliberately no network client here. Real-target adapters must separately
implement strict engagement scoping, authorization and human approval gates.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
from typing import Any
from uuid import uuid4


def digest(payload: Any) -> str:
    wire = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(wire.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Identity:
    principal: str
    role: str
    tenant: str


@dataclass(frozen=True)
class Hypothesis:
    id: str
    invariant: str
    workflow: str
    rationale: str
    expected: str
    risk: str


BANK_GRAPH = {
    "nodes": [
        {"id": "account", "kind": "resource", "label": "Bank account"},
        {"id": "statement", "kind": "operation", "label": "Read account statement"},
        {"id": "draft", "kind": "state", "label": "Payment draft"},
        {"id": "pending", "kind": "state", "label": "Pending approval"},
        {"id": "approved", "kind": "state", "label": "Approved payment"},
        {"id": "maker", "kind": "role", "label": "Maker"},
        {"id": "checker", "kind": "role", "label": "Checker"},
    ],
    "edges": [
        {"from": "account", "to": "statement", "label": "owner can read"},
        {"from": "maker", "to": "draft", "label": "create"},
        {"from": "draft", "to": "pending", "label": "submit"},
        {"from": "checker", "to": "approved", "label": "approve if distinct principal"},
        {"from": "pending", "to": "approved", "label": "valid transition"},
    ],
    "invariants": [
        {"id": "INV-OWNERSHIP", "rule": "A different customer must not read another customer's account"},
        {"id": "INV-SOD", "rule": "A payment initiator must not approve their own payment, even with a checker role"},
    ],
}


class HypothesisPlanner:
    """Produce hypotheses from explicit business invariants, not scanner signatures."""

    def generate(self) -> list[Hypothesis]:
        return [
            Hypothesis(
                id="HYP-OWNERSHIP-001",
                invariant="INV-OWNERSHIP",
                workflow="account / statement",
                rationale="Test cross-customer object authorization using two synthetic identities",
                expected="Access to the other customer's account is denied (HTTP 403)",
                risk="high",
            ),
            Hypothesis(
                id="HYP-SOD-001",
                invariant="INV-SOD",
                workflow="draft -> pending -> approved",
                rationale="Check maker/checker segregation across sessions with the same principal",
                expected="Initiating principal cannot approve their payment (HTTP 403)",
                risk="critical",
            ),
        ]


class SyntheticBank:
    """Deterministic isolated banking model; no real services or transfers."""

    def __init__(self, vulnerable: bool = False):
        self.vulnerable = vulnerable
        self.accounts = {"ACC-100": "customer-a", "ACC-200": "customer-b"}
        self.payments: dict[str, dict[str, Any]] = {}
        self.sequence = 0

    def read_statement(self, actor: Identity, account_id: str) -> dict[str, Any]:
        owner = self.accounts.get(account_id)
        if owner is None:
            return {"status": 404, "code": "account_not_found"}
        if actor.tenant != "retail" or (not self.vulnerable and actor.principal != owner):
            return {"status": 403, "code": "access_denied"}
        return {"status": 200, "code": "statement_retrieved", "account": account_id}

    def create_payment(self, actor: Identity, account_id: str) -> dict[str, Any]:
        if actor.role != "maker" or actor.tenant != "staff":
            return {"status": 403, "code": "access_denied"}
        self.sequence += 1
        payment_id = f"PAY-{self.sequence:03d}"
        self.payments[payment_id] = {"maker": actor.principal, "account": account_id, "status": "draft"}
        return {"status": 201, "payment": payment_id, "state": "draft"}

    def submit_payment(self, actor: Identity, payment_id: str) -> dict[str, Any]:
        payment = self.payments.get(payment_id)
        if payment is None:
            return {"status": 404, "code": "not_found"}
        if payment["maker"] != actor.principal or payment["status"] != "draft":
            return {"status": 403, "code": "invalid_transition"}
        payment["status"] = "pending"
        return {"status": 200, "state": "pending"}

    def approve_payment(self, actor: Identity, payment_id: str) -> dict[str, Any]:
        payment = self.payments.get(payment_id)
        if payment is None:
            return {"status": 404, "code": "not_found"}
        if actor.role != "checker" or actor.tenant != "staff":
            return {"status": 403, "code": "access_denied"}
        if payment["status"] != "pending":
            return {"status": 409, "code": "invalid_transition"}
        if not self.vulnerable and payment["maker"] == actor.principal:
            return {"status": 403, "code": "separation_of_duties"}
        payment["status"] = "approved"
        return {"status": 200, "state": "approved"}


def _observation(hypothesis: Hypothesis, observed: dict[str, Any], steps: list[dict[str, Any]]) -> dict[str, Any]:
    violated = observed["status"] in (200, 201, 202, 204)
    evidence = {
        "hypothesis_id": hypothesis.id,
        "expected_status": 403,
        "observed_status": observed["status"],
        "observed_code": observed.get("code", observed.get("state")),
        "steps": steps,
        "result": "violation" if violated else "protected",
    }
    evidence["sha256"] = digest(evidence)
    return {
        "hypothesis": asdict(hypothesis),
        "outcome": "finding" if violated else "passed",
        "evidence": evidence,
    }


def investigate(hypothesis: Hypothesis, vulnerable: bool) -> dict[str, Any]:
    # Each hypothesis gets a fresh sandbox: tests cannot contaminate each other.
    bank = SyntheticBank(vulnerable=vulnerable)
    if hypothesis.id == "HYP-OWNERSHIP-001":
        other_customer = Identity("customer-b", "customer", "retail")
        result = bank.read_statement(other_customer, "ACC-100")
        return _observation(hypothesis, result, [
            {"action": "read_statement", "actor": "customer-b", "object": "ACC-100", "status": result["status"]},
        ])
    if hypothesis.id == "HYP-SOD-001":
        maker = Identity("employee-7", "maker", "staff")
        checker_same_person = Identity("employee-7", "checker", "staff")
        created = bank.create_payment(maker, "ACC-100")
        if created["status"] != 201:
            raise RuntimeError("Demo setup could not create synthetic payment")
        payment_id = created["payment"]
        submitted = bank.submit_payment(maker, payment_id)
        if submitted["status"] != 200:
            raise RuntimeError("Demo setup could not submit synthetic payment")
        result = bank.approve_payment(checker_same_person, payment_id)
        return _observation(hypothesis, result, [
            {"action": "create_payment", "actor": "employee-7 (maker)", "object": payment_id, "status": 201},
            {"action": "submit_payment", "actor": "employee-7 (maker)", "object": payment_id, "status": 200},
            {"action": "approve_payment", "actor": "employee-7 (checker)", "object": payment_id, "status": result["status"]},
        ])
    raise ValueError(f"Unsupported hypothesis: {hypothesis.id}")


def run_assessment(scenario: str) -> dict[str, Any]:
    if scenario not in {"secure", "vulnerable"}:
        raise ValueError("Only synthetic scenarios 'secure' and 'vulnerable' are supported")
    hypotheses = HypothesisPlanner().generate()
    observations = [investigate(h, scenario == "vulnerable") for h in hypotheses]
    findings = [
        {
            "id": f"F-{index:03d}",
            "hypothesis_id": item["hypothesis"]["id"],
            "title": item["hypothesis"]["invariant"] + " violated",
            "risk": item["hypothesis"]["risk"],
            "workflow": item["hypothesis"]["workflow"],
            "evidence_sha256": item["evidence"]["sha256"],
            "status": "requires_human_validation",
        }
        for index, item in enumerate((i for i in observations if i["outcome"] == "finding"), start=1)
    ]
    return {
        "id": str(uuid4()),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "environment": "OFFLINE SYNTHETIC DEMO — NOT A REAL BANK ASSESSMENT",
        "scenario": scenario,
        "graph": BANK_GRAPH,
        "observations": observations,
        "findings": findings,
        "summary": {
            "hypotheses": len(hypotheses),
            "passed": sum(i["outcome"] == "passed" for i in observations),
            "potential_findings": len(findings),
            "coverage": [h.invariant for h in hypotheses],
        },
    }
