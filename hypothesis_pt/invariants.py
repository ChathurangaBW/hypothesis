"""Deterministic checks of sanitized observations against operator-supplied rules.

An observation is evidence of an HTTP outcome, not proof of business intent. Rules
must be supplied independently; this module never issues HTTP requests.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated, Literal
from uuid import uuid4

from pydantic import Field, model_validator

from .capture import Alias, CapturedObject, Contract, WorkflowCapture, canonical_origin
from .core import digest


class OperationSelector(Contract):
    origin: str
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
    route: str
    action: Alias

    @model_validator(mode="after")
    def validate_origin_and_route(self):
        # Reuse the same strict route/origin contract as captured observations.
        from .capture import Observation

        self.origin = canonical_origin(self.origin)
        Observation.route_template(self.route)
        return self


class ActorSelector(Contract):
    principal: Alias | None = None
    role: Alias | None = None
    tenant: Alias | None = None

    @model_validator(mode="after")
    def identify_actor(self):
        if self.principal is None and self.role is None:
            raise ValueError("Supply a principal or role to identify the expected denied actor")
        return self


class DenyOperation(Contract):
    id: Alias
    kind: Literal["deny_operation"]
    title: str = Field(min_length=1, max_length=160)
    operation: OperationSelector
    actor: ActorSelector
    object: CapturedObject | None = None


class SeparationOfDuties(Contract):
    id: Alias
    kind: Literal["separation_of_duties"]
    title: str = Field(min_length=1, max_length=160)
    initiate: OperationSelector
    approve: OperationSelector
    object_kind: Alias


Rule = Annotated[DenyOperation | SeparationOfDuties, Field(discriminator="kind")]


class InvariantPolicy(Contract):
    schema_version: Literal["1"] = "1"
    workflow_id: str = Field(min_length=36, max_length=36)
    workflow_source_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    author: Alias
    specification_reference: Alias
    rules: list[Rule] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def distinct_rules(self):
        if len({rule.id for rule in self.rules}) != len(self.rules):
            raise ValueError("Invariant IDs must be unique")
        return self


def _matches(item: dict, selector: OperationSelector) -> bool:
    return all(item[key] == getattr(selector, key) for key in ("origin", "method", "route", "action"))


def _classify(statuses: list[int]) -> str:
    if any(200 <= code < 300 for code in statuses):
        return "potential_violation"
    if statuses and all(code in (401, 403) for code in statuses):
        return "protected"
    return "inconclusive" if statuses else "not_tested"


def _evaluate_deny(rule: DenyOperation, capture: dict) -> tuple[str, list[str]]:
    sessions = {s["id"]: s for s in capture["sessions"]}
    matched = []
    for item in capture["observations"]:
        if not _matches(item, rule.operation):
            continue
        actor = sessions[item["session_id"]]
        if any(getattr(rule.actor, field) is not None and actor[field] != getattr(rule.actor, field)
               for field in ("principal", "role", "tenant")):
            continue
        if rule.object is not None and item["object"] != rule.object.model_dump():
            continue
        matched.append(item)
    return _classify([item["status"] for item in matched]), [item["id"] for item in matched]


def _evaluate_sod(rule: SeparationOfDuties, capture: dict) -> tuple[str, list[str]]:
    sessions = {s["id"]: s for s in capture["sessions"]}
    initiated: dict[tuple, list[str]] = {}
    approvals = []
    for item in capture["observations"]:
        actor = sessions[item["session_id"]]
        # Origin and tenant are part of object identity; aliases alone are insufficient.
        key = (item["origin"], actor["tenant"], item["object"]["kind"],
               item["object"]["alias"], actor["principal"])
        if item["object"]["kind"] != rule.object_kind:
            continue
        if _matches(item, rule.initiate) and 200 <= item["status"] < 300:
            initiated.setdefault(key, []).append(item["id"])
        if _matches(item, rule.approve) and key in initiated:
            approvals.append((item, initiated[key][-1]))
    evidence = list(dict.fromkeys(evidence_id for item, initiation in approvals
                                  for evidence_id in (initiation, item["id"])))
    return _classify([item["status"] for item, _ in approvals]), evidence


def assess_workflow(workflow: dict, policy: InvariantPolicy) -> dict:
    """Only compare a policy to the exact captured version it was authored for."""
    if policy.workflow_id != workflow["id"] or policy.workflow_source_sha256 != workflow["source_sha256"]:
        raise ValueError("Policy workflow ID or source fingerprint does not match the saved capture")
    # Validate integrity and shape independently of the storage layer.
    source = WorkflowCapture.model_validate(workflow["source"]).model_dump()
    if digest(source) != workflow["source_sha256"]:
        raise ValueError("Captured source fingerprint failed validation")
    if any(rule.operation.origin not in source["scope"]["approved_origins"]
           for rule in policy.rules if isinstance(rule, DenyOperation)):
        raise ValueError("Rule operation is outside the captured scope")
    if any((rule.initiate.origin not in source["scope"]["approved_origins"]
            or rule.approve.origin not in source["scope"]["approved_origins"])
           for rule in policy.rules if isinstance(rule, SeparationOfDuties)):
        raise ValueError("Rule operation is outside the captured scope")

    evaluations = []
    for rule in policy.rules:
        outcome, observations = (_evaluate_deny(rule, source) if isinstance(rule, DenyOperation)
                                 else _evaluate_sod(rule, source))
        evidence = {"rule_id": rule.id, "observation_ids": observations,
                    "source_sha256": workflow["source_sha256"], "outcome": outcome}
        evaluations.append({"rule_id": rule.id, "kind": rule.kind, "title": rule.title,
                            "outcome": outcome, "evidence": {**evidence, "sha256": digest(evidence)}})
    findings = [{"id": f"F-{index:03d}", "rule_id": item["rule_id"],
                 "title": item["title"], "evidence_sha256": item["evidence"]["sha256"],
                 "status": "requires_human_validation"}
                for index, item in enumerate(
                    (e for e in evaluations if e["outcome"] == "potential_violation"), start=1)]
    return {"id": str(uuid4()), "created_at": datetime.now(timezone.utc).isoformat(),
            "workflow_id": workflow["id"], "workflow_source_sha256": workflow["source_sha256"],
            "policy": policy.model_dump(), "policy_sha256": digest(policy.model_dump()),
            "evaluations": evaluations, "findings": findings,
            "summary": {key: sum(e["outcome"] == key for e in evaluations)
                        for key in ("potential_violation", "protected", "inconclusive", "not_tested")},
            "note": "Offline observation comparison only. Validate rules and outcomes with an independent reviewer."}


def example_policy(workflow: dict) -> dict:
    """A draft SOD rule for the bundled synthetic workflow; it is not auto-approved."""
    source = WorkflowCapture.model_validate(workflow["source"])
    if source.scope.environment != "synthetic":
        raise ValueError("Example rules are available for synthetic captures only")
    origin = source.scope.approved_origins[0]
    return {"schema_version": "1", "workflow_id": workflow["id"],
            "workflow_source_sha256": workflow["source_sha256"], "author": "demo-reviewer",
            "specification_reference": "DEMO-SOD-SPEC",
            "rules": [{"id": "INV-SOD", "kind": "separation_of_duties",
                       "title": "Payment initiator must not approve the same payment",
                       "initiate": {"origin": origin, "method": "POST", "route": "/payments",
                                    "action": "create"},
                       "approve": {"origin": origin, "method": "POST",
                                   "route": "/payments/{payment}/approve", "action": "approve"},
                       "object_kind": "payment"}]}
