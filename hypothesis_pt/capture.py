"""Import sanitized, authenticated observations; never replay captured traffic."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated, Literal
from urllib.parse import urlsplit
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .core import digest


Alias = Annotated[str, Field(min_length=1, max_length=100, pattern=r"^[A-Za-z0-9_.:-]+$")]


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


def canonical_origin(value: str) -> str:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Invalid origin") from exc
    if (parsed.scheme not in {"https", "http"} or not parsed.hostname
            or parsed.username is not None or parsed.password is not None
            or parsed.path not in {"", "/"} or parsed.query or parsed.fragment):
        raise ValueError("Use an HTTP(S) origin only, without credentials, path or query")
    host = parsed.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    default = 443 if parsed.scheme == "https" else 80
    return f"{parsed.scheme}://{host}" + (f":{port}" if port is not None and port != default else "")


class CaptureScope(Contract):
    engagement: Alias
    approval_reference: Alias
    environment: Literal["test", "staging", "synthetic"]
    approved_origins: list[str] = Field(min_length=1, max_length=20)

    @field_validator("approved_origins")
    @classmethod
    def origins(cls, values: list[str]) -> list[str]:
        return sorted(set(canonical_origin(value) for value in values))


class Session(Contract):
    id: Alias
    principal: Alias
    role: Alias
    tenant: Alias


class CapturedObject(Contract):
    kind: Alias
    alias: Alias


class Observation(Contract):
    id: Alias
    session_id: Alias
    origin: str
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
    route: str = Field(min_length=1, max_length=240)
    action: Alias
    object: CapturedObject
    status: int = Field(ge=100, le=599)
    state_before: Alias | None = None
    state_after: Alias | None = None

    @field_validator("origin")
    @classmethod
    def origin_only(cls, value: str) -> str:
        return canonical_origin(value)

    @field_validator("route")
    @classmethod
    def route_template(cls, value: str) -> str:
        # Normalized route templates only, never URLs, queries, headers or bodies.
        import re
        if not re.fullmatch(r"/(?:[A-Za-z0-9_{}.-]+/)*[A-Za-z0-9_{}.-]*", value):
            raise ValueError("Use a sanitized route template such as /payments/{payment}")
        if any(segment in {".", ".."} for segment in value.split("/")):
            raise ValueError("Relative path segments are not allowed")
        return value

    @model_validator(mode="after")
    def paired_states(self):
        if (self.state_before is None) != (self.state_after is None):
            raise ValueError("Supply both before and after states, or neither")
        return self


class WorkflowCapture(Contract):
    schema_version: Literal["1"] = "1"
    name: str = Field(min_length=1, max_length=120)
    scope: CaptureScope
    sessions: list[Session] = Field(min_length=1, max_length=100)
    observations: list[Observation] = Field(min_length=1, max_length=1000)

    @model_validator(mode="after")
    def references(self):
        sessions = {session.id for session in self.sessions}
        if len(sessions) != len(self.sessions):
            raise ValueError("Session IDs must be unique")
        ids = [item.id for item in self.observations]
        if len(set(ids)) != len(ids):
            raise ValueError("Observation IDs must be unique")
        for item in self.observations:
            if item.session_id not in sessions:
                raise ValueError("Observation references an unknown session")
            if item.origin not in self.scope.approved_origins:
                raise ValueError("Observation origin is outside the declared scope")
        return self


def build_graph(capture: WorkflowCapture) -> dict:
    nodes: dict[str, dict] = {}
    edges: dict[str, dict] = {}

    def node(kind, label, *identity):
        identifier = kind + ":" + digest([kind, *identity])[:24]
        nodes.setdefault(identifier, {"id": identifier, "kind": kind, "label": label})
        return identifier

    def edge(source, target, relation, evidence):
        identifier = digest([source, target, relation])[:24]
        item = edges.setdefault(identifier, {
            "id": identifier, "from": source, "to": target,
            "label": relation, "evidence": [], "basis": "observed",
        })
        if evidence not in item["evidence"]:
            item["evidence"].append(evidence)

    sessions = {session.id: session for session in capture.sessions}
    for item in capture.observations:
        actor = sessions[item.session_id]
        tenant = node("tenant", actor.tenant, actor.tenant)
        principal = node("principal", actor.principal, actor.tenant, actor.principal)
        role = node("role", actor.role, actor.tenant, actor.role)
        session = node("session", actor.id, actor.id)
        operation = node("operation", f"{item.method} {item.route} · {item.action}",
                         item.origin, item.method, item.route, item.action)
        resource = node("object", f"{item.object.kind}:{item.object.alias}",
                        item.origin, actor.tenant, item.object.kind, item.object.alias)
        for source, target, relation in [
            (principal, tenant, "observed_in_tenant"),
            (session, principal, "authenticated_as"),
            (session, role, "using_role"),
            (session, operation, "attempted"),
            (operation, resource, "observed_on"),
        ]:
            edge(source, target, relation, item.id)
        # Denied/error responses do not establish a successful lifecycle transition.
        if 200 <= item.status < 300 and item.state_before is not None:
            before = node("state", item.state_before, resource, item.state_before)
            after = node("state", item.state_after, resource, item.state_after)
            edge(resource, before, "observed_state", item.id)
            edge(resource, after, "observed_state", item.id)
            edge(before, after, "observed_transition", item.id)
            edge(operation, after, "observed_result", item.id)
    return {
        "nodes": sorted(nodes.values(), key=lambda n: n["id"]),
        "edges": sorted(edges.values(), key=lambda e: e["id"]),
        "invariants": [],
        "note": "Observed behavior only; expected business rules require independent specification.",
    }


def capture_record(capture: WorkflowCapture) -> dict:
    source = capture.model_dump()
    graph = build_graph(capture)
    record = {
        "id": str(uuid4()), "created_at": datetime.now(timezone.utc).isoformat(),
        "name": capture.name, "source": source, "graph": graph,
        "source_sha256": digest(source),
        "summary": {"sessions": len(capture.sessions), "observations": len(capture.observations),
                    "nodes": len(graph["nodes"]), "edges": len(graph["edges"])},
    }
    return record


def example_capture(self_approval: bool = False) -> dict:
    return {
        "schema_version": "1", "name": ("Synthetic prohibited self-approval workflow" if self_approval
                                          else "Synthetic payment approval workflow"),
        "scope": {"engagement": "demo", "approval_reference": "DEMO-ONLY",
                  "environment": "synthetic", "approved_origins": ["https://bank.example"]},
        "sessions": [
            {"id": "maker-session", "principal": "person-a", "role": "maker", "tenant": "staff"},
            {"id": "checker-session", "principal": "person-a" if self_approval else "person-b",
             "role": "checker", "tenant": "staff"},
        ],
        "observations": [
            {"id": oid, "session_id": sid, "origin": "https://bank.example", "method": "POST",
             "route": route, "action": action, "object": {"kind": "payment", "alias": "payment-a"},
             "status": status, "state_before": before, "state_after": after}
            for oid, sid, route, action, status, before, after in [
                ("obs-1", "maker-session", "/payments", "create", 201, "absent", "draft"),
                ("obs-2", "maker-session", "/payments/{payment}/submit", "submit", 200, "draft", "pending"),
                ("obs-3", "checker-session", "/payments/{payment}/approve", "approve", 200, "pending", "approved"),
            ]
        ],
    }
