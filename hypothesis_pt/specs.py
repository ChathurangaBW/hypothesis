"""Safe API-spec normalization and hypothesis planning.

The importer deliberately discards authentication material, request bodies,
example values and server URLs. These must never be committed as run evidence.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import re
from typing import Any

HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}
SENSITIVE = ("transfer", "payment", "beneficiary", "account", "balance", "statement", "loan", "card")
TRANSITIONS = ("approve", "authorize", "confirm", "submit", "release", "cancel", "reverse")
LIMIT = 500


@dataclass(frozen=True)
class Operation:
    method: str
    path: str
    summary: str
    tags: tuple[str, ...]
    category: str


def _category(method: str, path: str) -> str:
    lower = path.lower()
    if any(k in lower for k in TRANSITIONS):
        return "state_transition"
    if any(k in lower for k in SENSITIVE):
        return "banking_business"
    if method in {"POST", "PUT", "PATCH", "DELETE"}:
        return "mutation"
    return "read"


def _clean_path(path: str) -> str:
    path = path.strip()
    if not path.startswith("/") or path.startswith("//") or "://" in path or len(path) > 300:
        raise ValueError("Invalid operation path")
    if any(x in path for x in ("\x00", "\r", "\n", "?", "#")):
        raise ValueError("Path contains unsupported characters")
    # Spec placeholders are allowed for modelling; they are never substituted for execution.
    return path


def _normalize(raw: list[Operation]) -> list[dict[str, Any]]:
    if len(raw) > LIMIT:
        raise ValueError("Too many operations (maximum 500)")
    unique = {}
    for op in raw:
        unique[(op.method, op.path)] = asdict(op)
    return list(sorted(unique.values(), key=lambda x: (x["path"], x["method"])))


def import_openapi(document: dict[str, Any]) -> list[dict[str, Any]]:
    if not isinstance(document, dict) or not isinstance(document.get("paths"), dict):
        raise ValueError("Expected OpenAPI JSON with a paths object")
    operations: list[Operation] = []
    for path, resource in document["paths"].items():
        cleaned = _clean_path(str(path))
        if not isinstance(resource, dict):
            continue
        for method, details in resource.items():
            if method.lower() not in HTTP_METHODS or not isinstance(details, dict):
                continue
            label = str(details.get("summary") or details.get("operationId") or "")[:120]
            tags = details.get("tags", [])
            tags = tuple(str(t)[:40] for t in tags[:5]) if isinstance(tags, list) else ()
            operations.append(Operation(method.upper(), cleaned, label, tags, _category(method.upper(), cleaned)))
    return _normalize(operations)


def _postman_path(url: Any) -> str:
    if isinstance(url, dict):
        parts = url.get("path")
        if isinstance(parts, list):
            return _clean_path("/" + "/".join(str(p) for p in parts))
        url = url.get("raw", "")
    if not isinstance(url, str):
        raise ValueError("Missing Postman URL")
    raw = url.split("?", 1)[0]
    raw = re.sub(r"^https?://[^/]+", "", raw)
    raw = re.sub(r"^\{\{[^}]+\}\}", "", raw)
    return _clean_path(raw if raw.startswith("/") else "/" + raw)


def import_postman(document: dict[str, Any]) -> list[dict[str, Any]]:
    if not isinstance(document, dict) or not isinstance(document.get("item"), list):
        raise ValueError("Expected Postman collection with item array")
    operations: list[Operation] = []

    def visit(items: list[Any], depth: int) -> None:
        if depth > 12:
            raise ValueError("Postman folder depth exceeded")
        for item in items:
            if not isinstance(item, dict):
                continue
            if isinstance(item.get("item"), list):
                visit(item["item"], depth + 1)
            req = item.get("request")
            if isinstance(req, dict):
                method = str(req.get("method", "GET")).upper()
                if method not in {m.upper() for m in HTTP_METHODS}:
                    continue
                path = _postman_path(req.get("url"))
                operations.append(Operation(method, path, str(item.get("name", ""))[:120],
                                            (), _category(method, path)))
                if len(operations) > LIMIT:
                    raise ValueError("Too many operations")

    visit(document["item"], 0)
    return _normalize(operations)


def import_operations(source: str, document: Any) -> list[dict[str, Any]]:
    if len(json.dumps(document)) > 1_000_000:
        raise ValueError("Specification exceeds 1 MB")
    if source == "openapi":
        result = import_openapi(document)
    elif source == "postman":
        result = import_postman(document)
    else:
        raise ValueError("Unsupported specification format")
    if not result:
        raise ValueError("No supported operations found")
    return result


def plan_hypotheses(operations: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Candidates, not validated findings or executable exploit instructions."""
    plans: list[dict[str, str]] = []
    for op in operations:
        method, path = op["method"], op["path"]
        category = op["category"]
        cases: list[tuple[str, str, str]] = []
        if method in {"GET", "HEAD"} and ("{" in path or any(x in path.lower() for x in ("account", "statement", "beneficiary"))):
            cases.append(("Object ownership / BOLA", "Compare approved test accounts and expected object ownership", "high"))
        if category == "state_transition":
            cases.append(("Workflow state integrity", "Compare permitted prior states and authorization roles with expected transition policy", "high"))
            if "approv" in path.lower() or "release" in path.lower():
                cases.append(("Separation of duties", "Ensure a payment initiator cannot also authorize final approval", "critical"))
        if category == "banking_business" and method != "GET":
            cases.append(("Transaction business invariant", "Review transaction-limit, ownership, replay and approval-policy invariants", "high"))
        if re.search(r"(admin|internal|privileg|manage)", path, re.I):
            cases.append(("Function-level authorization / BFLA", "Compare explicitly permitted role matrix against route authorization", "high"))
        for label, rationale, severity in cases:
            if len(plans) >= 1000:
                break
            plans.append({
                "id": f"CAND-{len(plans)+1:04d}",
                "method": method, "path": path,
                "title": label, "rationale": rationale,
                "severity_hint": severity,
                "state": "proposed_unverified",
                "execution": "manual_policy_and_fixture_required",
            })
    return plans
