# Hypothesis

**A workflow-aware, security-invariant-driven penetration-testing research platform.**

Version 0.1 is a runnable **offline synthetic prototype** with a sanitized workflow importer and independent business-invariant evaluator. It models a bank's state transitions, generates testable security hypotheses, executes multi-step checks in a deterministic simulator, and stores evidence fingerprints in SQLite.

> **Not a production pentesting agent.** It does not connect to any external applications, automatically capture browser traffic, invoke ZAP or MobSF, carry out real money movements, or guarantee regulatory-compliant VAPT delivery. There is no live target execution endpoint. Every potential finding requires human validation.

## Get running

Requires Python 3.11+.

```bash
git clone https://github.com/ChathurangaBW/hypothesis.git
cd hypothesis
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
hypothesis-pt serve
```

Open **http://127.0.0.1:8000**. Select *Vulnerable synthetic bank* and click **Run investigation**. The demo should flag two seeded violations: cross-customer account access (BOLA/IDOR) and maker/checker separation-of-duties failure. Select *Secure synthetic bank* and confirm no violations.

For an end-to-end **captured workflow review**, select **Load synthetic self-approval**, **Import workflow**, **Load synthetic SOD rule**, and **Evaluate saved observations**. The checker uses a second session with the **same principal** as the maker, so the independent separation-of-duties rule produces one candidate finding. The ordinary synthetic workflow uses a different checker principal and is appropriately marked *not tested* for same-person approval, not falsely marked *protected*.

Command-line mode:

```bash
hypothesis-pt demo vulnerable
hypothesis-pt demo secure
python -m pytest -q
```

Windows PowerShell activation: `.venv\\Scripts\\Activate.ps1`.

## How it works

```text
Explicit workflow graph + business invariants
                  |
           Hypothesis planner
                  |
           Stateful test engine
                  |
        Isolated synthetic bank
                  |
       Expected vs actual oracle
                  |
  Evidence fingerprint + chained ledger
                  |
          Human validation queue
```

The capture/invariant pathway is independent of the simulator:

```text
Operator-sanitized observation import (no HTTP replay)
                 |
       Typed identity/workflow graph
                 |
      Version-bound SME invariant policy
                 |
        Deterministic observation oracle
                 |
       Outcome + evidence fingerprints
                 |
        Independent human review
```

The initial graph has two hard-coded invariants:

- **INV-OWNERSHIP:** one customer must not access another customer's account.
- **INV-SOD:** a payment initiator must not approve the same payment, even after switching from maker to checker role.

The second hypothesis performs an actual **three-step stateful test**: create a payment as maker, submit it, then attempt approval as the same principal under a checker role. The simulator deliberately contains this bug in *vulnerable* mode.

## API

- `GET /` — dashboard.
- `GET /api/health` — execution capabilities.
- `GET /api/model` — workflow graph and generated hypotheses.
- `POST /api/runs` — only `{"scenario": "secure"}` or `{"scenario": "vulnerable"}`.
- `GET /api/runs` — last 100 run summaries.
- `GET /api/runs/{id}` — execution traces and potential findings.
- `GET /api/runs/{id}/verify` — hash-chain integrity check.
- `GET /api/workflows/example` — synthetic, separated-principal capture JSON. Add `?scenario=self_approval` for the prohibited role-switch demo.
- `POST /api/workflows` — import a strictly validated sanitized capture; returns a workflow ID, source fingerprint, observed graph and summary.
- `GET /api/workflows` / `GET /api/workflows/{id}` — list or inspect saved captures.
- `GET /api/workflows/{id}/policy-example` — unapproved SOD policy draft for **synthetic** workflows only.
- `POST /api/workflows/{id}/assessments` — evaluate explicit business invariants against the saved observations; **offline only**.
- `GET /api/workflows/{id}/assessments` / `GET /api/assessments/{id}` — list and inspect evaluation history.

SQLite file location: `HYPOTHESIS_DB` environment variable, default `./data/hypothesis.sqlite3`. Never store real bank credentials or customer data in this database.

## Workflow capture contract

The importer accepts manually sanitized observations from separately authorized test sessions. Each capture declares `scope` (engagement, approval reference, `synthetic`/`test`/`staging` environment and exact approved origins), pseudonymous `sessions` (principal, role, tenant), and `observations` (session ID, HTTP method, origin, **route template**, action, object alias, status and optional before/after states). For a complete working sample use `GET /api/workflows/example` or the dashboard's example button.

Routes must look like `/payments/{payment}/approve`. Queries, headers, tokens, cookies, raw URLs, payloads and bodies are rejected by the schema. The declared scope and approval reference are **operator assertions**, not validated authorization from the bank. The importer never connects to the declared origins. HTTP failures remain attempted operations in the graph; only successful responses create observed state-transition edges. This graph describes **what was seen**, not what should have been permitted.

## Reviewer-supplied invariant policies

Invariant policies are external business claims grounded in an approved role matrix or documented workflow specification. Each policy must cite the saved capture's `workflow_id` and exact `workflow_source_sha256` from the import response. Replacing or changing a capture invalidates that binding. For example, after importing the synthetic self-approval workflow:

```json
{
  "schema_version": "1",
  "workflow_id": "<id from the import response>",
  "workflow_source_sha256": "<source_sha256 from the import response>",
  "author": "bank-sme",
  "specification_reference": "APPROVED-SOD-MATRIX-1",
  "rules": [{
    "id": "INV-SOD",
    "kind": "separation_of_duties",
    "title": "The initiator may not approve the same payment",
    "initiate": {"origin": "https://bank.example", "method": "POST", "route": "/payments", "action": "create"},
    "approve": {"origin": "https://bank.example", "method": "POST", "route": "/payments/{payment}/approve", "action": "approve"},
    "object_kind": "payment"
  }]
}
```

Policies support two deterministic rule types:

- `separation_of_duties`: same principal across roles/sessions, same origin/tenant/object, successful prior initiation and later approval attempt. Detects successful prohibited self-approval or a clear 401/403 rejection.
- `deny_operation`: explicit operation selector, actor selector (principal and/or role, optional tenant), and optional object alias. Useful for SME-specified object/role authorization prohibitions; no ownership is inferred from object names.

Every rule yields one of `potential_violation` (a success contradicts a deny expectation), `protected` (every applicable attempt returned 401/403), `inconclusive` (other HTTP outcomes), or `not_tested` (no qualifying attempt). A rule with no evidence is **never** marked protected. All potential findings remain `requires_human_validation`; a reviewer must confirm the business rule, status semantics, actual data access and impact. Evidence uses observation IDs and SHA-256 digests; it deliberately excludes full HTTP bodies.

## Boundaries

1. The current engine has **no network access to targets**, no arbitrary command execution and no endpoint for user-defined URLs.
2. Simulator run evidence hashes form a **tamper-evident chain**; capture and assessment records use independent integrity hashes. Neither is immutable storage. Production use requires append-only off-host storage, signature/attestation and operational retention rules.
3. A red-team operator must approve target scope, identities, test windows, safe operations and inference/data residency before real adapters are added.
4. An AI-generated hypothesis alone is not a confirmed vulnerability. Finding reports deliberately carry `requires_human_validation`.

## Next milestones

1. Approved Playwright/HTTPX capture adapters that export **sanitized** observations through the importer, without persisting credentials or raw bank data.
2. Sandboxed replay with engagement-scoped operations, per-action approvals, rate limits, network allowlists and emergency stop.
3. Persisted graph store and durable job/checkpoint orchestration for multi-agent investigations.
4. Model-assisted hypothesis ranking with bank-approved inference, isolated from credentials.
5. Independent review, signed evidence export, retesting and reporting after validation.

See `/docs` for the interactive OpenAPI reference.
