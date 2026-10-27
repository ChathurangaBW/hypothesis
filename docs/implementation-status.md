# Hypothesis implementation status

This repository implements an incremental, offline foundation for the proposed banking VAPT platform. The target architecture is an orchestrated, stateful system with scoped workers, shared application knowledge, deterministic oracles and human review. A complete banking deployment requires separately approved engagement controls and infrastructure.

| Requirement | Present state | Next required work |
| --- | --- | --- |
| Control plane and scope | Sanitized captures declare engagement, allowed origins, environment and approval reference. Demo execution is local only. | Verified engagement registry, identity/role based access, approved windows, operation approvals and kill switch. |
| Discovery and state graph | Strict JSON import of test-session observations; deterministic actor, session, role, object and successful state-transition graph. | Playwright + HTTPX collectors that emit sanitized observation contracts, and persistent Neo4j graph storage. |
| Business logic reasoning | Fixed synthetic hypotheses plus externally supplied invariant rules. | Spec-grounded candidate generation and risk/coverage ranking, reviewed before execution. |
| Security invariant oracle | `deny_operation` and `separation_of_duties` rules; version-bound capture evidence, explicit not-tested/inconclusive outcomes. | Rich state assertions, owner relationships, expected response predicates and pre/post transaction-state verification. |
| Execution engine | Deterministic in-memory synthetic bank only. | Sandboxed workers with exact allowlists, test identities, budgets, rate limits and two-stage approval for mutation. |
| Evidence and audit | Local SQLite record hashes; simulator runs have a hash chain. | Append-only off-host event ledger, encrypted artifacts, key management, attestation and retention policy. |
| Run state and task queue | Local SQLite and synchronous FastAPI operations. | Postgres run/checkpoint models, Redis worker queue and recoverable LangGraph orchestration. |
| Reasoning agents | Structured static planner for synthetic checks. | Agents SDK/LangGraph orchestration for discovery, logic, planning and validation, constrained to sanitized metadata. |
| UI and findings | Local dashboard, capture import, policy evaluation, evidence IDs and human-review flags. | Authentication, independent review workflow, CVSS/CBSL mapping, exports and retest tracking. |
| Mobile | Not implemented. | Approved Appium/Frida worker integration, only after Web/API safety gates. |

## Suggested next implementation slices

1. **Capture adapters:** passive Playwright/HTTPX observation exporters for a dedicated test environment. Do not store cookies, credentials, requests, responses or customer data; validate schema and scope before importing.
2. **Engagement control plane:** persist approved principals, route templates, exact origin and method allowlists, timing windows and explicit approvals per mutation type. Independent policy enforcement must apply to every worker action.
3. **Sandboxed stateful execution:** fixture-backed actions, idempotency keys, read-only default, deterministic before/after state checks, bounded retries, emergency stop and per-action audit events.
4. **Durable graph and inference:** Neo4j + Postgres models and resumable orchestrator checkpoints. Introduce model-assisted hypotheses only on an approved data-processing boundary; all execution proposals must be policy checked.
5. **Independent review:** verified vulnerability lifecycle, CVSS and project-specific mappings, evidence signing, reproducibility and retest status.

Before any external execution, the bank must confirm the complete rules of engagement, synthetic accounts/fixtures, mutation classes, permitted windows and AI processing location. The existing importer alone cannot prove any of those authorizations.

## Acceptance criteria for the current slice

- Importing an observation with an undeclared origin or raw credential-bearing field must fail validation.
- A capture must maintain distinct sessions and roles for the same principal and must not infer transitions from denied HTTP outcomes.
- Only an explicit reviewer-supplied rule tied to the correct capture fingerprint may produce a candidate finding.
- Same-principal initiation and approval of the same object must be flagged when approval succeeds; differing principals must not be flagged.
- A missing matching observation must be `not_tested` and a non-authorization error must be `inconclusive`.
- Evidence fingerprint mismatches must be visible; no imported observation may trigger live network execution.

These behaviors are covered by unit/API tests and can be exercised in the local dashboard with the synthetic self-approval example.
