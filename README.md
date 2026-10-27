# Hypothesis

**A workflow-aware, security-invariant-driven penetration-testing research platform.**

Version 0.1 is a runnable **offline synthetic prototype**. It models a bank's state transitions, generates testable security hypotheses, executes multi-step checks with separate identities, records reproducible traces, and stores tamper-evident evidence in SQLite.

> **Not a production pentesting agent.** It does not connect to any external applications, invoke ZAP or MobSF, carry out real money movements, or guarantee regulatory-compliant VAPT delivery. There is no live target execution endpoint. Every potential finding requires human validation.

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

SQLite file location: `HYPOTHESIS_DB` environment variable, default `./data/hypothesis.sqlite3`. Never store real bank credentials or customer data in this database.

## Boundaries

1. The current engine has **no network access to targets**, no arbitrary command execution and no endpoint for user-defined URLs.
2. Evidence hashes form a **tamper-evident chain**, not immutable logs. Production use requires append-only off-host storage, signature/attestation and operational retention rules.
3. A red-team operator must approve target scope, identities, test windows, safe operations and inference/data residency before real adapters are added.
4. An AI-generated hypothesis alone is not a confirmed vulnerability. Finding reports deliberately carry `requires_human_validation`.

## Next milestones

1. Authenticated workflow capture to produce a typed graph from **approved test environments**.
2. External security-invariant configuration, role matrix and expected-state oracle.
3. Sandboxed test adapter with explicit per-operation authorizations, deterministic fixtures, approval queues, rate limits and emergency stop.
4. Model-assisted hypothesis ranking with locally approved inference, isolated from credentials.
5. Peer review, reporting and retest management after validation.

See `/docs` for the interactive OpenAPI reference.
