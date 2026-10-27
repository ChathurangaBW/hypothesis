# Hypothesis

**Application-aware security investigation using workflow models, security invariants, controlled experiments and verifiable evidence.**

## Current version: 0.2

Hypothesis is a working self-hosted research prototype, **not a complete autonomous bank-grade penetration testing product**. It includes offline multi-step banking workflow tests, API specification intelligence, an optional local AI hypothesis planner, and an opt-in **read-only** check engine for explicitly approved test environments. Active testing is **OFF by default**.

### Included

- **Synthetic stateful banking PT:** Cross-account BOLA/IDOR and maker/checker separation-of-duties tests, with both secure and seeded-vulnerable workflows.
- **OpenAPI and Postman import:** Normalizes method, route, tags and safe labels, discarding request bodies, authentication material, server URLs and samples.
- **Business-aware hypothesis planning:** Proposes object-level authorization, function authorization, transaction invariants, state transitions and maker/checker checks for manual review. This is not a vulnerability scan.
- **Optional local AI reasoning:** A local Ollama-compatible inference server can suggest candidates from reduced route metadata. It cannot run network tools and its proposals are unverified.
- **Staging-only read authorization checks:** Administrator-owned local ROE manifest, HTTPS origin, literal allowlisted GET paths, environment-based test-account tokens, explicit opt-in and operator approval token.
- **Evidence review:** Response-code observations and bounded response fingerprints, no response bodies or bearer tokens in the evidence database.
- **Dashboard + API:** FastAPI control plane and responsive browser interface.
- **Run history + hash chain:** SQLite persistence with integrity verification. Hash chaining is *not* immutable audit storage or legal evidence certification.
- **CI tests:** Offline deterministic tests, mock transports for staging checks, fail-closed policy tests.

### Installation

Requires Python 3.11+.

```bash
git clone https://github.com/ChathurangaBW/hypothesis.git
cd hypothesis
git checkout feat/stateful-pt-mvp
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
python -m pytest -q
hypothesis-pt serve
```

Open **http://127.0.0.1:8000**. The dashboard defaults to the isolated synthetic banking environment and can be used without a model API key.

CLI demo:

```bash
hypothesis-pt demo vulnerable
hypothesis-pt demo secure
```

Windows PowerShell: `.venv\\Scripts\\Activate.ps1`.

### Import a specification

In the dashboard, choose an **OpenAPI JSON** or **Postman collection JSON** file. Click **Import**, then **Plan**. This produces a bounded candidate list for ownership, state transitions, maker/checker and administrative authorization. It **does not** execute the candidate hypotheses against targets.

### Optional local AI hypothesis proposals

Install and run an Ollama-compatible service bound to loopback. Only route metadata (method, path and category) is passed to the local model. Do not import confidential bank specifications on an unapproved workstation.

```bash
export HYPOTHESIS_ALLOW_LOCAL_AI=1
export HYPOTHESIS_LOCAL_MODEL_URL=http://127.0.0.1:11434
export HYPOTHESIS_LOCAL_MODEL=llama3.1
hypothesis-pt serve
```

Choose **Local AI** after importing a specification. The model produces up to 12 suggestions limited to known operations, with no execution privileges. Verify the model and its dependencies are downloaded and approved for use before attempting this.

### Opt-in staging GET authorization checks (advanced)

This runs actual HTTP GET requests only when explicitly enabled. Confirm your **signed Rules of Engagement**, approved synthetic test accounts, test target, access windows and local data handling arrangements.

1. Copy `examples/staging-engagement.example.json` to a private location outside GitHub. Replace the placeholder HTTPS origin, test-only path, approval reference and identity names. Every path must be a literal allowed GET resource and use **test data**, not real customer information.
2. Define the test identity bearer token in an environment variable. Do not commit secrets, tokens or evidence.
3. Explicitly enable execution and set a long local operator approval token.

```bash
export HYPOTHESIS_ENGAGEMENT_PATH=/private/path/approved-roe.json
export HYPOTHESIS_TOKEN_TEST_USER_B='redacted-test-only-token'
export HYPOTHESIS_ENABLE_READONLY_PT=1
export HYPOTHESIS_ROE_APPROVED=1
export HYPOTHESIS_ADMIN_TOKEN='generate-a-long-random-operator-approval-token'
hypothesis-pt serve
```

Execution is still blocked until the local operator supplies the approval token in the dashboard. Only manifest-listed HTTPS GET routes are executed, sequentially, without following redirects, proxies or saving response bodies. Unexpected successful access is a **potential** violation for human validation, not a confirmed vulnerability.

**Run locally.** By default the server binds to `127.0.0.1`. The prototype has no production user accounts, tenant separation, TLS termination or robust rate-limiting across concurrent clients. Do **not** expose it to an untrusted network. Real bank production testing, payment operations, mobile instrumentation and uncontrolled autonomous exploitation are not supported.

### API overview

| Route | Purpose |
|---|---|
| `GET /` | Local dashboard |
| `GET /api/model` | Synthetic workflow graph and invariants |
| `POST /api/runs` | Secure/vulnerable offline demo |
| `GET /api/runs` | List runs |
| `GET /api/runs/{id}` | Evidence and findings |
| `GET /api/runs/{id}/verify` | Chained evidence integrity check |
| `POST /api/specs` | OpenAPI/Postman JSON import |
| `GET /api/specs` | Sanitized workspaces |
| `GET /api/specs/{id}/hypotheses` | Deterministic hypothesis candidates |
| `POST /api/specs/{id}/reason` | Opt-in local model suggestions |
| `GET /api/engagement` | Sanitized local ROE configuration status |
| `POST /api/engagement/execute` | Approved, allowlisted staging GET checks only |

The full OpenAPI API reference is at `http://127.0.0.1:8000/docs`.

## What is not yet complete

- Browser/transaction workflow capture, parameter-aware replay and dynamic role modeling for arbitrary real applications.
- General multi-step **live** PT execution of payment state transitions.
- Security policy oracles driven by verified bank business specifications.
- Mobile dynamic-analysis adapters, isolated workers, operator SSO and independent reviewer sign-off.
- Production immutable logs, evidentiary chain of custody, encryption and bank-specific regulatory attestation.
- Proof that the platform can find unknown real-world banking logic vulnerabilities reliably.

Treat this as a testable platform foundation, **not a substitute for the required qualified manual VAPT engagement**.
