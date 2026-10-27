"""FastAPI control plane with explicit opt-in for read-only staging tests."""
from __future__ import annotations

from functools import lru_cache
import hmac
import os
from pathlib import Path
from typing import Any, Literal

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict

from .core import BANK_GRAPH, HypothesisPlanner, run_assessment
from .engagement import load_engagement, run_read_only, sanitized_plan
from .reasoning import local_hypotheses
from .specs import import_operations, plan_hypotheses
from .storage import RunStore


app = FastAPI(title="Hypothesis PT", version="0.2.0", docs_url="/docs")


class DemoRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scenario: Literal["secure", "vulnerable"]


class SpecImportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source: Literal["openapi", "postman"]
    document: dict[str, Any]


@lru_cache
def get_store() -> RunStore:
    return RunStore(os.environ.get("HYPOTHESIS_DB", "./data/hypothesis.sqlite3"))


@app.get("/")
def home():
    return FileResponse(Path(__file__).resolve().parent / "static" / "index.html")


@app.get("/api/health")
def health():
    return {
        "status": "ok", "mode": "offline_by_default",
        "live_target_execution": False,
        "read_only_staging_enabled": os.getenv("HYPOTHESIS_ENABLE_READONLY_PT") == "1",
        "local_ai_enabled": os.getenv("HYPOTHESIS_ALLOW_LOCAL_AI") == "1",
    }


@app.get("/api/model")
def model():
    return {"graph": BANK_GRAPH, "hypotheses": [h.__dict__ for h in HypothesisPlanner().generate()]}


@app.get("/api/runs")
def list_runs(store: RunStore = Depends(get_store)):
    return store.list_runs()


@app.post("/api/runs", status_code=201)
def create_run(body: DemoRunRequest, store: RunStore = Depends(get_store)):
    result = run_assessment(body.scenario)
    store.save(result)
    return result


@app.get("/api/runs/{run_id}")
def get_run(run_id: str, store: RunStore = Depends(get_store)):
    result = store.get(run_id)
    if result is None:
        raise HTTPException(404, detail="Run not found")
    return result


@app.get("/api/runs/{run_id}/verify")
def verify_run(run_id: str, store: RunStore = Depends(get_store)):
    result = store.verify(run_id)
    if not result["exists"]:
        raise HTTPException(404, detail="Run not found")
    return result


@app.get("/api/specs")
def list_specs(store: RunStore = Depends(get_store)):
    return store.list_specs()


@app.post("/api/specs", status_code=201)
def import_spec(body: SpecImportRequest, store: RunStore = Depends(get_store)):
    try:
        operations = import_operations(body.source, body.document)
    except ValueError as error:
        raise HTTPException(422, detail=str(error)) from error
    return store.save_spec(body.source, operations)


@app.get("/api/specs/{spec_id}")
def get_spec(spec_id: str, store: RunStore = Depends(get_store)):
    result = store.get_spec(spec_id)
    if not result:
        raise HTTPException(404, detail="Specification not found")
    return result


@app.get("/api/specs/{spec_id}/hypotheses")
def get_hypotheses(spec_id: str, store: RunStore = Depends(get_store)):
    result = store.get_spec(spec_id)
    if not result:
        raise HTTPException(404, detail="Specification not found")
    candidates = plan_hypotheses(result["operations"])
    return {"spec_id": spec_id, "candidates": candidates, "count": len(candidates),
            "note": "Candidates are not verified vulnerabilities"}


@app.post("/api/specs/{spec_id}/reason")
async def reason_over_spec(spec_id: str, store: RunStore = Depends(get_store)):
    result = store.get_spec(spec_id)
    if not result:
        raise HTTPException(404, detail="Specification not found")
    try:
        return await local_hypotheses(result["operations"])
    except PermissionError as error:
        raise HTTPException(403, detail=str(error)) from error
    except (ValueError, RuntimeError) as error:
        raise HTTPException(422, detail=str(error)) from error


@app.get("/api/engagement")
def engagement_status():
    try:
        config = load_engagement()
    except (ValueError, OSError) as error:
        raise HTTPException(422, detail=f"Invalid local engagement manifest: {error}") from error
    if config is None:
        return {"configured": False, "mode": "offline_only"}
    return {"configured": True, **sanitized_plan(config)}


@app.post("/api/engagement/execute", status_code=201)
async def execute_engagement(
    x_hypothesis_admin_token: str | None = Header(default=None),
    store: RunStore = Depends(get_store),
):
    if os.getenv("HYPOTHESIS_ENABLE_READONLY_PT") != "1" or os.getenv("HYPOTHESIS_ROE_APPROVED") != "1":
        raise HTTPException(403, detail="Read-only PT or ROE acknowledgment is disabled")
    secret = os.getenv("HYPOTHESIS_ADMIN_TOKEN")
    if not secret or len(secret) < 24 or not hmac.compare_digest(x_hypothesis_admin_token or "", secret):
        raise HTTPException(403, detail="Missing or invalid local operator approval token")
    try:
        config = load_engagement()
    except (ValueError, OSError) as error:
        raise HTTPException(422, detail=f"Invalid engagement: {error}") from error
    if config is None:
        raise HTTPException(403, detail="No locally configured engagement manifest")
    try:
        result = await run_read_only(config)
    except PermissionError as error:
        raise HTTPException(403, detail=str(error)) from error
    store.save(result)
    return result
