"""FastAPI control plane. No arbitrary target URLs or execution routes."""
from __future__ import annotations

from functools import lru_cache
import os
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict

from .core import BANK_GRAPH, HypothesisPlanner, run_assessment
from .capture import WorkflowCapture, capture_record, example_capture
from .invariants import InvariantPolicy, assess_workflow, example_policy
from .storage import RunStore


app = FastAPI(title="Hypothesis PT", version="0.1.0", docs_url="/docs")


class DemoRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scenario: Literal["secure", "vulnerable"]


@lru_cache
def get_store() -> RunStore:
    return RunStore(os.environ.get("HYPOTHESIS_DB", "./data/hypothesis.sqlite3"))


@app.get("/")
def home():
    return FileResponse(Path(__file__).resolve().parents[1] / "web" / "index.html")


@app.get("/api/health")
def health():
    return {"status": "ok", "mode": "offline_synthetic", "live_target_execution": False}


@app.get("/api/model")
def model():
    return {"graph": BANK_GRAPH, "hypotheses": [h.__dict__ for h in HypothesisPlanner().generate()]}


@app.get("/api/workflows/example")
def workflow_example(scenario: Literal["separated", "self_approval"] = "separated"):
    return example_capture(self_approval=scenario == "self_approval")


@app.get("/api/workflows")
def list_workflows(store: RunStore = Depends(get_store)):
    try:
        return store.list_workflows()
    except ValueError as exc:
        raise HTTPException(409, detail=str(exc)) from exc


@app.post("/api/workflows", status_code=201)
def import_workflow(body: WorkflowCapture, store: RunStore = Depends(get_store)):
    record = capture_record(body)
    store.save_workflow(record)
    return record


@app.get("/api/workflows/{workflow_id}")
def get_workflow(workflow_id: str, store: RunStore = Depends(get_store)):
    try:
        record = store.get_workflow(workflow_id)
    except ValueError as exc:
        raise HTTPException(409, detail="Stored workflow failed its integrity check") from exc
    if record is None:
        raise HTTPException(404, detail="Workflow not found")
    return record


@app.get("/api/workflows/{workflow_id}/policy-example")
def policy_example(workflow_id: str, store: RunStore = Depends(get_store)):
    workflow = get_workflow(workflow_id, store)
    try:
        return example_policy(workflow)
    except ValueError as exc:
        raise HTTPException(422, detail=str(exc)) from exc


@app.post("/api/workflows/{workflow_id}/assessments", status_code=201)
def create_assessment(workflow_id: str, body: InvariantPolicy, store: RunStore = Depends(get_store)):
    workflow = get_workflow(workflow_id, store)
    try:
        result = assess_workflow(workflow, body)
    except ValueError as exc:
        raise HTTPException(422, detail=str(exc)) from exc
    store.save_assessment(result)
    return result


@app.get("/api/workflows/{workflow_id}/assessments")
def workflow_assessments(workflow_id: str, store: RunStore = Depends(get_store)):
    get_workflow(workflow_id, store)
    try:
        return store.list_assessments(workflow_id)
    except ValueError as exc:
        raise HTTPException(409, detail=str(exc)) from exc


@app.get("/api/assessments/{assessment_id}")
def get_assessment(assessment_id: str, store: RunStore = Depends(get_store)):
    try:
        record = store.get_assessment(assessment_id)
    except ValueError as exc:
        raise HTTPException(409, detail=str(exc)) from exc
    if record is None:
        raise HTTPException(404, detail="Assessment not found")
    return record


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
