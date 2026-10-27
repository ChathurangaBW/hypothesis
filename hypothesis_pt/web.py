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
