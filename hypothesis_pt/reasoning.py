"""Optional LOCAL model proposal generation. No execution tools exposed to models."""
from __future__ import annotations

import json
import os
from typing import Any
from urllib.parse import urlsplit

import httpx


async def local_hypotheses(operations: list[dict[str, Any]], transport=None) -> dict[str, Any]:
    if os.getenv("HYPOTHESIS_ALLOW_LOCAL_AI") != "1":
        raise PermissionError("AI proposal generation is disabled until explicitly enabled")
    endpoint = os.getenv("HYPOTHESIS_LOCAL_MODEL_URL", "http://127.0.0.1:11434")
    parsed = urlsplit(endpoint)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"} or parsed.path not in {"", "/"} or parsed.query or parsed.username or parsed.password:
        raise ValueError("Only a direct local inference endpoint is allowed")
    model = os.getenv("HYPOTHESIS_LOCAL_MODEL", "llama3.1")
    allowed_operations = [{"method": op["method"], "path": op["path"], "category": op["category"]} for op in operations[:70]]
    prompt = (
        "You are a security test case planning assistant. Use ONLY paths and methods provided. "
        "Return JSON object with a 'hypotheses' array containing at most 12 objects. "
        "Each object has title, method, path, expected_security_invariant, rationale. "
        "Do not provide exploit payloads or instructions to execute actions. "
        "Proposals require human review before testing. "
        "Operations: " + json.dumps(allowed_operations)
    )
    async with httpx.AsyncClient(transport=transport, trust_env=False, follow_redirects=False, timeout=35.0) as client:
        response = await client.post(
            endpoint.rstrip("/") + "/api/generate",
            json={"model": model, "prompt": prompt, "stream": False, "format": "json"},
        )
        response.raise_for_status()
    raw = response.json().get("response", "")
    parsed_json = json.loads(raw)
    if not isinstance(parsed_json, dict) or not isinstance(parsed_json.get("hypotheses"), list):
        raise ValueError("Invalid local model response")
    approved_ops = {(o["method"], o["path"]) for o in allowed_operations}
    safe = []
    for item in parsed_json["hypotheses"][:12]:
        if not isinstance(item, dict):
            continue
        method, path = str(item.get("method", "")), str(item.get("path", ""))
        if (method, path) not in approved_ops:
            continue
        safe.append({
            "id": f"AI-CAND-{len(safe)+1:03d}",
            "title": str(item.get("title", ""))[:100],
            "method": method, "path": path,
            "expected_security_invariant": str(item.get("expected_security_invariant", ""))[:300],
            "rationale": str(item.get("rationale", ""))[:300],
            "state": "unverified_model_suggestion",
            "execution": "human_review_required",
        })
    return {"source": "local_inference_only", "model": model, "hypotheses": safe,
            "note": "No network test requests executed. AI suggestions are not findings."}
