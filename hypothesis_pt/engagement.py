"""Opt-in, bounded read-only staging API authorization checks.

Targets and probes are loaded from a LOCAL administrator-owned manifest.
There is NO API endpoint to supply arbitrary URLs, paths, or bearer tokens.
Tokens stay in environment variables and never enter run evidence.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

import httpx
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

SAFE_PROFILE = re.compile(r"^[A-Z][A-Z0-9_]{0,31}$")
SAFE_PATH = re.compile(r"^/(?!/)[A-Za-z0-9_./~\-]+$")
RESULT_CAP_BYTES = 8192


class ReadProbe(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(min_length=2, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    path: str
    requester_profile: str
    expected_denial_statuses: list[int] = Field(default_factory=lambda: [401, 403, 404], min_length=1, max_length=5)
    description: str = Field(default="", max_length=150)

    @field_validator("path")
    @classmethod
    def validate_path(cls, path: str) -> str:
        # No placeholders, encoded slashes, dot segments, queries or redirects.
        if (not SAFE_PATH.fullmatch(path) or
            ".." in path or "%" in path or "//" in path or
            len(path) > 240):
            raise ValueError("Probe path must be literal, normalized and read-only")
        return path

    @field_validator("requester_profile")
    @classmethod
    def validate_profile(cls, profile: str) -> str:
        if not SAFE_PROFILE.fullmatch(profile):
            raise ValueError("Profile must use uppercase A-Z, digits or underscores")
        return profile

    @field_validator("expected_denial_statuses")
    @classmethod
    def validate_denials(cls, values: list[int]) -> list[int]:
        if any(v not in {401, 403, 404} for v in values):
            raise ValueError("Expected denials must be 401, 403 or 404")
        return values


class Engagement(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str = Field(min_length=4, max_length=100)
    base_url: str
    approved_by: str = Field(min_length=2, max_length=100)
    approval_reference: str = Field(min_length=2, max_length=100)
    environment: str = Field(min_length=2, max_length=64)
    probes: list[ReadProbe] = Field(min_length=1, max_length=25)

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, url: str) -> str:
        parsed = urlsplit(url)
        if (parsed.scheme != "https" or not parsed.hostname or
            parsed.username or parsed.password or parsed.path not in ("", "/") or
            parsed.query or parsed.fragment or parsed.port not in (None, 443)):
            raise ValueError("Base URL must be the HTTPS origin on port 443 without credentials or path")
        if parsed.hostname.endswith(".") or not re.fullmatch(r"[a-zA-Z0-9.-]+", parsed.hostname):
            raise ValueError("Invalid hostname")
        return url.rstrip("/")

    @model_validator(mode="after")
    def validate_uniqueness(self):
        ids = [probe.id for probe in self.probes]
        if len(ids) != len(set(ids)):
            raise ValueError("Probe IDs must be unique")
        return self


def load_engagement() -> Engagement | None:
    path = os.getenv("HYPOTHESIS_ENGAGEMENT_PATH", "")
    if not path:
        return None
    source = Path(path).resolve(strict=True)
    if source.stat().st_size > 200_000:
        raise ValueError("Engagement manifest too large")
    return Engagement.model_validate_json(source.read_text(encoding="utf-8"))


def sanitized_plan(config: Engagement) -> dict[str, Any]:
    return {
        "title": config.title, "base_url": config.base_url, "environment": config.environment,
        "approval_reference": config.approval_reference,
        "approved_by": config.approved_by,
        "mode": "opt_in_read_only_get",
        "probes": [p.model_dump(exclude={"requester_profile"}) | {"profile": p.requester_profile} for p in config.probes],
        "execution_enabled": os.getenv("HYPOTHESIS_ENABLE_READONLY_PT") == "1",
    }


async def run_read_only(config: Engagement, transport: httpx.AsyncBaseTransport | None = None) -> dict[str, Any]:
    if os.getenv("HYPOTHESIS_ENABLE_READONLY_PT") != "1":
        raise PermissionError("Active staging checks disabled; set HYPOTHESIS_ENABLE_READONLY_PT=1")
    if os.getenv("HYPOTHESIS_ROE_APPROVED") != "1":
        raise PermissionError("Rules of Engagement approval not acknowledged")
    if not config.approval_reference.strip():
        raise PermissionError("Approval reference is required")
    # Every required secret must exist before the first outbound request.
    tokens = {}
    for probe in config.probes:
        env_key = f"HYPOTHESIS_TOKEN_{probe.requester_profile}"
        token = os.getenv(env_key)
        if not token:
            raise PermissionError(f"Missing scoped test credential {env_key}")
        if len(token) > 8192 or "\r" in token or "\n" in token:
            raise PermissionError(f"Invalid scoped credential {env_key}")
        tokens[probe.requester_profile] = token

    records: list[dict[str, Any]] = []
    async with httpx.AsyncClient(
        transport=transport, timeout=httpx.Timeout(6.0), follow_redirects=False,
        trust_env=False, verify=True, limits=httpx.Limits(max_connections=1),
    ) as client:
        for index, probe in enumerate(config.probes):
            if index:
                await asyncio.sleep(0.2)  # conservative request cadence
            url = config.base_url + probe.path
            try:
                # Stream with a strict bounded sample; never buffer full account data.
                async with client.stream(
                    "GET", url, headers={
                        "Authorization": "Bearer " + tokens[probe.requester_profile],
                        "Accept": "application/json",
                        "Cache-Control": "no-store",
                    },
                ) as response:
                    sample = bytearray()
                    async for chunk in response.aiter_bytes():
                        remaining = RESULT_CAP_BYTES - len(sample)
                        sample.extend(chunk[:remaining])
                        if len(sample) >= RESULT_CAP_BYTES:
                            break
                    body_hash = __import__("hashlib").sha256(sample).hexdigest()
                    if response.status_code in probe.expected_denial_statuses:
                        outcome = "protected"
                    elif response.status_code in {200, 206}:
                        outcome = "potential_access_control_violation_requires_review"
                    else:
                        outcome = "inconclusive"
                    records.append({
                        "probe_id": probe.id, "path": probe.path, "profile": probe.requester_profile,
                        "expected_denial_statuses": probe.expected_denial_statuses,
                        "status_code": response.status_code, "body_prefix_sha256": body_hash,
                        "body_bytes_sampled": len(sample),
                        "outcome": outcome,
                    })
            except (httpx.HTTPError, ValueError) as error:
                records.append({
                    "probe_id": probe.id, "path": probe.path, "profile": probe.requester_profile,
                    "expected_denial_statuses": probe.expected_denial_statuses,
                    "outcome": "execution_error",
                    "error_type": type(error).__name__,
                })

    return {
        "id": str(uuid4()), "created_at": datetime.now(timezone.utc).isoformat(),
        "scenario": "approved_staging_read_only",
        "environment": config.environment, "title": config.title,
        "approval_reference": config.approval_reference,
        "observations": records,
        "findings": [
            {"id": f"F-{i+1:03d}", "title": "Potential authorization policy violation",
             "probe_id": row["probe_id"], "status": "requires_human_validation"}
            for i, row in enumerate(r for r in records if r["outcome"] == "potential_access_control_violation_requires_review")
        ],
        "summary": {
            "hypotheses": len(records),
            "passed": sum(r["outcome"] == "protected" for r in records),
            "potential_findings": sum(r["outcome"] == "potential_access_control_violation_requires_review" for r in records),
            "errors": sum(r["outcome"] == "execution_error" for r in records),
            "coverage": [r["probe_id"] for r in records],
        },
    }
