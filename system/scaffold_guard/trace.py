"""Directive and audit trace export for Scaffold Guard."""

from __future__ import annotations

from pathlib import Path
import json
import time

from .engine import AuditReport, MaterializeReport, ScaffoldError
from .policy import PolicyProfile


def build_materialization_trace(
    report: MaterializeReport,
    *,
    requester: str,
    policy_profile: PolicyProfile,
    audit: AuditReport | None = None,
    directive: str | None = None,
) -> dict[str, object]:
    if not requester:
        raise ScaffoldError("trace export requires a requester")

    payload: dict[str, object] = {
        "created_at_epoch": int(time.time()),
        "destination": report.destination,
        "directive": directive,
        "engine": "openclaw-scaffold-guard",
        "file_count": report.file_count,
        "manifest_path": report.manifest_path,
        "policy_profile": policy_profile.to_dict(),
        "provenance": report.provenance,
        "requester": requester,
        "rolled_back": report.rolled_back,
        "source": report.source,
        "trace_version": 1,
    }
    if audit is not None:
        payload["audit"] = audit.to_dict()
    return payload


def write_materialization_trace(
    path: Path,
    report: MaterializeReport,
    *,
    requester: str,
    policy_profile: PolicyProfile,
    audit: AuditReport | None = None,
    directive: str | None = None,
) -> dict[str, object]:
    payload = build_materialization_trace(
        report,
        requester=requester,
        policy_profile=policy_profile,
        audit=audit,
        directive=directive,
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload
