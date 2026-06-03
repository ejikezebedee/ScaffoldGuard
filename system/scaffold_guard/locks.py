"""Signed template lock-file support for Scaffold Guard."""

from __future__ import annotations

from pathlib import Path
import hashlib
import hmac
import json
import time

from .engine import PreviewReport, ScaffoldEngine, ScaffoldError
from .policy import PolicyProfile, get_policy_profile

LOCK_VERSION = 1
SIGNATURE_ALGORITHM = "hmac-sha256"


def build_template_lock(
    source: Path,
    *,
    engine: ScaffoldEngine,
    policy_profile: PolicyProfile,
    signing_key: str,
) -> dict[str, object]:
    if not signing_key:
        raise ScaffoldError("lock signing requires a non-empty signing key")

    report = engine.preview(source)
    if not report.allowed:
        raise ScaffoldError(json.dumps(report.to_dict(), indent=2, sort_keys=True))

    payload: dict[str, object] = {
        "created_at_epoch": int(time.time()),
        "files": [file.to_dict() for file in report.files],
        "lock_version": LOCK_VERSION,
        "policy_profile": policy_profile.to_dict(),
        "signature_algorithm": SIGNATURE_ALGORITHM,
        "source": report.source,
        "source_fingerprint": _preview_fingerprint(report),
        "source_type": report.source_type,
        "total_bytes": report.total_bytes,
    }
    payload["signature"] = sign_lock_payload(payload, signing_key)
    return payload


def write_template_lock(
    source: Path,
    lock_path: Path,
    *,
    engine: ScaffoldEngine,
    policy_profile: PolicyProfile,
    signing_key: str,
) -> dict[str, object]:
    payload = build_template_lock(
        source,
        engine=engine,
        policy_profile=policy_profile,
        signing_key=signing_key,
    )
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload


def verify_template_lock(
    source: Path,
    lock_path: Path,
    *,
    engine: ScaffoldEngine,
    signing_key: str,
) -> dict[str, object]:
    payload = _read_lock(lock_path)
    if not signing_key:
        raise ScaffoldError("lock verification requires a non-empty signing key")
    if payload.get("lock_version") != LOCK_VERSION:
        raise ScaffoldError("unsupported template lock version")
    if payload.get("signature_algorithm") != SIGNATURE_ALGORITHM:
        raise ScaffoldError("unsupported template lock signature algorithm")

    expected_signature = payload.get("signature")
    if not isinstance(expected_signature, str):
        raise ScaffoldError("template lock missing signature")
    actual_signature = sign_lock_payload(payload, signing_key)
    if not hmac.compare_digest(expected_signature, actual_signature):
        raise ScaffoldError("template lock signature mismatch")

    profile_payload = payload.get("policy_profile")
    if not isinstance(profile_payload, dict) or not isinstance(profile_payload.get("name"), str):
        raise ScaffoldError("template lock missing policy profile")
    get_policy_profile(profile_payload["name"])

    report = engine.preview(source)
    if not report.allowed:
        raise ScaffoldError(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    if payload.get("source_fingerprint") != _preview_fingerprint(report):
        raise ScaffoldError("template lock source fingerprint mismatch")
    return payload


def sign_lock_payload(payload: dict[str, object], signing_key: str) -> str:
    canonical = _canonical_payload(payload)
    return hmac.new(signing_key.encode("utf-8"), canonical, hashlib.sha256).hexdigest()


def _preview_fingerprint(report: PreviewReport) -> str:
    canonical = json.dumps(
        {
            "files": [file.to_dict() for file in report.files],
            "source_type": report.source_type,
            "total_bytes": report.total_bytes,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _canonical_payload(payload: dict[str, object]) -> bytes:
    clean_payload = {key: value for key, value in payload.items() if key != "signature"}
    return json.dumps(clean_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _read_lock(lock_path: Path) -> dict[str, object]:
    try:
        payload = json.loads(lock_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise ScaffoldError(f"template lock cannot be read: {exc}") from exc
    if not isinstance(payload, dict):
        raise ScaffoldError("template lock must be a JSON object")
    return payload
