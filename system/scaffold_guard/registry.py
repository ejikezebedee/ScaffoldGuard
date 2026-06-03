"""Template registry validation and search for Scaffold Guard."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import json

from .engine import ScaffoldError
from .policy import get_policy_profile

SOURCE_TYPES = {"github_archive", "local_directory", "release_archive", "tar_archive"}


@dataclass(frozen=True)
class RegistryEntry:
    template_id: str
    owner: str
    version: str
    tags: tuple[str, ...]
    source_type: str
    source: str
    policy_profile: str
    intended_use: str
    checksum_sha256: str | None = None
    lock_path: str | None = None

    def to_dict(self) -> dict[str, object]:
        payload = {
            "id": self.template_id,
            "intended_use": self.intended_use,
            "owner": self.owner,
            "policy_profile": self.policy_profile,
            "source": self.source,
            "source_type": self.source_type,
            "tags": list(self.tags),
            "version": self.version,
        }
        if self.checksum_sha256 is not None:
            payload["checksum_sha256"] = self.checksum_sha256
        if self.lock_path is not None:
            payload["lock_path"] = self.lock_path
        return payload


@dataclass(frozen=True)
class RegistryReport:
    path: str
    valid: bool
    entries: tuple[RegistryEntry, ...]
    findings: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "entries": [entry.to_dict() for entry in self.entries],
            "findings": list(self.findings),
            "path": self.path,
            "valid": self.valid,
        }


def load_registry(path: Path) -> RegistryReport:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise ScaffoldError(f"template registry cannot be read: {exc}") from exc
    if not isinstance(payload, dict):
        raise ScaffoldError("template registry must be a JSON object")

    raw_entries = payload.get("templates")
    if not isinstance(raw_entries, list):
        return RegistryReport(str(path), False, (), ("registry missing templates list",))

    findings: list[str] = []
    entries: list[RegistryEntry] = []
    seen_ids: set[str] = set()
    for index, raw_entry in enumerate(raw_entries):
        if not isinstance(raw_entry, dict):
            findings.append(f"templates[{index}] must be an object")
            continue
        entry = _entry_from_payload(raw_entry, index, findings)
        if entry is None:
            continue
        if entry.template_id in seen_ids:
            findings.append(f"templates[{index}].id is duplicated: {entry.template_id}")
            continue
        seen_ids.add(entry.template_id)
        entries.append(entry)

    return RegistryReport(str(path), not findings, tuple(entries), tuple(findings))


def search_registry(
    report: RegistryReport,
    *,
    query: str | None = None,
    tag: str | None = None,
    policy_profile: str | None = None,
) -> tuple[RegistryEntry, ...]:
    entries = report.entries
    if query:
        needle = query.lower()
        entries = tuple(
            entry
            for entry in entries
            if needle in entry.template_id.lower()
            or needle in entry.owner.lower()
            or needle in entry.intended_use.lower()
            or any(needle in tag_value.lower() for tag_value in entry.tags)
        )
    if tag:
        entries = tuple(entry for entry in entries if tag in entry.tags)
    if policy_profile:
        entries = tuple(entry for entry in entries if entry.policy_profile == policy_profile)
    return entries


def _entry_from_payload(
    raw_entry: dict[str, object],
    index: int,
    findings: list[str],
) -> RegistryEntry | None:
    required = ("id", "owner", "version", "tags", "source_type", "source", "policy_profile", "intended_use")
    missing = [field for field in required if field not in raw_entry]
    if missing:
        findings.append(f"templates[{index}] missing required fields: {', '.join(missing)}")
        return None

    template_id = _required_text(raw_entry, "id", index, findings)
    owner = _required_text(raw_entry, "owner", index, findings)
    version = _required_text(raw_entry, "version", index, findings)
    source_type = _required_text(raw_entry, "source_type", index, findings)
    source = _required_text(raw_entry, "source", index, findings)
    policy_profile = _required_text(raw_entry, "policy_profile", index, findings)
    intended_use = _required_text(raw_entry, "intended_use", index, findings)
    raw_tags = raw_entry.get("tags")
    if not isinstance(raw_tags, list) or not all(isinstance(value, str) and value for value in raw_tags):
        findings.append(f"templates[{index}].tags must be a non-empty string list")
        tags: tuple[str, ...] = ()
    else:
        tags = tuple(raw_tags)

    if source_type and source_type not in SOURCE_TYPES:
        findings.append(f"templates[{index}].source_type is unsupported: {source_type}")
    if policy_profile:
        try:
            get_policy_profile(policy_profile)
        except ScaffoldError as exc:
            findings.append(f"templates[{index}].policy_profile is unsupported: {exc}")

    checksum = _optional_text(raw_entry, "checksum_sha256", index, findings)
    if source_type in {"github_archive", "release_archive", "tar_archive"} and not checksum:
        findings.append(f"templates[{index}].checksum_sha256 is required for archive sources")
    lock_path = _optional_text(raw_entry, "lock_path", index, findings)

    if not all((template_id, owner, version, source_type, source, policy_profile, intended_use, tags)):
        return None
    return RegistryEntry(
        template_id=template_id,
        owner=owner,
        version=version,
        tags=tags,
        source_type=source_type,
        source=source,
        policy_profile=policy_profile,
        intended_use=intended_use,
        checksum_sha256=checksum,
        lock_path=lock_path,
    )


def _required_text(
    raw_entry: dict[str, object],
    field: str,
    index: int,
    findings: list[str],
) -> str:
    value = raw_entry.get(field)
    if not isinstance(value, str) or not value.strip():
        findings.append(f"templates[{index}].{field} must be a non-empty string")
        return ""
    return value


def _optional_text(
    raw_entry: dict[str, object],
    field: str,
    index: int,
    findings: list[str],
) -> str | None:
    value = raw_entry.get(field)
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        findings.append(f"templates[{index}].{field} must be a non-empty string when set")
        return None
    return value
