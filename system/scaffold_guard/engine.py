"""Secure scaffold preview, verification, materialization, and audit flows.

This module is a clean-room OpenClaw-native scaffold engine. It does not clone
git history and it does not execute template scripts. It turns a local template
directory or tar archive into an auditable project copy with policy checks.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
import fnmatch
import hashlib
import json
import os
import shutil
import tarfile
import tempfile
import time
from typing import Iterable


class ScaffoldError(RuntimeError):
    """Raised when scaffold verification or materialization is unsafe."""


SECRET_PATTERNS = {
    "aws_access_key": "AKIA[0-9A-Z]{16}",
    "generic_assignment": r"(?i)\b(api[_-]?key|secret|token|password)\b\s*[:=]\s*['\"]?[^'\"\s]{12,}",
    "private_key": "-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
}

BLOCKED_NAMES = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    "node_modules",
}

TEXT_EXTENSIONS = {
    ".cfg",
    ".conf",
    ".env",
    ".ini",
    ".js",
    ".json",
    ".md",
    ".py",
    ".sh",
    ".toml",
    ".ts",
    ".txt",
    ".yaml",
    ".yml",
}


@dataclass(frozen=True)
class FileRecord:
    """One source file included in a scaffold plan."""

    relative_path: str
    size_bytes: int
    sha256: str

    def to_dict(self) -> dict[str, object]:
        return {
            "relative_path": self.relative_path,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
        }


@dataclass(frozen=True)
class Finding:
    """Policy finding raised during preview or audit."""

    severity: str
    code: str
    path: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {
            "code": self.code,
            "message": self.message,
            "path": self.path,
            "severity": self.severity,
        }


@dataclass(frozen=True)
class PreviewReport:
    source: str
    source_type: str
    file_count: int
    total_bytes: int
    files: tuple[FileRecord, ...]
    findings: tuple[Finding, ...]
    elapsed_microseconds: int
    provenance: dict[str, object] | None = None

    @property
    def allowed(self) -> bool:
        return not any(finding.severity == "blocker" for finding in self.findings)

    def to_dict(self) -> dict[str, object]:
        payload = {
            "allowed": self.allowed,
            "elapsed_microseconds": self.elapsed_microseconds,
            "file_count": self.file_count,
            "files": [file.to_dict() for file in self.files],
            "findings": [finding.to_dict() for finding in self.findings],
            "source": self.source,
            "source_type": self.source_type,
            "total_bytes": self.total_bytes,
        }
        if self.provenance is not None:
            payload["provenance"] = self.provenance
        return payload


@dataclass(frozen=True)
class VerifyReport:
    preview: PreviewReport
    destination: str | None = None

    @property
    def allowed(self) -> bool:
        return self.preview.allowed

    def to_dict(self) -> dict[str, object]:
        payload = self.preview.to_dict()
        payload["destination"] = self.destination
        payload["verified"] = self.allowed
        return payload


@dataclass(frozen=True)
class MaterializeReport:
    source: str
    destination: str
    file_count: int
    manifest_path: str
    rolled_back: bool
    elapsed_microseconds: int
    provenance: dict[str, object] | None = None

    def to_dict(self) -> dict[str, object]:
        payload = {
            "destination": self.destination,
            "elapsed_microseconds": self.elapsed_microseconds,
            "file_count": self.file_count,
            "manifest_path": self.manifest_path,
            "rolled_back": self.rolled_back,
            "source": self.source,
        }
        if self.provenance is not None:
            payload["provenance"] = self.provenance
        return payload


@dataclass(frozen=True)
class AuditReport:
    destination: str
    manifest_found: bool
    file_count: int
    changed: tuple[str, ...] = field(default_factory=tuple)
    missing: tuple[str, ...] = field(default_factory=tuple)
    extra: tuple[str, ...] = field(default_factory=tuple)
    findings: tuple[Finding, ...] = field(default_factory=tuple)
    elapsed_microseconds: int = 0

    @property
    def passed(self) -> bool:
        return (
            self.manifest_found
            and not self.changed
            and not self.missing
            and not self.extra
            and not self.findings
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "changed": list(self.changed),
            "destination": self.destination,
            "elapsed_microseconds": self.elapsed_microseconds,
            "extra": list(self.extra),
            "file_count": self.file_count,
            "findings": [finding.to_dict() for finding in self.findings],
            "manifest_found": self.manifest_found,
            "missing": list(self.missing),
            "passed": self.passed,
        }


class ScaffoldEngine:
    """Plan and materialize templates with safety checks and audit manifests."""

    def __init__(
        self,
        *,
        blocked_names: Iterable[str] = BLOCKED_NAMES,
        max_file_bytes: int = 5_000_000,
    ) -> None:
        self.blocked_names = frozenset(blocked_names)
        self.max_file_bytes = max_file_bytes

    def preview(self, source: Path, *, provenance: dict[str, object] | None = None) -> PreviewReport:
        start = time.perf_counter_ns()
        source = source.resolve()
        with self._prepared_source(source) as prepared:
            records, findings = self._scan_source(prepared.path)
            return PreviewReport(
                source=str(source),
                source_type=prepared.kind,
                file_count=len(records),
                total_bytes=sum(record.size_bytes for record in records),
                files=tuple(records),
                findings=tuple(findings),
                elapsed_microseconds=self._elapsed_us(start),
                provenance=provenance,
            )

    def verify(self, source: Path, destination: Path | None = None) -> VerifyReport:
        report = self.preview(source)
        findings = list(report.findings)
        if destination is not None:
            dest = destination.resolve()
            if dest.exists() and any(dest.iterdir()):
                findings.append(
                    Finding(
                        severity="blocker",
                        code="destination_not_empty",
                        path=str(dest),
                        message="destination must be empty unless a caller handles overwrite policy",
                    )
                )
        preview = PreviewReport(
            source=report.source,
            source_type=report.source_type,
            file_count=report.file_count,
            total_bytes=report.total_bytes,
            files=report.files,
            findings=tuple(findings),
            elapsed_microseconds=report.elapsed_microseconds,
            provenance=report.provenance,
        )
        return VerifyReport(preview=preview, destination=str(destination.resolve()) if destination else None)

    def materialize(
        self,
        source: Path,
        destination: Path,
        *,
        provenance: dict[str, object] | None = None,
    ) -> MaterializeReport:
        start = time.perf_counter_ns()
        destination = destination.resolve()
        verification = self.verify(source, destination)
        if not verification.allowed:
            raise ScaffoldError(json.dumps(verification.to_dict(), indent=2, sort_keys=True))

        with self._prepared_source(source.resolve()) as prepared:
            records, findings = self._scan_source(prepared.path)
            blockers = [finding for finding in findings if finding.severity == "blocker"]
            if blockers:
                raise ScaffoldError(json.dumps([finding.to_dict() for finding in blockers], indent=2))

            staging = Path(tempfile.mkdtemp(prefix=".scaffold_guard_", dir=str(destination.parent)))
            manifest_path = destination / ".scaffold_guard" / "manifest.json"
            try:
                shutil.copytree(prepared.path, staging, dirs_exist_ok=True, ignore=self._ignore_blocked)
                destination.mkdir(parents=True, exist_ok=True)
                for item in staging.iterdir():
                    shutil.move(str(item), str(destination / item.name))
                manifest_path.parent.mkdir(parents=True, exist_ok=True)
                manifest_path.write_text(
                    json.dumps(self._manifest(source, records, provenance=provenance), indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                return MaterializeReport(
                    source=str(source.resolve()),
                    destination=str(destination),
                    file_count=len(records),
                    manifest_path=str(manifest_path),
                    rolled_back=False,
                    elapsed_microseconds=self._elapsed_us(start),
                    provenance=provenance,
                )
            except Exception:
                if destination.exists():
                    for item in destination.iterdir():
                        if item.name != ".scaffold_guard":
                            if item.is_dir():
                                shutil.rmtree(item)
                            else:
                                item.unlink()
                raise
            finally:
                shutil.rmtree(staging, ignore_errors=True)

    def audit(self, destination: Path) -> AuditReport:
        start = time.perf_counter_ns()
        destination = destination.resolve()
        manifest_path = destination / ".scaffold_guard" / "manifest.json"
        if not manifest_path.exists():
            return AuditReport(
                destination=str(destination),
                manifest_found=False,
                file_count=0,
                elapsed_microseconds=self._elapsed_us(start),
            )

        findings: list[Finding] = []
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest_files = manifest.get("files", [])
            if not isinstance(manifest_files, list):
                raise ValueError("manifest files field must be a list")
            expected = {
                item["relative_path"]: item
                for item in manifest_files
                if isinstance(item, dict) and "relative_path" in item and "sha256" in item
            }
            if len(expected) != len(manifest_files):
                raise ValueError("manifest contains malformed file records")
        except (json.JSONDecodeError, OSError, ValueError) as exc:
            return AuditReport(
                destination=str(destination),
                manifest_found=True,
                file_count=0,
                findings=(
                    Finding(
                        "blocker",
                        "manifest_invalid",
                        str(manifest_path),
                        f"manifest cannot be audited: {exc}",
                    ),
                ),
                elapsed_microseconds=self._elapsed_us(start),
            )

        actual_records, findings = self._scan_source(destination, include_guard_dir=False)
        actual = {record.relative_path: record for record in actual_records}

        changed = []
        missing = []
        for relpath, item in expected.items():
            record = actual.get(relpath)
            if record is None:
                missing.append(relpath)
            elif record.sha256 != item["sha256"]:
                changed.append(relpath)

        extra = sorted(path for path in actual if path not in expected)
        return AuditReport(
            destination=str(destination),
            manifest_found=True,
            file_count=len(actual_records),
            changed=tuple(sorted(changed)),
            missing=tuple(sorted(missing)),
            extra=tuple(extra),
            findings=tuple(findings),
            elapsed_microseconds=self._elapsed_us(start),
        )

    def _scan_source(
        self, root: Path, *, include_guard_dir: bool = True
    ) -> tuple[list[FileRecord], list[Finding]]:
        records: list[FileRecord] = []
        findings: list[Finding] = []
        for path in sorted(root.rglob("*")):
            relpath = path.relative_to(root)
            rel = relpath.as_posix()
            parts = set(relpath.parts)
            if not include_guard_dir and ".scaffold_guard" in parts:
                continue
            if parts & self.blocked_names:
                findings.append(
                    Finding("warning", "blocked_name_skipped", rel, "blocked generated or VCS path")
                )
                continue
            if path.is_symlink():
                findings.append(Finding("blocker", "symlink_blocked", rel, "symlinks are not materialized"))
                continue
            if path.is_dir():
                continue
            if not self._is_safe_relative(rel):
                findings.append(Finding("blocker", "unsafe_path", rel, "path escapes scaffold root"))
                continue
            size = path.stat().st_size
            if size > self.max_file_bytes:
                findings.append(Finding("blocker", "file_too_large", rel, "file exceeds maximum size policy"))
                continue
            digest = self._sha256(path)
            records.append(FileRecord(relative_path=rel, size_bytes=size, sha256=digest))
            findings.extend(self._secret_findings(path, rel))
        return records, findings

    def _secret_findings(self, path: Path, rel: str) -> list[Finding]:
        if path.suffix.lower() not in TEXT_EXTENSIONS and path.name != ".env":
            return []
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            return []
        import re

        findings = []
        for code, pattern in SECRET_PATTERNS.items():
            if re.search(pattern, text):
                findings.append(Finding("blocker", f"secret_{code}", rel, "possible secret detected"))
        return findings

    def _ignore_blocked(self, directory: str, names: list[str]) -> set[str]:
        ignored = set()
        for name in names:
            if name in self.blocked_names or fnmatch.fnmatch(name, "*.pyc"):
                ignored.add(name)
        return ignored

    def _manifest(
        self,
        source: Path,
        records: list[FileRecord],
        *,
        provenance: dict[str, object] | None = None,
    ) -> dict[str, object]:
        payload = {
            "created_at_epoch": int(time.time()),
            "engine": "openclaw-scaffold-guard",
            "files": [record.to_dict() for record in records],
            "source": str(source.resolve()),
            "version": 1,
        }
        if provenance is not None:
            payload["provenance"] = provenance
        return payload

    @staticmethod
    def _is_safe_relative(path: str) -> bool:
        pure = PurePosixPath(path)
        return not pure.is_absolute() and ".." not in pure.parts

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _elapsed_us(start_ns: int) -> int:
        return (time.perf_counter_ns() - start_ns) // 1000

    @staticmethod
    def _prepared_source(source: Path) -> "_PreparedSource":
        if source.is_dir():
            return _PreparedSource(path=source, kind="directory")
        if source.is_file() and tarfile.is_tarfile(source):
            tempdir = Path(tempfile.mkdtemp(prefix="scaffold_guard_archive_"))
            try:
                with tarfile.open(source) as archive:
                    for member in archive.getmembers():
                        if member.issym() or member.islnk():
                            raise ScaffoldError(f"archive contains blocked link: {member.name}")
                        if not ScaffoldEngine._is_safe_relative(member.name):
                            raise ScaffoldError(f"archive contains unsafe path: {member.name}")
                    archive.extractall(tempdir)
                entries = [entry for entry in tempdir.iterdir()]
                root = entries[0] if len(entries) == 1 and entries[0].is_dir() else tempdir
                return _PreparedSource(path=root, kind="archive", cleanup=tempdir)
            except Exception:
                shutil.rmtree(tempdir, ignore_errors=True)
                raise
        raise ScaffoldError(f"unsupported scaffold source: {source}")


@dataclass(frozen=True)
class _PreparedSource:
    path: Path
    kind: str
    cleanup: Path | None = None

    def __enter__(self) -> "_PreparedSource":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        if self.cleanup is not None:
            shutil.rmtree(self.cleanup, ignore_errors=True)
