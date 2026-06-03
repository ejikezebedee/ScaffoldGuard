"""Remote source adapters for Scaffold Guard.

Adapters resolve remote references into local archives, then the existing
ScaffoldEngine handles preview, materialize, and audit. No shell commands are
used for remote resolution.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from urllib.error import URLError
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen
import hashlib

from .engine import ScaffoldError
from .policy import PolicyProfile


@dataclass(frozen=True)
class GitHubArchiveRef:
    owner: str
    repo: str
    ref: str

    @property
    def repo_key(self) -> str:
        return f"{self.owner}/{self.repo}"

    @property
    def archive_url(self) -> str:
        owner = quote(self.owner, safe="")
        repo = quote(self.repo, safe="")
        ref = quote(self.ref, safe="")
        return f"https://github.com/{owner}/{repo}/archive/{ref}.tar.gz"

    def to_dict(self) -> dict[str, str]:
        return {
            "adapter": "github_archive",
            "archive_url": self.archive_url,
            "owner": self.owner,
            "ref": self.ref,
            "repo": self.repo,
            "repo_key": self.repo_key,
        }


@dataclass(frozen=True)
class RemoteSourcePolicy:
    allowed_repositories: frozenset[str]
    expected_sha256: str | None = None
    network_enabled: bool = False
    max_archive_bytes: int = 25_000_000
    profile: PolicyProfile | None = None

    @classmethod
    def from_allowed(
        cls,
        allowed_repositories: list[str] | tuple[str, ...],
        *,
        expected_sha256: str | None = None,
        network_enabled: bool = False,
        max_archive_bytes: int = 25_000_000,
        profile: PolicyProfile | None = None,
    ) -> "RemoteSourcePolicy":
        return cls(
            allowed_repositories=frozenset(allowed_repositories),
            expected_sha256=expected_sha256,
            network_enabled=network_enabled,
            max_archive_bytes=max_archive_bytes,
            profile=profile,
        )


@dataclass(frozen=True)
class RemoteArchive:
    archive_path: Path
    provenance: dict[str, object]


def parse_github_archive_ref(value: str) -> GitHubArchiveRef:
    """Parse supported GitHub refs.

    Supported forms:
    - github:owner/repo#ref
    - https://github.com/owner/repo#ref
    """

    if value.startswith("github:"):
        body = value.removeprefix("github:")
        repo_part, sep, ref = body.partition("#")
        if not sep:
            raise ScaffoldError("github source must include an explicit #ref")
        owner_repo = repo_part.split("/")
        if len(owner_repo) != 2:
            raise ScaffoldError("github source must use owner/repo")
        return _clean_github_ref(owner_repo[0], owner_repo[1], ref)

    parsed = urlparse(value)
    if parsed.scheme == "https" and parsed.netloc == "github.com":
        parts = [part for part in parsed.path.split("/") if part]
        if len(parts) != 2:
            raise ScaffoldError("github URL must use https://github.com/owner/repo#ref")
        if not parsed.fragment:
            raise ScaffoldError("github URL must include an explicit #ref")
        return _clean_github_ref(parts[0], parts[1], parsed.fragment)

    raise ScaffoldError("unsupported remote source; expected github:owner/repo#ref")


def resolve_github_archive(
    value: str,
    *,
    policy: RemoteSourcePolicy,
    work_dir: Path | None = None,
    downloader: Callable[[str, Path, int], None] | None = None,
) -> RemoteArchive:
    source_ref = parse_github_archive_ref(value)
    if source_ref.repo_key not in policy.allowed_repositories:
        raise ScaffoldError(f"remote source is not allowlisted: {source_ref.repo_key}")
    if policy.profile is not None and policy.profile.require_remote_checksum and policy.expected_sha256 is None:
        raise ScaffoldError(f"{policy.profile.name} policy requires --expected-sha256 for remote sources")
    if not policy.network_enabled:
        raise ScaffoldError("remote source fetching requires network_enabled policy")

    if work_dir is None:
        raise ScaffoldError("remote archive resolution requires an explicit work_dir")

    destination_dir = Path(work_dir)
    destination_dir.mkdir(parents=True, exist_ok=True)
    archive_path = destination_dir / f"{source_ref.owner}-{source_ref.repo}-{_safe_ref_name(source_ref.ref)}.tar.gz"

    if downloader is None:
        _download_url(source_ref.archive_url, archive_path, max_bytes=policy.max_archive_bytes)
    else:
        downloader(source_ref.archive_url, archive_path, policy.max_archive_bytes)

    digest = _sha256(archive_path)
    if policy.expected_sha256 is not None and digest != policy.expected_sha256:
        archive_path.unlink(missing_ok=True)
        raise ScaffoldError("downloaded archive checksum mismatch")

    return RemoteArchive(
        archive_path=archive_path,
        provenance={
            **source_ref.to_dict(),
            "archive_sha256": digest,
            "archive_size_bytes": archive_path.stat().st_size,
            "checksum_verified": policy.expected_sha256 is not None,
            "policy_profile": policy.profile.to_dict() if policy.profile is not None else None,
        },
    )


def _clean_github_ref(owner: str, repo: str, ref: str) -> GitHubArchiveRef:
    for label, value in {"owner": owner, "repo": repo, "ref": ref}.items():
        if not value or value.startswith(".") or ".." in value:
            raise ScaffoldError(f"invalid github {label}")
        if any(char in value for char in ("\\", "\0", "?", "&", " ")):
            raise ScaffoldError(f"invalid github {label}")
    if "/" in owner or "/" in repo:
        raise ScaffoldError("owner and repo cannot contain path separators")
    return GitHubArchiveRef(owner=owner, repo=repo, ref=ref)


def _safe_ref_name(ref: str) -> str:
    return "".join(char if char.isalnum() or char in ("-", "_", ".") else "-" for char in ref)


def _download_url(url: str, destination: Path, *, max_bytes: int) -> None:
    request = Request(url, headers={"User-Agent": "scaffold-guard/0.1"})
    try:
        with urlopen(request, timeout=30) as response, destination.open("wb") as handle:
            written = 0
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                written += len(chunk)
                if written > max_bytes:
                    destination.unlink(missing_ok=True)
                    raise ScaffoldError("remote archive exceeds maximum size policy")
                handle.write(chunk)
    except URLError as exc:
        raise ScaffoldError(f"remote archive download failed: {exc}") from exc


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
