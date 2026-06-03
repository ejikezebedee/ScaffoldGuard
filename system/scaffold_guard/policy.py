"""Named security profiles for Scaffold Guard."""

from __future__ import annotations

from dataclasses import dataclass

from .engine import ScaffoldError


@dataclass(frozen=True)
class PolicyProfile:
    name: str
    max_file_bytes: int
    max_archive_bytes: int
    require_remote_checksum: bool
    require_signed_lock: bool
    network_enabled_by_default: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "max_archive_bytes": self.max_archive_bytes,
            "max_file_bytes": self.max_file_bytes,
            "name": self.name,
            "network_enabled_by_default": self.network_enabled_by_default,
            "require_remote_checksum": self.require_remote_checksum,
            "require_signed_lock": self.require_signed_lock,
        }


POLICY_PROFILES = {
    "dev": PolicyProfile(
        name="dev",
        max_file_bytes=5_000_000,
        max_archive_bytes=25_000_000,
        require_remote_checksum=False,
        require_signed_lock=False,
    ),
    "commercial": PolicyProfile(
        name="commercial",
        max_file_bytes=3_000_000,
        max_archive_bytes=15_000_000,
        require_remote_checksum=True,
        require_signed_lock=True,
    ),
    "enterprise": PolicyProfile(
        name="enterprise",
        max_file_bytes=1_000_000,
        max_archive_bytes=10_000_000,
        require_remote_checksum=True,
        require_signed_lock=True,
    ),
}


def get_policy_profile(name: str) -> PolicyProfile:
    try:
        return POLICY_PROFILES[name]
    except KeyError as exc:
        allowed = ", ".join(sorted(POLICY_PROFILES))
        raise ScaffoldError(f"unknown policy profile: {name}; expected one of: {allowed}") from exc
