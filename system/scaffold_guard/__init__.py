"""Guarded scaffold materialization for agent-safe project creation."""

from .engine import (
    AuditReport,
    MaterializeReport,
    PreviewReport,
    ScaffoldEngine,
    ScaffoldError,
    VerifyReport,
)
from .locks import build_template_lock, verify_template_lock, write_template_lock
from .policy import PolicyProfile, get_policy_profile
from .registry import RegistryEntry, RegistryReport, load_registry, search_registry
from .source_adapters import GitHubArchiveRef, RemoteArchive, RemoteSourcePolicy, parse_github_archive_ref
from .trace import build_materialization_trace, write_materialization_trace

__all__ = [
    "AuditReport",
    "GitHubArchiveRef",
    "PolicyProfile",
    "MaterializeReport",
    "PreviewReport",
    "RemoteArchive",
    "RemoteSourcePolicy",
    "RegistryEntry",
    "RegistryReport",
    "ScaffoldEngine",
    "ScaffoldError",
    "VerifyReport",
    "build_template_lock",
    "build_materialization_trace",
    "get_policy_profile",
    "load_registry",
    "parse_github_archive_ref",
    "search_registry",
    "verify_template_lock",
    "write_materialization_trace",
    "write_template_lock",
]
