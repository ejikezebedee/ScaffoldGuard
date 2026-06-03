"""CLI for OpenClaw guarded scaffold operations."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import tempfile

from .engine import ScaffoldEngine, ScaffoldError
from .locks import verify_template_lock, write_template_lock
from .policy import get_policy_profile
from .registry import load_registry, search_registry
from .source_adapters import RemoteSourcePolicy, resolve_github_archive
from .trace import write_materialization_trace


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m system.scaffold_guard")
    parser.add_argument("--max-file-bytes", type=int, default=5_000_000)
    parser.add_argument("--policy-profile", choices=("dev", "commercial", "enterprise"), default="dev")

    subcommands = parser.add_subparsers(dest="command", required=True)

    preview = subcommands.add_parser("preview", help="Inspect a scaffold source without writing.")
    preview.add_argument("source")

    verify = subcommands.add_parser("verify", help="Run source and destination policy checks.")
    verify.add_argument("source")
    verify.add_argument("--dest")

    materialize = subcommands.add_parser("materialize", help="Create a guarded project copy.")
    materialize.add_argument("source")
    materialize.add_argument("dest")
    materialize.add_argument("--requester")
    materialize.add_argument("--trace-path")
    materialize.add_argument("--directive")

    github = subcommands.add_parser("materialize-github", help="Materialize an approved GitHub archive source.")
    github.add_argument("source", help="github:owner/repo#ref or https://github.com/owner/repo#ref")
    github.add_argument("dest")
    github.add_argument("--allow", action="append", default=[], help="Allowed owner/repo. Repeat as needed.")
    github.add_argument("--expected-sha256")
    github.add_argument("--enable-network", action="store_true")
    github.add_argument("--requester")
    github.add_argument("--trace-path")
    github.add_argument("--directive")

    lock_source = subcommands.add_parser("lock-source", help="Create a signed template lock file.")
    lock_source.add_argument("source")
    lock_source.add_argument("lock_path")
    lock_source.add_argument("--signing-key", required=True)

    verify_lock = subcommands.add_parser("verify-lock", help="Verify a signed template lock file.")
    verify_lock.add_argument("source")
    verify_lock.add_argument("lock_path")
    verify_lock.add_argument("--signing-key", required=True)

    registry_validate = subcommands.add_parser("validate-registry", help="Validate a template registry index.")
    registry_validate.add_argument("registry_path")

    registry_search = subcommands.add_parser("search-registry", help="Search a validated template registry index.")
    registry_search.add_argument("registry_path")
    registry_search.add_argument("--query")
    registry_search.add_argument("--tag")
    registry_search.add_argument("--profile")

    audit = subcommands.add_parser("audit", help="Validate a materialized scaffold manifest.")
    audit.add_argument("dest")

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    profile = get_policy_profile(args.policy_profile)
    max_file_bytes = args.max_file_bytes if args.max_file_bytes != 5_000_000 else profile.max_file_bytes
    engine = ScaffoldEngine(max_file_bytes=max_file_bytes)

    try:
        if args.command == "preview":
            report = engine.preview(Path(args.source))
            print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
            return 0 if report.allowed else 2

        if args.command == "verify":
            destination = Path(args.dest) if args.dest else None
            report = engine.verify(Path(args.source), destination)
            print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
            return 0 if report.allowed else 2

        if args.command == "materialize":
            report = engine.materialize(Path(args.source), Path(args.dest))
            if args.trace_path:
                audit = engine.audit(Path(args.dest))
                write_materialization_trace(
                    Path(args.trace_path),
                    report,
                    requester=args.requester or "unknown",
                    policy_profile=profile,
                    audit=audit,
                    directive=args.directive,
                )
            print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
            return 0

        if args.command == "materialize-github":
            policy = RemoteSourcePolicy.from_allowed(
                args.allow,
                expected_sha256=args.expected_sha256,
                network_enabled=args.enable_network,
                max_archive_bytes=profile.max_archive_bytes,
                profile=profile,
            )
            with tempfile.TemporaryDirectory(prefix="scaffold_guard_remote_") as work_dir:
                archive = resolve_github_archive(args.source, policy=policy, work_dir=Path(work_dir))
                report = engine.materialize(
                    archive.archive_path,
                    Path(args.dest),
                    provenance=archive.provenance,
                )
                if args.trace_path:
                    audit = engine.audit(Path(args.dest))
                    write_materialization_trace(
                        Path(args.trace_path),
                        report,
                        requester=args.requester or "unknown",
                        policy_profile=profile,
                        audit=audit,
                        directive=args.directive,
                    )
            print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
            return 0

        if args.command == "lock-source":
            payload = write_template_lock(
                Path(args.source),
                Path(args.lock_path),
                engine=engine,
                policy_profile=profile,
                signing_key=args.signing_key,
            )
            print(json.dumps(payload, indent=2, sort_keys=True))
            return 0

        if args.command == "verify-lock":
            payload = verify_template_lock(
                Path(args.source),
                Path(args.lock_path),
                engine=engine,
                signing_key=args.signing_key,
            )
            print(json.dumps({"lock_path": args.lock_path, "profile": payload["policy_profile"], "verified": True}, indent=2, sort_keys=True))
            return 0

        if args.command == "validate-registry":
            report = load_registry(Path(args.registry_path))
            print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
            return 0 if report.valid else 2

        if args.command == "search-registry":
            report = load_registry(Path(args.registry_path))
            if not report.valid:
                print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
                return 2
            entries = search_registry(
                report,
                query=args.query,
                tag=args.tag,
                policy_profile=args.profile,
            )
            print(json.dumps({"entries": [entry.to_dict() for entry in entries]}, indent=2, sort_keys=True))
            return 0

        if args.command == "audit":
            report = engine.audit(Path(args.dest))
            print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
            return 0 if report.passed else 2
    except ScaffoldError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    return 1
