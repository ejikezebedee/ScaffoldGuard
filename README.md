# Scaffold Guard

![ScaffoldGuard product image](./assets/scaffoldguard-product-image.png)

Scaffold Guard is an open-source, clean-room project materialization engine for
safe template use by humans and coding agents.

It takes the useful idea behind lightweight repository scaffolding and adds
governance controls before files are written.

## Positioning

Secure scaffolding for open-source AI teams, agents, and developers.

`degit` is fast because it strips Git history and copies a repository snapshot.
Scaffold Guard targets a stricter operating lane: it previews, verifies,
materializes, and audits template output so agent-driven project creation can be
reviewed and reproduced.

## Install From Source

```bash
python -m pip install -e ./system/scaffold_guard
```

The package exposes a console command:

```bash
scaffold-guard --help
```

## Policy Profiles

Scaffold Guard supports named policy profiles:

- `dev`: permissive local development defaults.
- `commercial`: hardened release profile with tighter file/archive limits,
  required remote checksums, and signed lock files.
- `enterprise`: strictest default limits for high-control environments.

Select a profile with `--policy-profile`:

```bash
python -m system.scaffold_guard --policy-profile commercial verify ./template --dest ./new-project
```

## Commands

Preview a template source without writing:

```bash
python -m system.scaffold_guard preview ./template
scaffold-guard preview ./template
```

Verify a source and destination:

```bash
python -m system.scaffold_guard verify ./template --dest ./new-project
scaffold-guard verify ./template --dest ./new-project
```

Materialize a guarded copy:

```bash
python -m system.scaffold_guard materialize ./template ./new-project
scaffold-guard materialize ./template ./new-project
```

Export a directive/audit trace during materialization:

```bash
python -m system.scaffold_guard --policy-profile commercial materialize ./template ./new-project --requester community-maintainer --directive "create open-source service scaffold" --trace-path ./trace.json
```

Materialize an approved GitHub archive source:

```bash
python -m system.scaffold_guard materialize-github github:owner/repo#main ./new-project --allow owner/repo --expected-sha256 <sha256> --enable-network
scaffold-guard materialize-github github:owner/repo#main ./new-project --allow owner/repo --expected-sha256 <sha256> --enable-network
```

Create and verify a signed template lock:

```bash
python -m system.scaffold_guard --policy-profile commercial lock-source ./template ./template.scaffold-lock.json --signing-key "$SCAFFOLD_GUARD_LOCK_KEY"
python -m system.scaffold_guard verify-lock ./template ./template.scaffold-lock.json --signing-key "$SCAFFOLD_GUARD_LOCK_KEY"
```

Validate and search an approved template registry:

```bash
python -m system.scaffold_guard validate-registry ./registry.json
python -m system.scaffold_guard search-registry ./registry.json --tag web --profile commercial
```

Audit the generated project against its manifest:

```bash
python -m system.scaffold_guard audit ./new-project
scaffold-guard audit ./new-project
```

## Current Scope

- Local directory, tar archive, and policy-controlled GitHub archive sources.
- No template script execution.
- Secret-pattern blocking before materialization.
- Symlink and unsafe path blocking.
- Atomic staging before destination writes.
- Manifest-based audit after generation.
- Remote source provenance stored in generated manifests.
- Policy profiles for development, commercial, and enterprise guard levels.
- Signed template locks with source fingerprints and HMAC-SHA256 signatures.
- Template registry validation and search for approved template catalogs.
- Directive/audit trace export for materialization evidence.

## Examples

Community reference examples live in `examples/`:

- `examples/sample_registry.json`: valid template registry entries for a
  policy-controlled GitHub archive and a local documentation starter.
- `examples/sample_trace.json`: realistic directive/audit trace output using
  portable relative paths and placeholder checksums.

Validate and search the sample registry:

```bash
python -m system.scaffold_guard validate-registry ./system/scaffold_guard/examples/sample_registry.json
python -m system.scaffold_guard search-registry ./system/scaffold_guard/examples/sample_registry.json --tag agent-safe
```

## Security Model

Scaffold Guard does not trust template contents by default.

The engine blocks or warns on:

- VCS and generated folders such as `.git`, `__pycache__`, and `node_modules`.
- Symlinks, including symlinked directories.
- Unsafe archive paths that attempt to escape the scaffold root.
- Oversized files above the configured policy limit.
- Common secret patterns in text files.
- Non-empty destinations unless the caller has an explicit overwrite policy.
- Invalid or tampered audit manifests.
- Commercial and enterprise policy profiles require checksum pinning for remote
  sources.
- Signed template lock verification fails when source files drift or the lock is
  tampered with.

The engine does not:

- Execute template scripts.
- Install dependencies.
- Contact remote services unless the caller explicitly enables network access.
- Start servers.
- Store credentials. Signing keys are caller-provided and are never written into
  generated manifests or lock files.

## Source Adapter Roadmap

The current safe adapter set is:

- Local directory
- Local tar archive
- GitHub archive source with explicit allowlist and optional checksum pinning
- Signed template lock files for repeatable trusted sources
- Template registry index with owner, version, tags, source metadata, checksum,
  policy profile, and approved use case
- Directive/audit trace export for materialization requests

The next adapters should be added in this order:

1. Release archive URL with checksum pinning.
2. Registry publishing after license and provenance checks.
3. Aggregate analytics for blocked findings, audits, source types, and usage.
4. License/SBOM reporting for approved registry entries.

## Open-Source Direction

The project is built for public open-source release. Future community work can
include additional remote source adapters, registry publishing, license/SBOM
reporting, aggregate safety analytics, and stricter policy packs.

## Public Release Hygiene

- Standard-library Python only.
- No private paths or credentials required.
- Examples use portable relative paths.
- No machine-specific local paths are required for public use.
- Production network fetching remains intentionally disabled.
- Lock-file examples use environment variables for signing keys.
- Trace examples use portable relative output paths.

## Release Checklist

- Documentation explains preview, verify, materialize, and audit.
- Packaging metadata is present.
- License choice is explicit.
- Security model is documented.
- Tests cover secrets, unsafe archive paths, symlinks, dry-run behavior,
  non-empty destinations, junk exclusions, manifest tampering, audit drift,
  extra-file audit failure, remote allowlists, checksum mismatch,
  network-disabled fallback, provenance recording, commercial checksum policy,
  signed lock verification, lock tamper detection, source drift detection,
  registry validation/search, and directive/audit trace export.
- Examples use portable relative paths.
- No sensitive values, server paths, or internal-only references are present.
