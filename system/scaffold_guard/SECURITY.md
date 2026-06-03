# Security Policy

## Supported Scope

Scaffold Guard currently supports local directory, local tar archive, and
policy-controlled GitHub archive sources.

## Security Guarantees

- Preview inspects a source without writing output files.
- Verify blocks non-empty destinations by default.
- Materialize uses a temporary staging directory before moving files into place.
- Audit compares generated files against `.scaffold_guard/manifest.json`.
- Template scripts are never executed.
- Symlinks are blocked.
- Unsafe archive paths are blocked.
- Common generated and VCS folders are skipped.
- Common secret patterns are blocked before materialization.
- Remote GitHub sources require an explicit repository allowlist.
- Remote GitHub fetching requires an explicit network-enabled policy.
- Optional checksum pinning blocks mismatched downloaded archives.
- Hardened and enterprise profiles require checksum pinning for remote
  materialization.
- Remote provenance is written into generated manifests.
- Signed template locks use HMAC-SHA256 with caller-provided keys.
- Lock verification detects source drift and lock tampering before use.

## Non-Goals

- Scaffold Guard is not a malware scanner.
- Scaffold Guard does not prove that application code is safe.
- Scaffold Guard does not validate dependency supply chains.
- Scaffold Guard does not guarantee remote source availability.
- Scaffold Guard does not replace legal, compliance, or production release review.
- Scaffold Guard does not manage signing key storage or rotation.

## Reporting Issues

For public release, create a private security reporting channel before accepting
external vulnerability reports.
