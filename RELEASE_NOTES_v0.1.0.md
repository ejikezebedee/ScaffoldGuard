# Scaffold Guard v0.1.0 Release Notes

Scaffold Guard v0.1.0 is the first open-source release baseline for secure
project scaffolding by AI teams, coding agents, and developers.

## Positioning

Secure scaffolding for open-source AI teams, agents, and developers.

Scaffold Guard gives maintainers a clean-room way to preview, verify,
materialize, and audit template-based project creation before files are written
into a destination project.

## Seven-Phase Architecture Milestone

### Phase 1: Clean-Room Scaffold Engine

- Local template preview.
- Guarded materialization into a destination folder.
- No template script execution.
- No dependency installation.
- No implicit server startup.

### Phase 2: Safety Policy Foundation

- Secret-pattern detection.
- Unsafe path blocking.
- Symlink blocking.
- Generated and VCS folder exclusions.
- Non-empty destination protection.

### Phase 3: Manifest and Audit Layer

- Generated manifest records for materialized files.
- SHA-256 file integrity records.
- Audit checks for changed, missing, or unexpected files.
- Tampered or invalid manifest detection.

### Phase 4: Extra-File Audit Hardening

- Audit failure on files added outside the manifest.
- Stronger regression coverage around materialized output drift.
- Cleaner release audit documentation.

### Phase 5: Trust Layer

- HMAC-SHA256 signed template lock files.
- Lock verification before trusted reuse.
- Source drift detection.
- Lock tamper detection.
- Multi-tier policy profiles: `dev`, `commercial`, and `enterprise`.

### Phase 6: Registry and Trace Evidence

- Template registry validation.
- Registry search by query, tag, and policy profile.
- Directive/audit trace export for materialization requests.
- Public API exports for registry and trace helpers.

### Phase 7: Open-Source Release Readiness

- MIT license file.
- Contributor guide.
- Public community examples.
- Sample registry and trace files.
- Open-source positioning cleanup.
- Final leak/path scan.

## Included Verification

- Native test suite: `23/23` tests passing.
- Compile check passing.
- CLI help check passing.
- Sample registry validation and search passing.
- Sample trace JSON validation passing.
- No committed bytecode cache residue.
- No unrelated local files, repository history, logs, credentials, or sample app
  fragments included in the standalone export.

## Local Install

From the standalone export root:

```bash
python3 -m pip install -e ./system/scaffold_guard
```

Run the test suite:

```bash
python3 -m unittest system.scaffold_guard.tests.test_engine
```

Validate the sample registry:

```bash
python3 -m system.scaffold_guard validate-registry ./system/scaffold_guard/examples/sample_registry.json
```

## Release Boundary

This release is the public v0.1.0 open-source baseline. The repository and
version tag are published on GitHub for community review and use. No package
registry upload has been performed.
