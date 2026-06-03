# Release Audit

## Product Status

Scaffold Guard is in Phase 7 open-source release readiness.

## Packaging

- Package metadata exists in `pyproject.toml`.
- Console entry point is `scaffold-guard`.
- Runtime dependency target remains standard-library only.
- Package metadata declares the MIT license.
- Module license file is present.

## Documentation

- README covers positioning, install, commands, current scope, security model,
  policy profiles, signed lock files, template registry, trace export, roadmap,
  and release checklist.
- CONTRIBUTING covers clone, editable install, native tests, compile checks, and
  contribution rules.
- Security policy documents guarantees and non-goals.
- Examples use portable relative paths.
- Open-source examples include a sample registry and sample trace.

## Security Coverage

Current regression coverage includes:

- Clean template preview.
- Secret detection.
- Manifest write and audit pass.
- Junk folder exclusion.
- Audit drift detection.
- Non-empty destination blocking.
- Tar archive materialization.
- Unsafe archive path rejection.
- Symlinked directory blocking.
- Preview no-write behavior.
- Invalid manifest detection.
- Extra-file audit detection.
- GitHub reference parsing.
- Unapproved GitHub source blocking.
- Network-disabled GitHub source blocking.
- GitHub archive checksum mismatch blocking.
- GitHub archive materialization with manifest provenance.
- Commercial remote checksum requirement.
- Signed template lock creation and verification.
- Signed template lock source drift detection.
- Signed template lock tamper detection.
- Template registry validation.
- Template registry search.
- Malformed archive registry entry blocking.
- Directive/audit trace export.

## Phase 7 Verification

- Native test suite passes with `python3 -m unittest
  system.scaffold_guard.tests.test_engine`.
- Compile check passes with `python3 -m compileall -q system/scaffold_guard`.
- CLI help check passes.
- Sample registry validates and is searchable.
- Sample trace is valid JSON.
- Sale-positioning scan is clean.
- Path, credential, and local-server scan found no exposed private data. The
  only hit is the intentional private-key detector pattern in `engine.py`.

## Release Blockers Before Public Launch

- Decide whether package source should remain under `system/scaffold_guard/` or
  move to a distribution-native `src/` layout.
- Decide whether the hardened release profile should become the default for
  packaged releases.
- Run a final repository-wide leak scan before publication.
