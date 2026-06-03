# Contributing to Scaffold Guard

Scaffold Guard is an open-source security tool for guarded project
scaffolding. Contributions should improve safe template use for AI teams,
agents, and developers without adding hidden execution, credential handling, or
unreviewed network behavior.

## Clone and Install

Scaffold Guard is released under the MIT License. See `LICENSE` in this module
for the full text.

From the repository root:

```bash
python3 -m pip install -e ./system/scaffold_guard
```

Confirm the command is available:

```bash
python3 -m system.scaffold_guard --help
scaffold-guard --help
```

## Run Tests

Run the native test suite from the repository root:

```bash
python3 -m unittest system.scaffold_guard.tests.test_engine
```

Run a compile check before opening a pull request:

```bash
python3 -m compileall -q system/scaffold_guard
```

## Contribution Rules

- Keep runtime dependencies standard-library only unless a dependency is
  strongly justified.
- Do not add template script execution.
- Do not store signing keys, tokens, or credentials in examples, tests, logs, or
  manifests.
- Keep network access disabled unless the caller explicitly enables it.
- Prefer portable relative paths in examples and documentation.
- Add focused tests for every new source adapter, policy rule, audit behavior,
  or CLI command.

## Pull Request Checklist

- Tests pass with `python3 -m unittest system.scaffold_guard.tests.test_engine`.
- `python3 -m compileall -q system/scaffold_guard` passes.
- README or examples are updated when behavior changes.
- No sensitive paths, credentials, local logs, or internal-only references are
  included.
- Security-sensitive behavior is documented in `SECURITY.md`.
