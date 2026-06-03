# Scaffold Guard Examples

These examples are safe public references for maintainers who want to evaluate
Scaffold Guard without exposing private repositories, credentials, or local
machine paths.

## sample_registry.json

`sample_registry.json` shows two registry entries:

- A checksum-pinned GitHub archive template for a hardened open-source release
  workflow.
- A local directory template for documentation scaffolding.

Validate it from the repository root:

```bash
python3 -m system.scaffold_guard validate-registry ./system/scaffold_guard/examples/sample_registry.json
```

Search it by tag:

```bash
python3 -m system.scaffold_guard search-registry ./system/scaffold_guard/examples/sample_registry.json --tag agent-safe
```

## sample_trace.json

`sample_trace.json` shows the structure produced by trace export during a
materialization request. It uses placeholder checksums and portable relative
paths so it can be committed publicly.

Generate a trace from a local template:

```bash
python3 -m system.scaffold_guard --policy-profile commercial materialize ./template ./generated/service --requester community-maintainer --directive "create open-source service scaffold" --trace-path ./trace.json
```
