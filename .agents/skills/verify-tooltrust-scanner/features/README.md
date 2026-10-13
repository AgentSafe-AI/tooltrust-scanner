# ToolTrust Scanner verification map

This index is the maintained source for user-facing verification. Read the relevant recipe before driving. Initial map targets the CLI and MCP stdio interfaces at scanner main revision `e1436162f9bf73d766a58a4f933fcdf215cdaf9f`; every run records the actual current revision and source hash.

## Preconditions

Launch and doctor using the parent SKILL.md. Use a fresh, owned run directory and `TT_VERIFY_RUN` containing its absolute path. All drives use scratch state and trusted fixtures. No API keys, production config or private data are required. Helpers capture commands and resulting state under `evidence/`; cleanup preserves it.

## Features

| ID | Recipe | Automated path |
|---|---|---|
| static | [Scan a JSON tool manifest](static.md) | JSON/text/SARIF, fail-on, custom rules, malformed input, SQLite |
| live | [Scan a running MCP server](live.md) | CLI stdio initialization/listing; no tool calls |
| source | [Inspect source for embedded MCP](source.md) | Go/Python/TS presence, negative fixture, auth-route asymmetry |
| mcp | [Use ToolTrust from an MCP client](mcp.md) | initialize, list, raw JSON scan, rules catalog |
| gate | [Scan before adding a server](gate.md) | dry-run, policy block, forced project-config install |
| osv | [Vulnerability service failures](osv.md) | Local HTTP success/error/timeout, partial failure, CLI and MCP propagation |

## Proof and gaps

`--feature all` runs the baseline rows; do not equate it with all advertised product entry points. Each feature lists additional entry points explicitly as NOT RUN. To claim one verified, add and execute a real-path recipe, including side-effect evidence.

`--feature gaps` probes Rust presence, pagination, and empty manifests/live discovery across CLI, gate and MCP (including config aggregation); FAIL is an unmet acceptance condition, not a passing expected failure. See [acceptance.md](../acceptance.md) for remaining planned coverage. A failure during a drive stops the remaining baseline features; its summary records only what was attempted. Do not describe omitted features as passed.
