# Inspect source for embedded MCP

A user points `scan-repo` at a directory to identify embedded MCP server usage and suspicious route authentication asymmetry. Presence detection does not enumerate tool contracts or assign a security grade.

## Sub-features

- `source-presence`: supported Go, Python and TypeScript fixtures are detected.
- `source-negative`: documentation snippets do not count as embedded servers.
- `source-routes`: the Go asymmetric-auth fixture emits AS-019.
- `source-rust`: a handwritten Rust JSON-RPC tools/list handler needs explicit recognition; tracked as an acceptance gap.

## How to get to it (user POV)

Run `tooltrust-scanner scan-repo --repo directory --output json --file result.json`. Default text output is another entry point and is NOT RUN by this recipe.

## Driving it with verify.py

Preconditions: launch and doctor pass. Existing `pkg/sourcedetect/testdata/fixtures` remains in the checkout.

- Run `python3 .agents/skills/verify-tooltrust-scanner/scripts/verify.py drive --run "$TT_VERIFY_RUN" --feature source`.
- Require true detection for three languages, false for docs-only data, AS-019 for the asymmetric route, and no `policies` grade output. Evidence includes one `.source.json` per case and exact CLI invocations.
- Run `--feature gaps` to generate/scan an owned Rust fixture. Require recognition before calling Rust presence supported; full tool/schema extraction needs additional cases from acceptance.md.

## Gotchas

A false presence result is not proof a repository has no MCP implementation. Scan limits, ignored files and SDK-less servers affect coverage. Current route fixtures are source snippets, not running HTTP services; they prove source findings only. Do not infer complete Rust schema support from recognizing an SDK import or tool name.
