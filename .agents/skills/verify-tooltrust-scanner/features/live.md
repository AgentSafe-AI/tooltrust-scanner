# Scan a running MCP server

A user supplies a command, and ToolTrust starts a stdio MCP server, lists its tools, and scans their contracts without invoking the tools.

## Sub-features

- `live-handshake`: initialize and tools/list reach an actual subprocess.
- `live-parity`: equivalent static and live tool definitions produce matching named policies/scores.
- `live-no-execution`: request logs contain no tools/call.
- `live-pagination`: the risky second-page tool must not be missed; checked in the separate acceptance suite and passed in the initial run.

## How to get to it (user POV)

CLI: `tooltrust-scanner scan --server "command args"`. MCP users can also invoke `tooltrust_scan_server` or `tooltrust_scan_config`; these secondary live entry points are NOT RUN by this recipe.

## Driving it with verify.py

Preconditions: launch and doctor pass. Only the helper's owned fixture may be started.

- Run `python3 .agents/skills/verify-tooltrust-scanner/scripts/verify.py drive --run "$TT_VERIFY_RUN" --feature live`.
- Inspect `live.requests.jsonl` for initialize/tools/list and no tools/call; inspect `live.report.json` and `live-comparison.report.json` for both tools and equal policies/scores.
- Run `--feature gaps` separately to exercise the cursor-bearing fixture. Inspect `gap-pagination.requests.jsonl` and `gaps.summary.json`; require the second page and risky policy before accepting pagination support.

## Gotchas

Starting a third-party server can execute arbitrary code even when no tool is called. This harness substitutes a trusted fixture at the protocol boundary; it does not prove sandboxing. Production live timeout/error/abort behavior, HTTP transport, multiple configurations and credentials need explicit future recipes. The harness's own timeout is not evidence that the product timed out correctly.
