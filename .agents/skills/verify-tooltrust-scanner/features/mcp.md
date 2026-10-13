# Use ToolTrust from an MCP client

An agent client starts the real `tooltrust-mcp` binary, discovers its tools, submits a JSON manifest for scanning, and requests the rules catalog.

## Sub-features

- `mcp-handshake`: actual JSON-RPC initialize response from the built binary.
- `mcp-discovery`: five expected ToolTrust tool names are advertised.
- `mcp-json-scan`: raw tool definitions reach the public scanning tool and produce findings.
- `mcp-rules`: the public catalog includes AS-001.

## How to get to it (user POV)

Configure the built `tooltrust-mcp` as an MCP stdio command; invoke `tooltrust_scanner_scan` or `tooltrust_list_rules`. `tooltrust_lookup`, `tooltrust_scan_server` and `tooltrust_scan_config` are advertised but their calls are NOT RUN here. Standalone `--rules`/`--help` and npm packaging are also outside this recipe.

## Driving it with verify.py

Preconditions: launch and doctor pass; no production MCP client/config required.

- Run `python3 .agents/skills/verify-tooltrust-scanner/scripts/verify.py drive --run "$TT_VERIFY_RUN" --feature mcp`.
- Inspect `mcp.requests.jsonl` and the `mcp-stdio` stdout/stderr transcripts. Require response IDs 1–4, five tool names, a successful scan containing the risky fixture and AS-001, and a catalog response with AS-001.
- EOF/process-group teardown closes only this run's server.

## Gotchas

The driver speaks the actual stdio protocol; it does not call Go handlers directly. Result IDs, not line order, associate responses with actions. Discovery of a tool is not verification of that tool's behavior. Catalog presence is not an execution test for every security rule. Online lookup and config-driven spawning require separate scoped evidence.
