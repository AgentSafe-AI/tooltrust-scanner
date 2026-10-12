# Vulnerability service failures

Run `verify.py drive --run "$TT_VERIFY_RUN" --feature osv` after launch. An owned loopback HTTP service replaces OSV; the real CLI and MCP binaries perform HTTP requests through `TOOLTRUST_OSV_URL`.

Require successful clean and malicious-package responses to remain distinguishable. Require HTTP 503, HTTP 429, malformed JSON, null JSON, partial dependency failure and timeout to fail the CLI with `scan incomplete` and no success report. Gate with an owned local package-lock inventory must refuse `--force` and preserve existing configuration when OSV fails. The MCP JSON scan must return `isError: true` on service failure. Capture query bodies, reports and exit codes, and close the owned HTTP listener even on failure.

This tests the OSV HTTP integration, not MCP HTTP transport. The live public OSV service and other inventory sources are NOT RUN. Missing lockfiles and source/runtime inventory mismatch remain separate coverage requirements.
