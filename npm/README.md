# tooltrust-mcp

MCP server that scans other MCP servers for prompt injection, supply chain attacks, excessive permissions, and privilege escalation. Add to your `.mcp.json` and let your AI agent audit its own tools.

> **First run** downloads a ~10MB Go binary from GitHub Releases and caches it at `~/.tooltrust-mcp/bin/`. Subsequent runs use the cached binary with no download.

## Quick start

Add to your `.mcp.json`:

```json
{
  "mcpServers": {
    "tooltrust": {
      "command": "npx",
      "args": ["-y", "tooltrust-mcp"]
    }
  }
}
```

Then ask your agent: `run tooltrust_scan_config`

## Available tools

| Tool | Description |
|------|-------------|
| `tooltrust_scan_config` | Scan all servers in your `.mcp.json` or `~/.claude.json` |
| `tooltrust_scan_server` | Scan a specific MCP server |
| `tooltrust_scanner_scan` | Scan a JSON blob of tool definitions |
| `tooltrust_lookup` | Look up a server's trust grade |
| `tooltrust_list_rules` | List all 13 security rules |

## Example output

```
Scan Summary: 14 tools scanned | 13 allowed | 1 need approval | 0 blocked
Tool Grades: A×13  C×1
Findings by Severity: HIGH×1  MEDIUM×14  LOW×1 (16 total)

Flagged Tools:
• search_files  🟡 GRADE C  needs approval
  [AS-002] High: Network access declared
  [AS-011] Low: Missing rate-limit or timeout
  Action now: Keep this tool on manual approval until the risky capabilities are reviewed.
```

## Links

- **GitHub:** https://github.com/AgentSafe-AI/tooltrust-scanner
- **Directory:** https://www.tooltrust.dev/
- **Rules:** https://github.com/AgentSafe-AI/tooltrust-scanner/blob/main/docs/RULES.md
