# ToolTrust Usage Guide

This page collects the detailed CLI, gate, and CI integration examples for ToolTrust.

## MCP Tools

Use ToolTrust as an MCP server if you want your agent to scan other MCP servers directly inside Claude Code, Cursor, or Claude Desktop.

| Tool | Description |
|------|-------------|
| `tooltrust_scan_config` | Scan all MCP servers in `.mcp.json` or `~/.claude.json` |
| `tooltrust_scan_server` | Launch and scan a specific MCP server |
| `tooltrust_scanner_scan` | Scan a JSON blob of tool definitions |
| `tooltrust_lookup` | Look up a server's trust grade from ToolTrust Directory |
| `tooltrust_list_rules` | List all built-in security rules |

## CLI

```bash
# Install
curl -sfL https://raw.githubusercontent.com/AgentSafe-AI/tooltrust-scanner/main/install.sh | bash

# Scan any MCP server
tooltrust-scanner scan --server "npx -y @modelcontextprotocol/server-filesystem /tmp"

# Scan a local Node-based MCP server and inspect nearby lockfiles when possible
tooltrust-scanner scan --server "node ./server.js"

# Scan-then-install: gate checks a server before adding it to your config
tooltrust-scanner gate @modelcontextprotocol/server-memory -- /tmp
```

### Dependency visibility

ToolTrust reports how much dependency evidence it was able to recover during a scan:

- `No dependency data`: the MCP server did not expose `metadata.dependencies` or `repo_url`
- `Declared by MCP metadata`: dependencies came from the MCP payload
- `Verified from local lockfile`: dependencies were recovered from local artifacts near the launched server
- `Verified from remote lockfile`: dependencies were recovered from a repository lockfile via `repo_url`
- `Repo URL available`: a repository URL was exposed, even if no lockfile dependency was recovered yet

If ToolTrust cannot see dependency data, it now emits an informational finding so supply-chain coverage gaps are explicit instead of silent.

### Other install methods

```bash
# Go install
go install github.com/AgentSafe-AI/tooltrust-scanner/cmd/tooltrust-scanner@latest

# Homebrew
brew install AgentSafe-AI/tap/tooltrust-scanner

# Specific version
curl -sfL https://raw.githubusercontent.com/AgentSafe-AI/tooltrust-scanner/main/install.sh | VERSION=vX.Y.Z bash
```

## Gate

`tooltrust-scanner gate` scans an MCP server before installing it.

- Grade A/B: auto-install
- Grade C/D: prompt for confirmation
- Grade F: block entirely

```bash
# Scan and install if safe (writes .mcp.json)
tooltrust-scanner gate @modelcontextprotocol/server-memory -- /tmp

# Dry run — scan only, don't install
tooltrust-scanner gate --dry-run @modelcontextprotocol/server-filesystem -- /tmp

# Block anything below grade B
tooltrust-scanner gate --block-on B @some/package

# Install to user config (~/.claude.json) instead of project
tooltrust-scanner gate --scope user @some/package

# Override the server name in config
tooltrust-scanner gate --name my-server @some/package

# Force install regardless of grade (with warning)
tooltrust-scanner gate --force @some/package
```

| Flag | Default | Description |
|------|---------|-------------|
| `--name` | derived from package | Server name in config |
| `--dry-run` | `false` | Scan only, don't install |
| `--block-on` | `F` | Minimum grade that blocks: `F`, `D`, `C`, `B` |
| `--scope` | `project` | `project` (`.mcp.json`) or `user` (`~/.claude.json`) |
| `--force` | `false` | Bypass grade check |
| `--deep-scan` | `false` | Enable AI-based semantic analysis |
| `--rules-dir` | built-in | Custom YAML rules directory |

Exit codes:

- `0`: installed or dry-run
- `1`: blocked by policy
- `2`: error

## Pre-Hook Integration

### Shell alias

Replace `claude mcp add` with `tooltrust-scanner gate` so every install is scanned first:

```bash
alias mcp-add='tooltrust-scanner gate'
# mcp-add @modelcontextprotocol/server-memory -- /tmp
```

### Git pre-commit hook

If `.mcp.json` is checked into your repo, scan it on every commit:

```bash
# .git/hooks/pre-commit
#!/bin/sh
if git diff --cached --name-only | grep -q '\.mcp\.json'; then
  tooltrust-scanner scan --input .mcp.json --fail-on block || exit 1
fi
```

## GitHub Actions

```yaml
- name: Audit MCP Server
  uses: AgentSafe-AI/tooltrust-scanner@main
  with:
    server: "npx -y @modelcontextprotocol/server-filesystem /tmp"
    fail-on: "approval"
```
