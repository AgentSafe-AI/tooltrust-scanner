# ToolTrust Scanner

[![CI](https://github.com/AgentSafe-AI/tooltrust-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/AgentSafe-AI/tooltrust-scanner/actions/workflows/ci.yml)
[![Security](https://github.com/AgentSafe-AI/tooltrust-scanner/actions/workflows/security.yml/badge.svg)](https://github.com/AgentSafe-AI/tooltrust-scanner/actions/workflows/security.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/AgentSafe-AI/tooltrust-scanner)](https://goreportcard.com/report/github.com/AgentSafe-AI/tooltrust-scanner)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Scan MCP servers for prompt injection, data exfiltration, and privilege escalation before your AI agent blindly trusts them.**

![ToolTrust Scanner demo](docs/demo.gif)

## 🤖 Let your AI agent scan its own tools

Add ToolTrust as an MCP server in your `.mcp.json` and your agent can audit every tool it has access to:

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

Then ask your agent to run `tooltrust_scan_config` — it reads your MCP config and scans all servers in parallel.

| Tool | Description |
|------|-------------|
| `tooltrust_scan_config` | Scan all servers in your `.mcp.json` or `~/.claude.json` in parallel |
| `tooltrust_scan_server` | Launch and scan a specific MCP server |
| `tooltrust_scanner_scan` | Scan a JSON blob of tool definitions |
| `tooltrust_lookup` | Look up a server's trust grade from the [ToolTrust Directory](https://tooltrust-directory.vercel.app) |
| `tooltrust_list_rules` | List all 11 security rules with IDs and descriptions |

## 💻 CLI

```bash
# Install
curl -sfL https://raw.githubusercontent.com/AgentSafe-AI/tooltrust-scanner/main/install.sh | bash

# Scan any MCP server
tooltrust-scanner scan --server "npx -y @modelcontextprotocol/server-filesystem /tmp"
```

<details>
<summary>Other install methods</summary>

```bash
# Go install
go install github.com/AgentSafe-AI/tooltrust-scanner/cmd/tooltrust-scanner@latest

# Homebrew
brew install AgentSafe-AI/tap/tooltrust-scanner

# Specific version
curl -sfL https://raw.githubusercontent.com/AgentSafe-AI/tooltrust-scanner/main/install.sh | VERSION=vX.Y.Z bash
```
</details>

## 🔍 What it catches

| ID | Severity | Detects |
|----|:--------:|---------|
| **AS-001** | Critical | Prompt poisoning / injection in tool descriptions |
| **AS-002** | High/Low | Excessive permissions (`exec`, `network`, `db`, `fs`) |
| **AS-003** | High | Scope mismatch (name contradicts permissions) |
| **AS-004** | High/Crit | Supply chain CVEs via [OSV](https://osv.dev) |
| **AS-005** | High | Privilege escalation (`admin` scopes, `sudo`) |
| **AS-006** | Critical | Arbitrary code execution |
| **AS-007** | Info | Missing description or schema |
| **AS-009** | Medium | Typosquatting (edit-distance impersonation) |
| **AS-010** | Medium | Insecure secret handling in params |
| **AS-011** | Low | Missing rate-limits or timeouts |
| **AS-013** | High/Med | Tool shadowing (duplicate name hijacking) |

## 🤝 GitHub Actions

```yaml
- name: Audit MCP Server
  uses: AgentSafe-AI/tooltrust-scanner@main
  with:
    server: "npx -y @modelcontextprotocol/server-filesystem /tmp"
    fail-on: "approval"
```

---

[Developer guide](docs/DEVELOPER.md) · [Contributing](docs/CONTRIBUTING.md) · [Changelog](CHANGELOG.md) · [Security](docs/SECURITY.md) · [License: MIT](LICENSE) © 2026 AgentSafe-AI
