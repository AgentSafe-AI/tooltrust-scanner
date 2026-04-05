<img src="https://github.com/AgentSafe-AI/.github/raw/main/profile/logo.png" alt="AgentSafe AI" width="80" />

# AgentSafe AI

**Agent tools are an attack surface — we help you see the risk before your agent acts.**

AI agents are powerful — but every tool they call can hide prompt injection, data exfiltration, privilege escalation, and supply-chain backdoors. We build open-source tools that scan production **tool definitions** (today heavily **MCP**; **skills** and more surfaces are on the roadmap) and surface trust grades before anything runs.

---

### ToolTrust Scanner

Static security scanner for MCP server tool definitions. **16** active security rules in this repo, plus explicit supply-chain visibility signals for missing dependency data and transitive dependency coverage from common lockfiles. **AS-012** (tool drift) is surfaced in the **[ToolTrust Directory](https://github.com/AgentSafe-AI/tooltrust-directory)** when new scans are compared to prior results. Battle-tested against hundreds of production servers.

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

Then ask your agent: *"Run tooltrust_scan_config"*

[tooltrust-scanner →](https://github.com/AgentSafe-AI/tooltrust-scanner)

### ToolTrust Directory

Public trust registry: browse scan-backed grades, compare servers, and verify before you install. **[tooltrust.dev](https://www.tooltrust.dev)** stays current as automated scanning scales beyond any single cohort.

[www.tooltrust.dev →](https://www.tooltrust.dev)

---

### What we detect

| Threat | What happens |
|--------|-------------|
| Prompt injection | Malicious instructions hidden in tool descriptions hijack your agent |
| Arbitrary code execution | Tools run `eval()`, `exec()`, or scripts on your machine |
| Data exfiltration | Tools send your data to external endpoints |
| Privilege escalation | Tools grab admin/sudo/root access beyond their stated purpose |
| Supply-chain attacks | Known compromised packages (LiteLLM, Trivy, Langflow) |
| Tool shadowing | Duplicate tool names hijack agent behavior |

### Aggregate stats

Directory-wide metrics and trends live on **[tooltrust.dev](https://www.tooltrust.dev)**. One published research snapshot (207 MCP servers, 3,235 tools) found **70%** of servers with at least one finding and **10%** with a clean Grade A — use the live site for numbers that reflect current scanning scope.

### Get involved

- Report a vulnerability: [SECURITY.md](https://github.com/AgentSafe-AI/tooltrust-scanner/blob/main/docs/SECURITY.md)
- Contribute: [CONTRIBUTING.md](https://github.com/AgentSafe-AI/tooltrust-scanner/blob/main/docs/CONTRIBUTING.md)
- Contact: **contact@tooltrust.dev**
- MIT Licensed
