# ToolTrust Scanner

**Static scanner for MCP tool definitions — trust grades (A–F) before your agent calls a tool.** Coverage is expanding; **skills** and more agent tool formats are on the roadmap.

ToolTrust scans for prompt injection, data exfiltration, privilege escalation, and supply-chain issues — pure static analysis, no LLM calls, no data leaves your machine (except optional CVE lookups).

> Pure static analysis. No LLM calls. No data leaves your machine. Runs in milliseconds.

## Live Directory

Browse trust grades and scan-backed reports first: **[tooltrust.dev](https://www.tooltrust.dev/)**

[![ToolTrust Directory UI](https://raw.githubusercontent.com/AgentSafe-AI/tooltrust-scanner/main/docs/tooltrust-ui.png)](https://www.tooltrust.dev/)

*Then see it in the IDE — MCP demo:*

![ToolTrust MCP demo](https://raw.githubusercontent.com/AgentSafe-AI/tooltrust-scanner/main/docs/mcp-demo.gif)

## Scan your setup in 30 seconds

Add ToolTrust as an MCP server:

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

It reads your MCP config, connects to each server in parallel, scans every tool, and returns a risk report with grades and enforcement decisions.

## What it catches

| Threat | What it detects |
|--------|-----------------|
| Prompt injection | Malicious instructions hidden in tool descriptions |
| Arbitrary code execution | Tools that run `eval()`, `exec()`, or arbitrary scripts |
| Data exfiltration | Tools that send data to external endpoints |
| Privilege escalation | Tools requesting admin/sudo/root access |
| Supply-chain CVEs | Known vulnerabilities in server dependencies |
| Known malware | Confirmed compromised package versions (LiteLLM, Trivy, Langflow) |
| Typosquatting | Tool names impersonating legitimate tools |
| Tool shadowing | Duplicate tool names designed to hijack agent behavior |
| Insecure secret handling | Plaintext-style API keys, tokens, or passwords in tool inputs |
| Missing rate limits | Tools with no timeout or rate-limit configuration |
| Dependency visibility | Missing dependency metadata / repo URL limiting supply-chain analysis |
| Suspicious npm scripts / IOCs | Risky install scripts or known-bad registry indicators |
| Suspicious exfil wording | Descriptions suggesting forwarding user data externally (AS-017) |

**16** built-in rules run in this repo (**AS-001–AS-011**, **AS-013–AS-017**). **AS-012** (tool drift) is assessed in the **[ToolTrust Directory](https://github.com/AgentSafe-AI/tooltrust-directory)** when scans are compared over time. Full catalog: [docs/RULES.md](https://github.com/AgentSafe-AI/tooltrust-scanner/blob/main/docs/RULES.md) · [tooltrust.dev](https://www.tooltrust.dev/)

## Example snapshot (research cohort)

**[tooltrust.dev](https://www.tooltrust.dev/)** reflects current directory-wide results. One published pass used **207 MCP servers** and **3,235** tools — illustrative, not an exhaustive count of everything scanned today:

| Metric | Count |
|--------|-------|
| MCP servers in cohort | 207 |
| Individual tools analyzed | 3,235 |
| Total security findings | 3,613 |
| Servers with at least one finding | 145 (70%) |
| Clean Grade A | 22 (10%) |
| Servers with arbitrary code execution | 16 |

## More ways to use ToolTrust

- **CLI**: `tooltrust-scanner scan --server "npx -y @modelcontextprotocol/server-filesystem /tmp"`
- **Scan-before-install gate**: `tooltrust-scanner gate @modelcontextprotocol/server-memory -- /tmp`
- **GitHub Actions**: block risky servers in CI
- **Pre-commit hook**: auto-scan `.mcp.json` on every commit

Full docs: [Usage Guide](https://github.com/AgentSafe-AI/tooltrust-scanner/blob/main/docs/USAGE.md) · [Developer Guide](https://github.com/AgentSafe-AI/tooltrust-scanner/blob/main/docs/DEVELOPER.md)

## Links

- GitHub: [AgentSafe-AI/tooltrust-scanner](https://github.com/AgentSafe-AI/tooltrust-scanner)
- Live Directory: [tooltrust.dev](https://www.tooltrust.dev/)
- Security: [SECURITY.md](https://github.com/AgentSafe-AI/tooltrust-scanner/blob/main/docs/SECURITY.md)
- MIT Licensed
