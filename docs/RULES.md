# Security Rules

ToolTrust Scanner checks every MCP tool against 13 built-in rules.
Each rule fires independently; a tool can trigger multiple rules.

---

## 🚨 AS-001 — Prompt Injection / Tool Poisoning

**Severity:** Critical

Detects malicious instructions hidden in tool names or descriptions that attempt to hijack the agent's reasoning, override system prompts, or redirect behavior toward attacker-controlled goals.

Common patterns: `ignore previous instructions`, `system:`, `exfiltrate data to`, role-override language, base64-encoded payloads.

---

## ⚠️ AS-002 — Excessive Permissions

**Severity:** High / Low (depends on permission type)

Flags tools that declare broad capabilities — filesystem access, network access, database access, or arbitrary code execution — without a clear, scoped justification.

Permissions checked: `exec`, `network`, `fs`, `db`.

---

## 🔀 AS-003 — Scope Mismatch

**Severity:** High

Fires when a tool's name implies one capability but its description or schema claims another. Example: a tool called `read_file` that also declares network write access.

---

## 📦 AS-004 — Supply Chain CVEs (OSV)

**Severity:** High / Critical

Queries the [OSV vulnerability database](https://osv.dev) for known CVEs in packages declared as dependencies. Requires network access during scan; results are cached per run.

---

## 🔐 AS-005 — Privilege Escalation

**Severity:** High

Detects tools that request or claim `admin`, `root`, `sudo`, or elevated permission scopes beyond what the tool's stated purpose requires.

---

## 💻 AS-006 — Arbitrary Code Execution

**Severity:** Critical

Flags tools whose name or description implies the ability to run arbitrary host commands, scripts, or code. Patterns include `exec`, `eval`, `shell`, `run_code`, `execute_script`, backtick shell syntax.

---

## ℹ️ AS-007 — Missing Description or Schema

**Severity:** Info

Tools with no description or no input schema give the agent no basis for safe use. Flagged as informational — not a security risk by itself, but a quality signal.

---

## 🚨 AS-008 — Known-Compromised Packages (Offline Blacklist)

**Severity:** Critical

Checks an offline bundled blacklist of packages confirmed to have been compromised in supply chain attacks. No network required — zero latency.

Current blacklist: LiteLLM 1.82.7/1.82.8 (TeamPCP `.pth` backdoor), Trivy v0.69.4–v0.69.6 (CI pipeline compromise), Langflow < 1.9.0 (unauthenticated RCE).

---

## 🎭 AS-009 — Typosquatting

**Severity:** Medium

Uses edit-distance heuristics to detect tool names that closely resemble known legitimate tools — a common technique for impersonation attacks. Tuned to avoid false positives on legitimate plural/variant tool families.

---

## 🔑 AS-010 — Insecure Secret Handling

**Severity:** Medium

Flags tools whose input parameters appear designed to accept secrets (API keys, tokens, passwords) in plaintext rather than via environment variables or secret stores.

---

## ℹ️ AS-011 — Missing Rate-Limit / Timeout

**Severity:** Low

Tools that perform network or execution operations without declaring rate-limit, timeout, or retry configuration can cause runaway agent behavior or denial-of-service conditions.

---

## 🔄 AS-012 — Tool Drift

**Severity:** Medium

Detects tools whose definition has changed since the last scan — new parameters added, descriptions modified, or permissions expanded. Drift can indicate a supply chain compromise or unreviewed update.

---

## 👥 AS-013 — Tool Shadowing

**Severity:** High / Medium

Detects tools whose names are exact normalized duplicates of other tools in the same server — a sign that a malicious tool is attempting to shadow or override a legitimate one.

Near-duplicate detection (edit distance 1) was removed in v0.1.15 after a 13/13 false-positive rate on legitimate tool families. Only exact normalized duplicates fire this rule.
