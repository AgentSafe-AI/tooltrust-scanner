# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

---

## [0.1.3] - 2026-03-04

### Changed

- **BREAKING**: Repository renamed from `agentsentry` to `tooltrust-scanner`
- Binary renamed: `agentsentry` → `tooltrust-scanner`, `agentsentry-mcp` → `tooltrust-scanner-mcp`
- MCP tool renamed: `agentsentry_scan` → `tooltrust_scanner_scan`
- Module path: `github.com/AgentSafe-AI/tooltrust-scanner`

### Added

- `--fail-on` flag: exit non-zero if any tool reaches `allow` | `approval` | `block`
- `--db` flag: persist scan results to SQLite
- `testdata/tools.json`: 6-tool MCP fixture for E2E testing
- Unit tests for `checkFailOn` logic in CLI
- `storage.OpenContext` for context-aware DB initialization

### Fixed

- Engine docstring: corrected rule mapping (AS-003, AS-004, etc.)
- Homebrew formula: fixed install path to match renamed cmd entrypoint (`cmd/tooltrust-scanner`)

---

## [0.1.2] - 2026-03-01

### Added

- AS-005 Privilege Escalation checker
- AS-010 Secret Handling checker
- AS-011 DoS Resilience checker
- ToolTrust methodology alignment (grade boundaries, severity weights)
- `docs/DEVELOPER.md` developer guide
- Problem-focused README restructure

### Changed

- Grade boundaries: A:0–9, B:10–24, C:25–49, D:50–74, F:75+
- Severity weights: Low=2, Info=0 (ToolTrust v1.0)
- JSON output: snake_case, `schema_version`, `scanned_at` for ToolTrust Directory

---

## [0.1.0] - 2026-03-01

### Added

- Initial Go rewrite of AgentSafe
- CLI: `tooltrust-scanner scan`, `tooltrust-scanner version`
- MCP adapter and protocol support
- Scan rules: AS-001 (Tool Poisoning), AS-002 (Permission Surface), AS-003 (Scope Mismatch), AS-004 (Supply Chain CVE)
- Risk scoring with A–F grades
- Gateway policy generation (ALLOW, REQUIRE_APPROVAL, BLOCK)
- SQLite storage for scan history
- MCP meta-scanner server (`tooltrust-scanner-mcp`)
- Docker image, CI/CD, GitHub Actions

[Unreleased]: https://github.com/AgentSafe-AI/tooltrust-scanner/compare/v0.1.3...HEAD
[0.1.3]: https://github.com/AgentSafe-AI/tooltrust-scanner/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/AgentSafe-AI/tooltrust-scanner/compare/v0.1.0...v0.1.2
[0.1.0]: https://github.com/AgentSafe-AI/tooltrust-scanner/releases/tag/v0.1.0
