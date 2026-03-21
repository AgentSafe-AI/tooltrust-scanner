# Changelog

All notable changes to tooltrust-scanner are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [0.1.13] - 2026-03-21

### Fixed
- **MCP parser**: The JSON Schema `"type"` field may be either a plain string
  (`"string"`) or an array of strings (`["string","null"]`) per the JSON Schema
  spec. The MCP adapter now handles both via a new `FlexType` unmarshaler.
  Previously, Smithery-hosted tools such as `googlesheets` caused a hard parse
  error (`cannot unmarshal array into Go struct field … of type string`), silently
  skipping the tool in the directory pipeline.

---

## [0.1.12] - 2026-03-20

### Fixed
- **AS-010**: Removed bare `"pass"` from the secret-param pattern list. It matched
  `passenger`, `bypass`, `passthrough`, `pass_count`, `compass`, producing false
  positives on common non-secret parameters. Replaced with `"passphrase"`.
- **AS-001**: Tightened `system:` regex from `(?i)system\s*:` to `(?im)^\s*system\s*:`
  so it only matches at the start of a line. Prose like
  "Monitors system: CPU, RAM, disk" no longer triggers a finding.
- **AS-001**: The bare `exfiltrate` pattern now requires a direct object
  (`data`, `info`, `credentials`, `secrets`, `content`, or `results`) within two words,
  preventing false positives on defensive security tools that mention "exfiltration".

### Added
- Regression tests for all three false-positive fixes above.

---

## [0.1.11] - 2026-03-19

### Added
- **AS-009 Typosquatting checker**: detects tool names that closely resemble known
  legitimate tools using edit-distance heuristics.
- **AS-013 Tool Shadowing checker**: flags tools whose names or descriptions appear
  designed to shadow or override higher-priority tools in an agent's tool list.
- **AS-006**: Catch additional false negatives — `run-code` and `run_shortcut` patterns
  now detected.
- ToolTrust shield + Celtic knot logo SVG (`docs/logo.svg`) matching the site's
  emerald color scheme (`#10B981`).

### Fixed
- **AS-006**: Added word boundaries to backtick shell-execution pattern to prevent
  substring false positives.
- **AS-006**: Removed false positive on "execute arbitrary query/request/operation"
  phrasing used in legitimate database/API tools.

---

## [0.1.10] - 2026-03-18

### Added
- Regression tests for AS-006 real-production false positives.

---

## [0.1.9] - 2026-03-17

### Fixed
- **AS-006**: Additional false positive removed — "execute arbitrary query/request/operation".
- **AS-006**: Word-boundary fix for backtick shell pattern.

---

## [0.1.8] - 2026-03-16

### Fixed
- **AS-006**: Removed false positive on "execute arbitrary query/request/operation".

---

## [0.1.7] - 2026-03-15

### Added
- **AS-001**: Phase 1 false-positive reduction — confidence tiers and tool-name
  allowlist. Data-movement tools (email, reply, forward, …) no longer trigger
  broad exfiltration patterns. Patterns downgraded to Medium severity.

### Fixed
- **AS-001**: Tightened data-exfiltration regex to require an explicit external-
  destination indicator (`https://`, `external`, `remote`, `attacker`, `base64`).

---

## [0.1.6] - 2026-03-14

### Added
- Per-grade action guide printed below scan results in the CLI.
- Actionable issue hints per rule ID (`ruleHint` map in CLI).
- GitHub Actions workflow to auto-update the Homebrew formula on release.

### Fixed
- **AS-002** and **AS-006** recommendation text made actionable with specific
  guidance (enum validation, `approval_required: true`).
- Added `tooltrust-mcp` binary to `.gitignore`.

### Changed
- `--help` output slimmed down; `-r`/`--rules` flag added for full rule catalog.
- `-v` flag added for version output.

---

## [0.1.5] and earlier

Initial releases establishing the core scanning engine with rules AS-001 through
AS-011. See git log for full history.
