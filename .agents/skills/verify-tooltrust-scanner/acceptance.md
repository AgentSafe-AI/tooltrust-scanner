# Acceptance before expanding scanner coverage

Baseline success is not a claim that future features are implemented or all defects are absent. Keep each acceptance condition tied to observable CLI/MCP evidence. Do not weaken an assertion solely to make new code pass.

## Executable gap probes

Run `verify.py drive --run "$TT_VERIFY_RUN" --feature gaps`. Each condition must PASS after its corresponding feature is implemented. FAIL is an actual unresolved requirement, and the command exits nonzero if any remain.

1. **Rust presence:** handwritten `tools/list` handler is recognized. The driver also checks rmcp ServerHandler, client-only code, comments, and raw-string negatives. Recognition alone does not prove schema extraction.
2. **Pagination:** first page is harmless, second page contains prompt injection/code execution. Both names must be scanned; requests must follow `nextCursor`.
3. **Empty input:** empty tool manifests must exit nonzero or explicitly indicate empty/incomplete coverage, rather than produce an unqualified clean grade. Additional probes require errors for CLI live, gate dry-run/force (unchanged config), MCP JSON/live, and MCP config aggregation. The manifest probe recognizes `scan_incomplete` or `coverage.status`; if a different documented output contract is introduced, update the probe and verify its semantics.

## Required additional cases, not yet automated

Before claiming the corresponding improvement complete, extend the driver and map:

- **Rust full schema:** preserve all 10 Hyperconsciousness tool names and nested schemas resolved from `Context::schema()` / `Change::schema()` at a pinned fixture revision, with provenance. No private store or real keys. Include unsupported/dynamic cases that must fail explicitly rather than synthesize empty schemas.
- **Coverage/provenance:** full vs partial vs unsupported discovery; known count mismatch; source commit/manifest hash mismatch; source/runtime name mismatch; stale report handling; scanner version. Verify the public report, not an internal flag. Directory-specific publication must be tested in that separate repository.
- **Dependency inventory:** Cargo.lock, pinned Python lockfiles and workspace npm lockfiles; exact versions, transitive dependencies, unreadable/absent files, network failure and unknown inventory. Do not equate failed lookups with zero vulnerabilities. Use an explicitly configured local HTTP fixture only if the production client supports that boundary; online checks are separate and timestamped.
- **Transport:** HTTP/streamable HTTP initialization, auth-required discovery, cursor cycles, empty intermediate page, next-page error, timeout and cancellation; enumerate all tools across every supported entry point.
- **Rule semantics:** positive and negative cases per modified rule, including declared-vs-implemented timeout language and advisory match-vs-reachability wording. Baseline code-execution fixture does not cover all shell phrasing; the phrase "Execute arbitrary shell commands" did not trigger AS-006 in the initial baseline attempt and should receive its own desired-behavior decision/test.
- **Other paths:** MCP config scan/self-skip/errors, remote directory lookup, optional deep model, interactive gate approval/rejection, real Claude CLI handoff and user config. Never claim these passed based solely on a tool appearing in tools/list.

## Reporting

Report BASELINE PASS/FAIL separately from ACCEPTANCE PASS/FAIL and NOT RUN. Include the tested revision, source hash, exact commands, observed outputs, known limitations and surviving evidence directory. Use `/maintain-verification-skill` to keep the map aligned as features land.
