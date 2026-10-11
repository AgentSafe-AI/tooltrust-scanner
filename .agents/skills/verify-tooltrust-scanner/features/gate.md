# Scan before adding a server

A user scans a package, previews installation, blocks risky additions, or writes an approved project MCP configuration.

## Sub-features

- `gate-dry`: scans the fixture while keeping existing configuration byte-identical.
- `gate-block`: a strict threshold exits 1 and leaves configuration unchanged.
- `gate-install`: forced project install writes the exact command/args and preserves an existing server.

## How to get to it (user POV)

Run `tooltrust-scanner gate package --dry-run`, `--block-on`, or `--force --scope project`. User scope, real `claude mcp add`, C/D interactive confirmation and real npm downloads are separate paths, NOT RUN by this recipe.

## Driving it with verify.py

Preconditions: launch and doctor pass. The helper's runtime PATH contains only owned binaries and its recording `npx` shim, with no real `claude` executable. The working directory is scratch.

- Run `python3 .agents/skills/verify-tooltrust-scanner/scripts/verify.py drive --run "$TT_VERIFY_RUN" --feature gate`.
- Require dry-run and blocked runs to leave `.mcp.json` unchanged; logs must prove scanning happened.
- Require forced install to add `verified-fixture` with command `npx` and args `[-y, verify-owned-fixture]`, retaining the existing entry.
- Inspect `gate.before.json`, `gate.after.json`, `npx.argv.jsonl`, `gate.requests.jsonl` and command exit codes. No tools/call may occur.

## Gotchas

Dry-run skips installation, not server execution. Do not run this recipe with the user's regular PATH or cwd. The npx shim proves gate behavior at the subprocess boundary; it does not prove npm package fetching or an actual vendor server. Project-config fallback is tested; success does not verify the Claude CLI installation branch or user-level configuration.
