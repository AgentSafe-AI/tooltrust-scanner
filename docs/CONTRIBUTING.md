# Contributing to ToolTrust Scanner

Thank you for your interest in contributing. This page covers local setup, branch / PR flow, and the checks we expect before review.

## Prerequisites

- Go 1.26+
- `golangci-lint` v2 — `brew install golangci-lint` or see [golangci-lint docs](https://golangci-lint.run/usage/install/)
- Git

## Development setup

```bash
git clone https://github.com/AgentSafe-AI/tooltrust-scanner.git
cd tooltrust-scanner
go mod download
make test
make lint
```

## Workflow

1. **Fork** the repo and create a branch from `main`.
2. **Make changes** — follow the [TDD workflow](../.cursor/skills/tdd-go/SKILL.md): write failing tests first, then implement, then refactor.
3. **Run checks** — `make test` and `make lint` must pass before committing.
4. **Commit** — use conventional commits: `feat:`, `fix:`, `docs:`, `chore:`.
5. **Open a PR** — target `main` and describe your change. Link any related issues.

### Fork PRs and GitHub Actions

Pull requests from forks may show **“Workflow runs waiting for approval”** on the base repo until a maintainer approves them. That is a GitHub security setting, not a code failure. After approval, CI runs the same jobs as for branches on the upstream repo.

### Reproduce CI locally (Linux)

To approximate Ubuntu CI without pushing (requires Docker):

```bash
git archive --format=tar HEAD > /tmp/src.tar
docker run --rm -v /tmp/src.tar:/tmp/src.tar:ro golang:1.26-bookworm \
  bash -c 'mkdir -p /src && tar -xf /tmp/src.tar -C /src && bash /src/scripts/verify-ci-parity.sh'
docker run --rm --entrypoint bash -v /tmp/src.tar:/tmp/src.tar:ro golangci/golangci-lint:v2.10.1 \
  -c 'mkdir -p /src && tar -xf /tmp/src.tar -C /src && cd /src && golangci-lint run --timeout=5m'
```

## Before opening a PR

- Make sure tests cover the change.
- Update user-facing docs if behavior or output changed.
- Keep PRs scoped: one feature or one fix is much easier to review than a mixed batch.

## Deeper implementation guides

- Adding a new scan rule: [Developer guide](./DEVELOPER.md#adding-a-new-scan-rule)
- Adding a new protocol adapter: [Developer guide](./DEVELOPER.md#adding-a-new-protocol-adapter)
- CLI, MCP, gate, and CI examples: [Usage guide](./USAGE.md)

## Code style

- Format: `make fmt` (runs `go fmt`)
- Lint: `make lint` — must pass with zero issues
- Tests: `make test` — race detector enabled; all tests must pass

## Questions

- **Bug reports** — use [GitHub Issues](https://github.com/AgentSafe-AI/tooltrust-scanner/issues).
- **Feature requests** — open an issue with the `enhancement` label.
- **Security** — see [Security policy](./SECURITY.md).

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
