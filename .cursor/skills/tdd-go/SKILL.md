---
name: tdd-go
description: Enforces TDD red-green-refactor cycle for Go development in ToolTrust Scanner. Use when implementing any new feature, package, or function. Applies to all Go files in this project — always write the failing test first, then minimal implementation, then refactor.
---

# TDD for ToolTrust Scanner (Go)

## The Cycle

Every feature follows this order — no exceptions:

1. **RED** — Write a failing `_test.go` file that defines the contract
2. **GREEN** — Write the minimal code to make it pass (ugly is fine)
3. **REFACTOR** — Clean up; tests must still pass after

## File Layout

Test files live next to the implementation:

```
pkg/analyzer/
├── poisoning.go
└── poisoning_test.go   ← same package (white-box) or _test suffix (black-box)
```

Use the same package name for white-box tests, `package foo_test` for black-box.

## Test Structure

Always use table-driven tests:

```go
func TestGradeFromScore(t *testing.T) {
    cases := []struct {
        name  string
        score int
        want  Grade
    }{
        {"grade A lower bound", 0, GradeA},
        {"grade A upper bound", 10, GradeA},
        {"grade B lower bound", 11, GradeB},
        {"grade F threshold", 76, GradeF},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            got := GradeFromScore(tc.score)
            assert.Equal(t, tc.want, got)
        })
    }
}
```

## Mocking Pattern

Inject all dependencies via interfaces. Never instantiate real I/O in unit tests.

```go
// production code — define the interface in the consuming package
type Scanner interface {
    Scan(ctx context.Context, tool model.UnifiedTool) (model.RiskScore, error)
}

// test file — hand-written fake (preferred for simple cases)
type fakeScanner struct {
    score model.RiskScore
    err   error
}
func (f *fakeScanner) Scan(_ context.Context, _ model.UnifiedTool) (model.RiskScore, error) {
    return f.score, f.err
}

// or testify/mock for complex interaction verification
type mockScanner struct{ mock.Mock }
func (m *mockScanner) Scan(ctx context.Context, t model.UnifiedTool) (model.RiskScore, error) {
    args := m.Called(ctx, t)
    return args.Get(0).(model.RiskScore), args.Error(1)
}
```

## Running Tests

```bash
# All tests, race detector, no cache
go test -race -count=1 ./...

# Single package
go test -race -count=1 ./pkg/analyzer/...

# Verbose with test names
go test -v -race -count=1 ./...

# via Makefile (required before every commit)
make test
```

## Rules

- Tests must run in **milliseconds** — no sleeps, no real network, no real filesystem
- All external dependencies must be behind an interface
- A commit is only valid when `make test` exits 0
- RED phase: run `go test` and confirm it **fails** before writing implementation
- GREEN phase: write the **simplest** code that passes — resist over-engineering
- REFACTOR phase: improve readability, naming, structure; verify `make test` still passes
