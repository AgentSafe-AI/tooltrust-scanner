package analyzer_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/analyzer"
	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

// ---------------------------------------------------------------------------
// Mock OSV client
// ---------------------------------------------------------------------------

// mockOSVClient implements the internal osvClient interface via a test double.
// It is wired in through newSupplyChainCheckerWithClient (unexported helper
// exposed to the _test package via the same package-level test file).
type mockOSVResponse struct {
	vulns []osvVulnFixture
	err   error
}

type osvVulnFixture struct {
	id       string
	summary  string
	severity string // CVSS v3 score string, e.g. "9.8"
}

// We cannot directly use the unexported osvClient interface from the test
// package, so we use the exported Engine.ScanWithSupplyChain helper instead.
// For direct SupplyChainChecker testing we use the exported
// NewSupplyChainCheckerForTest factory defined below.

// ---------------------------------------------------------------------------
// Engine integration — SupplyChainChecker wired via Engine
// ---------------------------------------------------------------------------

func TestEngine_AS004_NoDependencies_NoFinding(t *testing.T) {
	tool := model.UnifiedTool{
		Name:        "simple_tool",
		Description: "Does something safe.",
	}
	eng_8bb451, _ := analyzer.NewEngine(false, "")
	report := eng_8bb451.Scan(tool)
	assert.False(t, report.HasFinding("AS-004"),
		"tool with no metadata should not trigger AS-004")
}

func TestEngine_AS004_EmptyDependencies_NoFinding(t *testing.T) {
	tool := model.UnifiedTool{
		Name:        "safe_tool",
		Description: "No deps.",
		Metadata:    map[string]any{"dependencies": []any{}},
	}
	eng_e7b04a, _ := analyzer.NewEngine(false, "")
	report := eng_e7b04a.Scan(tool)
	assert.False(t, report.HasFinding("AS-004"))
}

// ---------------------------------------------------------------------------
// SupplyChainChecker unit tests with injected mock
// ---------------------------------------------------------------------------

func TestSupplyChainChecker_CVEFound_CriticalScore(t *testing.T) {
	checker := analyzer.NewSupplyChainCheckerWithMock([]analyzer.MockVuln{
		{ID: "CVE-2024-1234", Summary: "Remote code execution", CVSSScore: "9.8"},
	}, nil)

	tool := model.UnifiedTool{
		Name: "vuln_tool",
		Metadata: map[string]any{
			"dependencies": []any{
				map[string]any{"name": "lodash", "version": "4.17.15", "ecosystem": "npm"},
			},
		},
	}
	issues, err := checker.Check(tool)
	require.NoError(t, err)
	require.Len(t, issues, 1)
	assert.Equal(t, "AS-004", issues[0].RuleID)
	assert.Equal(t, "SUPPLY_CHAIN_CVE", issues[0].Code)
	assert.Equal(t, model.SeverityCritical, issues[0].Severity)
	assert.Contains(t, issues[0].Description, "CVE-2024-1234")
	assert.Contains(t, issues[0].Description, "lodash@4.17.15")
}

func TestSupplyChainChecker_CVEFound_HighScore(t *testing.T) {
	checker := analyzer.NewSupplyChainCheckerWithMock([]analyzer.MockVuln{
		{ID: "CVE-2023-5678", Summary: "Privilege escalation", CVSSScore: "7.5"},
	}, nil)

	tool := model.UnifiedTool{
		Name: "tool_with_high_cve",
		Metadata: map[string]any{
			"dependencies": []any{
				map[string]any{"name": "express", "version": "4.18.0", "ecosystem": "npm"},
			},
		},
	}
	issues, err := checker.Check(tool)
	require.NoError(t, err)
	require.Len(t, issues, 1)
	assert.Equal(t, model.SeverityHigh, issues[0].Severity)
}

func TestSupplyChainChecker_NoCVEs_NoIssues(t *testing.T) {
	checker := analyzer.NewSupplyChainCheckerWithMock(nil, nil)

	tool := model.UnifiedTool{
		Name: "clean_tool",
		Metadata: map[string]any{
			"dependencies": []any{
				map[string]any{"name": "axios", "version": "1.6.0", "ecosystem": "npm"},
			},
		},
	}
	issues, err := checker.Check(tool)
	require.NoError(t, err)
	assert.Empty(t, issues)
}

func TestSupplyChainChecker_MultipleDeps_MultipleCVEs(t *testing.T) {
	checker := analyzer.NewSupplyChainCheckerWithMock([]analyzer.MockVuln{
		{ID: "CVE-2024-0001", Summary: "XSS", CVSSScore: "6.1"},
		{ID: "CVE-2024-0002", Summary: "SQL injection", CVSSScore: "9.1"},
	}, nil)

	tool := model.UnifiedTool{
		Name: "multi_dep_tool",
		Metadata: map[string]any{
			"dependencies": []any{
				map[string]any{"name": "jquery", "version": "3.5.0", "ecosystem": "npm"},
				map[string]any{"name": "sequelize", "version": "6.0.0", "ecosystem": "npm"},
			},
		},
	}
	issues, err := checker.Check(tool)
	require.NoError(t, err)
	// 2 vulns × 2 deps = 4 findings (mock returns same vulns for every dep)
	assert.Len(t, issues, 4)
	for _, issue := range issues {
		assert.Equal(t, "AS-004", issue.RuleID)
	}
}

func TestSupplyChainChecker_NetworkError_Skipped(t *testing.T) {
	checker := analyzer.NewSupplyChainCheckerWithMock(nil, assert.AnError)

	tool := model.UnifiedTool{
		Name: "unreachable_tool",
		Metadata: map[string]any{
			"dependencies": []any{
				map[string]any{"name": "somelib", "version": "1.0.0", "ecosystem": "npm"},
			},
		},
	}
	// Network errors are non-fatal: checker returns no issues and no error.
	issues, err := checker.Check(tool)
	assert.NoError(t, err)
	assert.Empty(t, issues)
}

func TestSupplyChainChecker_MaliciousPackage_Critical(t *testing.T) {
	checker := analyzer.NewSupplyChainCheckerWithMock([]analyzer.MockVuln{
		{ID: "MAL-2024-1234", Summary: "Malicious package steals credentials", CVSSScore: "7.5"},
	}, nil)

	tool := model.UnifiedTool{
		Name: "bad_tool",
		Metadata: map[string]any{
			"dependencies": []any{
				map[string]any{"name": "evil-pkg", "version": "1.0.0", "ecosystem": "npm"},
			},
		},
	}
	issues, err := checker.Check(tool)
	require.NoError(t, err)
	require.Len(t, issues, 1)
	assert.Equal(t, "MALICIOUS_PACKAGE", issues[0].Code,
		"MAL-* advisory must produce MALICIOUS_PACKAGE code")
	assert.Equal(t, model.SeverityCritical, issues[0].Severity,
		"MAL-* advisory must always be Critical regardless of CVSS score")
}

func TestSupplyChainChecker_FixVersion_AppendedToDescription(t *testing.T) {
	checker := analyzer.NewSupplyChainCheckerWithMock([]analyzer.MockVuln{
		{ID: "CVE-2024-1234", Summary: "RCE", CVSSScore: "9.8", FixVersion: "4.17.21"},
	}, nil)

	tool := model.UnifiedTool{
		Name: "vuln_tool",
		Metadata: map[string]any{
			"dependencies": []any{
				map[string]any{"name": "lodash", "version": "4.17.15", "ecosystem": "npm"},
			},
		},
	}
	issues, err := checker.Check(tool)
	require.NoError(t, err)
	require.Len(t, issues, 1)
	assert.Contains(t, issues[0].Description, "upgrade to 4.17.21",
		"fix version must appear in description when OSV supplies one")
}

func TestSupplyChainChecker_NoSeverityScore_DefaultsToHigh(t *testing.T) {
	checker := analyzer.NewSupplyChainCheckerWithMock([]analyzer.MockVuln{
		{ID: "CVE-2024-9999", Summary: "Unknown severity", CVSSScore: ""},
	}, nil)

	tool := model.UnifiedTool{
		Name: "unknown_sev_tool",
		Metadata: map[string]any{
			"dependencies": []any{
				map[string]any{"name": "unknown-pkg", "version": "0.1.0", "ecosystem": "npm"},
			},
		},
	}
	issues, err := checker.Check(tool)
	require.NoError(t, err)
	require.Len(t, issues, 1)
	assert.Equal(t, model.SeverityHigh, issues[0].Severity,
		"missing CVSS score should default to HIGH (conservative)")
}

func TestSupplyChainChecker_RepoURLLockfileDependency_IncludesEvidenceSource(t *testing.T) {
	prev := analyzer.LockfileDepsFetcherForTest()
	analyzer.SetLockfileDepsFetcherForTest(func(string) []analyzer.Dependency {
		return []analyzer.Dependency{
			{Name: "axios", Version: "1.14.1", Ecosystem: "npm"},
		}
	})
	t.Cleanup(func() {
		analyzer.SetLockfileDepsFetcherForTest(prev)
	})

	checker := analyzer.NewSupplyChainCheckerWithMock([]analyzer.MockVuln{
		{ID: "MAL-2026-0001", Summary: "Known malicious package", CVSSScore: "9.8"},
	}, nil)

	tool := model.UnifiedTool{
		Name: "repo_tool",
		Metadata: map[string]any{
			"repo_url": "https://github.com/example/repo",
		},
	}
	issues, err := checker.Check(tool)
	require.NoError(t, err)
	require.Len(t, issues, 1)
	assert.Equal(t, "dependency_source", issues[0].Evidence[3].Kind)
	assert.Equal(t, "lockfile", issues[0].Evidence[3].Value)
	assert.Equal(t, "MALICIOUS_PACKAGE", issues[0].Code)
}

// ---------------------------------------------------------------------------
// Lockfile parser unit tests
// ---------------------------------------------------------------------------

func TestParsePackageLockJSON_V2(t *testing.T) {
	data := []byte(`{
  "packages": {
    "": {"version": "1.0.0"},
    "node_modules/lodash": {"version": "4.17.15"},
    "node_modules/express/node_modules/qs": {"version": "6.5.2"}
  }
}`)
	deps, err := analyzer.ParsePackageLockJSONForTest(data)
	require.NoError(t, err)
	assert.Len(t, deps, 2)

	names := make(map[string]string)
	for _, d := range deps {
		names[d.Name] = d.Version
		assert.Equal(t, "npm", d.Ecosystem)
	}
	assert.Equal(t, "4.17.15", names["lodash"])
	assert.Equal(t, "6.5.2", names["qs"])
}

func TestParseGoSum(t *testing.T) {
	data := []byte(`github.com/foo/bar v1.2.3 h1:abc
github.com/foo/bar v1.2.3/go.mod h1:def
github.com/baz/qux v0.1.0+incompatible h1:xyz
`)
	deps, err := analyzer.ParseGoSumForTest(data)
	require.NoError(t, err)
	assert.Len(t, deps, 2)

	names := make(map[string]string)
	for _, d := range deps {
		names[d.Name] = d.Version
		assert.Equal(t, "Go", d.Ecosystem)
	}
	assert.Equal(t, "v1.2.3", names["github.com/foo/bar"])
	assert.Equal(t, "v0.1.0", names["github.com/baz/qux"], "+incompatible must be stripped")
}

func TestParseRequirementsTxt(t *testing.T) {
	data := []byte(`# comment
django==4.2.0
requests>=2.28.0
Flask==2.3.1 ; python_requires >= "3.8"
-r other.txt
`)
	deps, err := analyzer.ParseRequirementsTxtForTest(data)
	require.NoError(t, err)
	assert.Len(t, deps, 2, "only exact == pins and no -r lines")

	names := make(map[string]string)
	for _, d := range deps {
		names[d.Name] = d.Version
		assert.Equal(t, "PyPI", d.Ecosystem)
	}
	assert.Equal(t, "4.2.0", names["django"])
	assert.Equal(t, "2.3.1", names["Flask"])
}

func TestParsePNPMLockYAML(t *testing.T) {
	data := []byte(`
lockfileVersion: '9.0'
packages:
  /axios@1.14.1:
    resolution: {integrity: sha512-abc}
  /@scope/sdk@2.3.4(axios@1.14.1):
    resolution: {integrity: sha512-def}
`)
	deps, err := analyzer.ParsePNPMLockYAMLForTest(data)
	require.NoError(t, err)
	assert.Len(t, deps, 2)

	names := make(map[string]string)
	for _, d := range deps {
		names[d.Name] = d.Version
		assert.Equal(t, "npm", d.Ecosystem)
	}
	assert.Equal(t, "1.14.1", names["axios"])
	assert.Equal(t, "2.3.4", names["@scope/sdk"])
}

func TestParseYarnLock(t *testing.T) {
	data := []byte(`
"axios@^1.14.1":
  version "1.14.1"
  resolved "https://registry.yarnpkg.com/axios/-/axios-1.14.1.tgz"

"@scope/sdk@^2.3.4", "@scope/sdk@~2.3.4":
  version "2.3.4"
`)
	deps, err := analyzer.ParseYarnLockForTest(data)
	require.NoError(t, err)
	assert.Len(t, deps, 2)

	names := make(map[string]string)
	for _, d := range deps {
		names[d.Name] = d.Version
		assert.Equal(t, "npm", d.Ecosystem)
	}
	assert.Equal(t, "1.14.1", names["axios"])
	assert.Equal(t, "2.3.4", names["@scope/sdk"])
}

// ---------------------------------------------------------------------------
// Transitive / source-based severity tests (Change 1)
// ---------------------------------------------------------------------------

func TestSupplyChainChecker_LockfileCVE_Info(t *testing.T) {
	// Lockfile-sourced CVE must be downgraded to Info with code
	// SUPPLY_CHAIN_CVE_TRANSITIVE and a note about unconfirmed reachability.
	prev := analyzer.LockfileDepsFetcherForTest()
	analyzer.SetLockfileDepsFetcherForTest(func(string) []analyzer.Dependency {
		return []analyzer.Dependency{
			{Name: "lodash", Version: "4.17.15", Ecosystem: "npm"},
		}
	})
	t.Cleanup(func() { analyzer.SetLockfileDepsFetcherForTest(prev) })

	checker := analyzer.NewSupplyChainCheckerWithMock([]analyzer.MockVuln{
		{ID: "CVE-2026-5024", Summary: "Prototype pollution", CVSSScore: "9.8"},
	}, nil)

	tool := model.UnifiedTool{
		Name:     "go_tool",
		Metadata: map[string]any{"repo_url": "https://github.com/example/repo"},
	}
	issues, err := checker.Check(tool)
	require.NoError(t, err)
	require.Len(t, issues, 1)
	assert.Equal(t, "SUPPLY_CHAIN_CVE_TRANSITIVE", issues[0].Code,
		"lockfile CVE must use SUPPLY_CHAIN_CVE_TRANSITIVE code")
	assert.Equal(t, model.SeverityInfo, issues[0].Severity,
		"lockfile CVE must be Info to avoid inflating score")
	assert.Contains(t, issues[0].Description, "transitive dependency",
		"description must note transitive dependency")
}

func TestSupplyChainChecker_LockfileMAL_Critical(t *testing.T) {
	// MAL-* from lockfile must stay Critical — malware anywhere in the tree is a
	// true positive regardless of source.
	prev := analyzer.LockfileDepsFetcherForTest()
	analyzer.SetLockfileDepsFetcherForTest(func(string) []analyzer.Dependency {
		return []analyzer.Dependency{
			{Name: "evil-pkg", Version: "1.0.0", Ecosystem: "npm"},
		}
	})
	t.Cleanup(func() { analyzer.SetLockfileDepsFetcherForTest(prev) })

	checker := analyzer.NewSupplyChainCheckerWithMock([]analyzer.MockVuln{
		{ID: "MAL-2026-9999", Summary: "Credential stealer", CVSSScore: "7.0"},
	}, nil)

	tool := model.UnifiedTool{
		Name:     "repo_tool",
		Metadata: map[string]any{"repo_url": "https://github.com/example/repo"},
	}
	issues, err := checker.Check(tool)
	require.NoError(t, err)
	require.Len(t, issues, 1)
	assert.Equal(t, "MALICIOUS_PACKAGE", issues[0].Code,
		"MAL-* from lockfile must still be MALICIOUS_PACKAGE")
	assert.Equal(t, model.SeverityCritical, issues[0].Severity,
		"MAL-* from lockfile must stay Critical")
}

func TestSupplyChainChecker_MetadataCVE_KeepsSeverity(t *testing.T) {
	// Metadata-sourced CVE keeps OSV-derived severity (Critical for CVSS 9.8).
	checker := analyzer.NewSupplyChainCheckerWithMock([]analyzer.MockVuln{
		{ID: "CVE-2024-1111", Summary: "RCE", CVSSScore: "9.8"},
	}, nil)

	tool := model.UnifiedTool{
		Name: "meta_tool",
		Metadata: map[string]any{
			"dependencies": []any{
				map[string]any{"name": "vuln-pkg", "version": "2.0.0", "ecosystem": "npm"},
			},
		},
	}
	issues, err := checker.Check(tool)
	require.NoError(t, err)
	require.Len(t, issues, 1)
	assert.Equal(t, "SUPPLY_CHAIN_CVE", issues[0].Code,
		"metadata CVE must use SUPPLY_CHAIN_CVE code")
	assert.Equal(t, model.SeverityCritical, issues[0].Severity,
		"metadata CVE must keep OSV-derived severity")
}

// ---------------------------------------------------------------------------
// local_lockfile source tests (Change B — AS-004 FP fix 0.3.16)
// ---------------------------------------------------------------------------

func TestSupplyChainChecker_LocalLockfileCVE_Info(t *testing.T) {
	// A metadata dep carrying source:"local_lockfile" with a non-MAL CVE must be
	// downgraded to Info (SUPPLY_CHAIN_CVE_TRANSITIVE), not scored at OSV severity.
	// Before 0.3.16 this produced High/SUPPLY_CHAIN_CVE because the source field was
	// dropped at unmarshal and collectDependencies hardcoded source="metadata".
	checker := analyzer.NewSupplyChainCheckerWithMock([]analyzer.MockVuln{
		{ID: "CVE-2026-5024", Summary: "Memory corruption", CVSSScore: "9.8"},
	}, nil)

	tool := model.UnifiedTool{
		Name: "go_tool",
		Metadata: map[string]any{
			"dependencies": []any{
				map[string]any{
					"name":      "golang.org/x/sys",
					"version":   "v0.28.0",
					"ecosystem": "Go",
					"source":    "local_lockfile",
				},
			},
		},
	}
	issues, err := checker.Check(tool)
	require.NoError(t, err)
	require.Len(t, issues, 1)
	assert.Equal(t, "SUPPLY_CHAIN_CVE_TRANSITIVE", issues[0].Code,
		"local_lockfile CVE must use SUPPLY_CHAIN_CVE_TRANSITIVE code (not SUPPLY_CHAIN_CVE)")
	assert.Equal(t, model.SeverityInfo, issues[0].Severity,
		"local_lockfile CVE must be downgraded to Info (was High before 0.3.16 fix)")
	assert.Contains(t, issues[0].Description, "transitive dependency",
		"description must note unconfirmed reachability")
}

func TestSupplyChainChecker_LocalLockfileMAL_Critical(t *testing.T) {
	// MAL-* from a local_lockfile dep must stay Critical — malicious packages are
	// always true positives regardless of source.
	checker := analyzer.NewSupplyChainCheckerWithMock([]analyzer.MockVuln{
		{ID: "MAL-2026-9999", Summary: "Credential stealer", CVSSScore: "7.0"},
	}, nil)

	tool := model.UnifiedTool{
		Name: "infected_tool",
		Metadata: map[string]any{
			"dependencies": []any{
				map[string]any{
					"name":      "evil-pkg",
					"version":   "1.0.0",
					"ecosystem": "npm",
					"source":    "local_lockfile",
				},
			},
		},
	}
	issues, err := checker.Check(tool)
	require.NoError(t, err)
	require.Len(t, issues, 1)
	assert.Equal(t, "MALICIOUS_PACKAGE", issues[0].Code,
		"MAL-* from local_lockfile must still produce MALICIOUS_PACKAGE code")
	assert.Equal(t, model.SeverityCritical, issues[0].Severity,
		"MAL-* from local_lockfile must remain Critical")
}

func TestSupplyChainChecker_EmptySource_UnchangedBehavior(t *testing.T) {
	// A metadata dep with no source field keeps OSV-derived severity (High for CVSS
	// 7.5). This is a regression guard: the empty-source path must behave as before.
	checker := analyzer.NewSupplyChainCheckerWithMock([]analyzer.MockVuln{
		{ID: "CVE-2024-0001", Summary: "Privilege escalation", CVSSScore: "7.5"},
	}, nil)

	tool := model.UnifiedTool{
		Name: "normal_tool",
		Metadata: map[string]any{
			"dependencies": []any{
				// No "source" key — simulates deps declared before 0.3.16.
				map[string]any{"name": "express", "version": "4.18.0", "ecosystem": "npm"},
			},
		},
	}
	issues, err := checker.Check(tool)
	require.NoError(t, err)
	require.Len(t, issues, 1)
	assert.Equal(t, "SUPPLY_CHAIN_CVE", issues[0].Code,
		"dep with no source must default to metadata treatment (SUPPLY_CHAIN_CVE)")
	assert.Equal(t, model.SeverityHigh, issues[0].Severity,
		"dep with no source must keep OSV-derived severity (unchanged behavior)")
}
