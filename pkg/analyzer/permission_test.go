package analyzer_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/AgentSafe-AI/tooltrust-scanner/internal/jsonschema"
	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/analyzer"
	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

func TestPermissionChecker_NoPermissions(t *testing.T) {
	tool := model.UnifiedTool{
		Name:        "greet",
		Description: "Say hello to the user.",
		Permissions: nil,
	}
	checker := analyzer.NewPermissionChecker()
	issues, err := checker.Check(tool)
	require.NoError(t, err)
	assert.Empty(t, issues)
}

func TestPermissionChecker_ExecNetworkFS_SingleCapabilitySummary(t *testing.T) {
	// exec + network + fs → exactly ONE AS-002 CAPABILITY_SURFACE at Info (weight 0).
	// Capabilities must be listed in disclosedPermOrder order: exec, network, fs.
	tool := model.UnifiedTool{
		Name:        "run_script",
		Description: "Runs an arbitrary script with network and file access.",
		Permissions: []model.Permission{
			model.PermissionExec,
			model.PermissionNetwork,
			model.PermissionFS,
		},
	}
	issues, err := analyzer.NewPermissionChecker().Check(tool)
	require.NoError(t, err)
	require.Len(t, issues, 1, "expected exactly one CAPABILITY_SURFACE issue")

	iss := issues[0]
	assert.Equal(t, "AS-002", iss.RuleID)
	assert.Equal(t, model.SeverityInfo, iss.Severity)
	assert.Equal(t, "CAPABILITY_SURFACE", iss.Code)
	assert.Contains(t, iss.Description, "code/command execution")
	assert.Contains(t, iss.Description, "network access")
	assert.Contains(t, iss.Description, "filesystem access")

	// Verify order: exec appears before network, network before filesystem.
	execIdx := strings.Index(iss.Description, "code/command execution")
	netIdx := strings.Index(iss.Description, "network access")
	fsIdx := strings.Index(iss.Description, "filesystem access")
	assert.Less(t, execIdx, netIdx, "exec must appear before network in capability list")
	assert.Less(t, netIdx, fsIdx, "network must appear before filesystem in capability list")

	// Evidence uses Kind="capability" with raw permission values.
	require.Len(t, iss.Evidence, 3)
	assert.Equal(t, "capability", iss.Evidence[0].Kind)
	assert.Equal(t, "exec", iss.Evidence[0].Value)
	assert.Equal(t, "capability", iss.Evidence[1].Kind)
	assert.Equal(t, "network", iss.Evidence[1].Value)
	assert.Equal(t, "capability", iss.Evidence[2].Kind)
	assert.Equal(t, "fs", iss.Evidence[2].Value)
}

func TestPermissionChecker_SingleNetworkPermission_InfoSummary(t *testing.T) {
	// Network-only → one Info CAPABILITY_SURFACE issue mentioning "network access".
	tool := model.UnifiedTool{
		Name:        "http_client",
		Description: "Makes HTTP requests.",
		Permissions: []model.Permission{model.PermissionNetwork},
	}
	issues, err := analyzer.NewPermissionChecker().Check(tool)
	require.NoError(t, err)
	require.Len(t, issues, 1)
	assert.Equal(t, "AS-002", issues[0].RuleID)
	assert.Equal(t, model.SeverityInfo, issues[0].Severity)
	assert.Equal(t, "CAPABILITY_SURFACE", issues[0].Code)
	assert.Contains(t, issues[0].Description, "network access")
	require.Len(t, issues[0].Evidence, 1)
	assert.Equal(t, "capability", issues[0].Evidence[0].Kind)
	assert.Equal(t, "network", issues[0].Evidence[0].Value)
}

func TestPermissionChecker_NoRiskyPermissions_SmallSchema_ZeroIssues(t *testing.T) {
	// No permissions, small schema → zero AS-002 issues.
	tool := model.UnifiedTool{
		Name:        "greet",
		Description: "Says hello to the user.",
		Permissions: nil,
		InputSchema: jsonschema.Schema{
			Properties: map[string]jsonschema.Property{
				"name": {Type: "string"},
			},
		},
	}
	issues, err := analyzer.NewPermissionChecker().Check(tool)
	require.NoError(t, err)
	assert.Empty(t, issues)
}

func TestPermissionChecker_SchemaPropCountNote(t *testing.T) {
	// More than largeSchemaPropThreshold properties → LARGE_INPUT_SURFACE Low issue.
	// Also has a network permission, so both CAPABILITY_SURFACE (Info) and
	// LARGE_INPUT_SURFACE (Low) are emitted.
	props := make(map[string]jsonschema.Property)
	for i := range 15 {
		props[string(rune('a'+i))] = jsonschema.Property{Type: "string"}
	}
	tool := model.UnifiedTool{
		Permissions: []model.Permission{model.PermissionNetwork},
		InputSchema: jsonschema.Schema{Properties: props},
	}
	issues, err := analyzer.NewPermissionChecker().Check(tool)
	require.NoError(t, err)

	var foundCap, foundLarge bool
	for _, iss := range issues {
		switch iss.Code {
		case "CAPABILITY_SURFACE":
			foundCap = true
			assert.Equal(t, model.SeverityInfo, iss.Severity)
		case "LARGE_INPUT_SURFACE":
			foundLarge = true
			assert.Equal(t, model.SeverityLow, iss.Severity)
			require.Len(t, iss.Evidence, 2)
			assert.Equal(t, "schema_property_count", iss.Evidence[0].Kind)
			assert.Equal(t, "15", iss.Evidence[0].Value)
		}
	}
	assert.True(t, foundCap, "expected CAPABILITY_SURFACE issue for network permission")
	assert.True(t, foundLarge, "expected LARGE_INPUT_SURFACE issue for schemas with >10 properties")
}

func TestPermissionChecker_LargeSchemaOnly_NoPermissions(t *testing.T) {
	// No permissions but > threshold properties → only LARGE_INPUT_SURFACE (Low), no CAPABILITY_SURFACE.
	props := make(map[string]jsonschema.Property)
	for i := range 12 {
		props[string(rune('a'+i))] = jsonschema.Property{Type: "string"}
	}
	tool := model.UnifiedTool{
		InputSchema: jsonschema.Schema{Properties: props},
	}
	issues, err := analyzer.NewPermissionChecker().Check(tool)
	require.NoError(t, err)
	require.Len(t, issues, 1)
	assert.Equal(t, "LARGE_INPUT_SURFACE", issues[0].Code)
	assert.Equal(t, model.SeverityLow, issues[0].Severity)
}
