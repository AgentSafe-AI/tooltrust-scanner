package analyzer_test

import (
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

func TestPermissionChecker_ExecPermission_MediumRisk(t *testing.T) {
	// exec was High; now Medium — genuinely risky but over-inferred at High.
	tool := model.UnifiedTool{
		Name:        "run_script",
		Description: "Runs an arbitrary script.",
		Permissions: []model.Permission{model.PermissionExec},
	}
	issues, err := analyzer.NewPermissionChecker().Check(tool)
	require.NoError(t, err)
	require.NotEmpty(t, issues)
	assert.Equal(t, "HIGH_RISK_PERMISSION", issues[0].Code)
	assert.Equal(t, model.SeverityMedium, issues[0].Severity)
	require.Len(t, issues[0].Evidence, 1)
	assert.Equal(t, "permission", issues[0].Evidence[0].Kind)
	assert.Equal(t, "exec", issues[0].Evidence[0].Value)
}

func TestPermissionChecker_DBPermission_LowRisk(t *testing.T) {
	// DB was Medium; now Low — unusual but not high-confidence enough for Medium.
	tool := model.UnifiedTool{
		Name:        "query",
		Permissions: []model.Permission{model.PermissionDB},
	}
	issues, err := analyzer.NewPermissionChecker().Check(tool)
	require.NoError(t, err)
	require.NotEmpty(t, issues)
	assert.Equal(t, model.SeverityLow, issues[0].Severity)
}

func TestPermissionChecker_NetworkPermission_Info(t *testing.T) {
	// network was High; now Info — ubiquitous and expected for most tools.
	// The issue is still emitted (Code=HIGH_RISK_PERMISSION) for transparency
	// but carries zero weight in the composite score.
	tool := model.UnifiedTool{
		Name:        "http_client",
		Description: "Makes HTTP requests.",
		Permissions: []model.Permission{model.PermissionNetwork},
	}
	issues, err := analyzer.NewPermissionChecker().Check(tool)
	require.NoError(t, err)
	require.Len(t, issues, 1)
	assert.Equal(t, "HIGH_RISK_PERMISSION", issues[0].Code)
	assert.Equal(t, model.SeverityInfo, issues[0].Severity)
	require.Len(t, issues[0].Evidence, 1)
	assert.Equal(t, "permission", issues[0].Evidence[0].Kind)
	assert.Equal(t, "network", issues[0].Evidence[0].Value)
}

func TestPermissionChecker_MultiplePermissions_NewSeverities(t *testing.T) {
	// exec→Medium(8) + network→Info(0): two issues emitted, new severities.
	tool := model.UnifiedTool{
		Permissions: []model.Permission{model.PermissionExec, model.PermissionNetwork},
	}
	issues, err := analyzer.NewPermissionChecker().Check(tool)
	require.NoError(t, err)
	assert.Len(t, issues, 2)
	// Find each by evidence value
	sevByPerm := map[string]model.Severity{}
	for _, iss := range issues {
		require.Len(t, iss.Evidence, 1)
		sevByPerm[iss.Evidence[0].Value] = iss.Severity
	}
	assert.Equal(t, model.SeverityMedium, sevByPerm["exec"], "exec should now be Medium")
	assert.Equal(t, model.SeverityInfo, sevByPerm["network"], "network should now be Info")
}

func TestPermissionChecker_SchemaPropCountNote(t *testing.T) {
	props := make(map[string]jsonschema.Property)
	for i := range 15 {
		props[string(rune('a'+i))] = jsonschema.Property{Type: "string"}
	}
	tool := model.UnifiedTool{
		InputSchema: jsonschema.Schema{Properties: props},
	}
	issues, err := analyzer.NewPermissionChecker().Check(tool)
	require.NoError(t, err)
	var found bool
	for _, iss := range issues {
		if iss.Code == "LARGE_INPUT_SURFACE" {
			found = true
			require.Len(t, iss.Evidence, 2)
			assert.Equal(t, "schema_property_count", iss.Evidence[0].Kind)
			assert.Equal(t, "15", iss.Evidence[0].Value)
		}
	}
	assert.True(t, found, "expected LARGE_INPUT_SURFACE issue for schemas with >10 properties")
}
