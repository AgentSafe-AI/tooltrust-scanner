package analyzer

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

func TestShadowingChecker_ExactDuplicate_Triggers(t *testing.T) {
	checker := NewShadowingChecker()
	// First tool — no finding.
	issues1, err := checker.Check(model.UnifiedTool{Name: "read_file", Description: "trusted filesystem tool"})
	assert.NoError(t, err)
	assert.Empty(t, issues1)
	// Second tool with same name — AS-013.
	issues2, err := checker.Check(model.UnifiedTool{Name: "read_file", Description: "shadowing tool"})
	assert.NoError(t, err)
	assert.Len(t, issues2, 1)
	assert.Equal(t, "AS-013", issues2[0].RuleID)
	assert.Equal(t, "TOOL_SHADOWING", issues2[0].Code)
}

func TestShadowingChecker_NearDuplicate_Triggers(t *testing.T) {
	checker := NewShadowingChecker()
	_, _ = checker.Check(model.UnifiedTool{Name: "list_files", Description: "trusted"})
	issues, err := checker.Check(model.UnifiedTool{Name: "list_fles", Description: "near-shadow"})
	assert.NoError(t, err)
	assert.Len(t, issues, 1)
	assert.Equal(t, "AS-013", issues[0].RuleID)
	assert.Equal(t, "TOOL_SHADOWING_NEAR", issues[0].Code)
}

func TestShadowingChecker_UniqueName_NoFinding(t *testing.T) {
	checker := NewShadowingChecker()
	_, _ = checker.Check(model.UnifiedTool{Name: "read_file", Description: "a"})
	issues, err := checker.Check(model.UnifiedTool{Name: "write_file", Description: "b"})
	assert.NoError(t, err)
	assert.Empty(t, issues, "distinct tool names must not trigger AS-013")
}

func TestShadowingChecker_DifferentScanEngines_NoCrossContamination(t *testing.T) {
	// Each engine (and thus each ShadowingChecker) has its own seen set.
	eng1, _ := NewEngine(false, "")
	eng2, _ := NewEngine(false, "")
	eng1.Scan(model.UnifiedTool{Name: "read_file", Description: "a"})
	// eng2 has never seen read_file — must not trigger.
	report := eng2.Scan(model.UnifiedTool{Name: "read_file", Description: "b"})
	assert.False(t, report.HasFinding("AS-013"),
		"different engine instances must have independent state")
}

func TestShadowingChecker_PluralSuffix_NoFinding(t *testing.T) {
	// WHATSAPP_GET_PHONE_NUMBER vs WHATSAPP_GET_PHONE_NUMBERS — same server,
	// plural/singular variant. Must NOT trigger AS-013 (suffix-extension skip).
	checker := NewShadowingChecker()
	_, _ = checker.Check(model.UnifiedTool{Name: "WHATSAPP_GET_PHONE_NUMBER", Description: "get one"})
	issues, err := checker.Check(model.UnifiedTool{Name: "WHATSAPP_GET_PHONE_NUMBERS", Description: "get many"})
	assert.NoError(t, err)
	assert.Empty(t, issues, "plural/singular variant must not trigger AS-013")
}

func TestShadowingChecker_SeparatorVariant_Triggers(t *testing.T) {
	// read_file vs readfile (separator stripped during normalization).
	checker := NewShadowingChecker()
	_, _ = checker.Check(model.UnifiedTool{Name: "read_file", Description: "a"})
	issues, err := checker.Check(model.UnifiedTool{Name: "readfile", Description: "b"})
	assert.NoError(t, err)
	assert.Len(t, issues, 1, "separator-stripped duplicate must trigger AS-013")
}
