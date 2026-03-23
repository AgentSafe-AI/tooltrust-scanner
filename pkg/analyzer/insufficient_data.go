package analyzer

import (
	"fmt"
	"strings"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

// InsufficientDataChecker detects if a tool lacks a description or schema,
// hindering agents from reasoning about its purpose and limiting static
// analysis coverage.
//
// Rule ID: AS-007
// Severity: INFO.
type InsufficientDataChecker struct{}

func (c *InsufficientDataChecker) Meta() RuleMeta {
	return RuleMeta{
		ID:          "AS-007",
		Title:       "Insufficient Tool Data",
		Description: "Reports tools that lack a description or input schema, hindering agent reasoning and limiting static analysis coverage.",
	}
}

func NewInsufficientDataChecker() *InsufficientDataChecker {
	return &InsufficientDataChecker{}
}

func (c *InsufficientDataChecker) Check(tool model.UnifiedTool) ([]model.Issue, error) {
	var issues []model.Issue

	if strings.TrimSpace(tool.Description) == "" {
		issues = append(issues, model.Issue{
			RuleID:      "AS-007",
			ToolName:    tool.Name,
			Severity:    model.SeverityInfo,
			Code:        "INSUFFICIENT_TOOL_DATA",
			Description: fmt.Sprintf("Tool '%s' has no description - agents cannot reason about its purpose, and static analysis coverage is limited", tool.Name),
		})
	}

	return issues, nil
}
