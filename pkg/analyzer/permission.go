package analyzer

import (
	"fmt"
	"strings"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

const largeSchemaPropThreshold = 10

// disclosedPermOrder is the stable order capabilities are listed in the summary.
var disclosedPermOrder = []model.Permission{
	model.PermissionExec,
	model.PermissionNetwork,
	model.PermissionFS,
	model.PermissionDB,
	model.PermissionEnv,
	model.PermissionHTTP,
}

// permissionCapability maps a Permission to a human-readable capability label.
var permissionCapability = map[model.Permission]string{
	model.PermissionExec:    "code/command execution",
	model.PermissionNetwork: "network access",
	model.PermissionFS:      "filesystem access",
	model.PermissionDB:      "database access",
	model.PermissionEnv:     "environment variables",
	model.PermissionHTTP:    "HTTP requests",
}

// PermissionChecker analyses the declared permissions of a tool.
type PermissionChecker struct{}

func (c *PermissionChecker) Meta() RuleMeta {
	return RuleMeta{
		ID:          "AS-002",
		Title:       "Permission & Capability Surface",
		Description: "Discloses the capabilities a tool declares (network, filesystem, code execution, …). Permission-vs-purpose mismatches are scored separately by AS-003.",
	}
}

// NewPermissionChecker returns a new PermissionChecker.
func NewPermissionChecker() *PermissionChecker { return &PermissionChecker{} }

// Check produces a single Info capability-disclosure summary (CAPABILITY_SURFACE) when
// the tool declares any known permissions, and a Low finding for over-broad input schemas.
func (c *PermissionChecker) Check(tool model.UnifiedTool) ([]model.Issue, error) {
	var issues []model.Issue

	var caps []string
	var evidence []model.Evidence
	for _, perm := range disclosedPermOrder {
		if !tool.HasPermission(perm) {
			continue
		}
		if label, ok := permissionCapability[perm]; ok {
			caps = append(caps, label)
			evidence = append(evidence, model.Evidence{Kind: "capability", Value: string(perm)})
		}
	}
	if len(caps) > 0 {
		issues = append(issues, model.Issue{
			RuleID:      "AS-002",
			ToolName:    tool.Name,
			Severity:    model.SeverityInfo,
			Code:        "CAPABILITY_SURFACE",
			Description: fmt.Sprintf("declared capabilities: %s", strings.Join(caps, ", ")),
			Location:    "permissions",
			Evidence:    evidence,
		})
	}

	if propCount := len(tool.InputSchema.Properties); propCount > largeSchemaPropThreshold {
		issues = append(issues, model.Issue{
			RuleID:      "AS-002",
			ToolName:    tool.Name,
			Severity:    model.SeverityLow,
			Code:        "LARGE_INPUT_SURFACE",
			Description: fmt.Sprintf("input schema exposes %d properties (threshold: %d)", propCount, largeSchemaPropThreshold),
			Location:    "inputSchema",
			Evidence: []model.Evidence{
				{Kind: "schema_property_count", Value: fmt.Sprintf("%d", propCount)},
				{Kind: "schema_property_threshold", Value: fmt.Sprintf("%d", largeSchemaPropThreshold)},
			},
		})
	}

	return issues, nil
}
