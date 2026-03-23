package analyzer

import (
	"fmt"
	"strings"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

// ShadowingChecker detects exact tool name collisions within a scan session.
// When multiple tools share the same normalized name, a malicious server can
// register an identically-named tool to intercept calls intended for a trusted
// tool — a cross-server shadowing attack.
//
// AS-013 fires only on exact normalized matches.  Near-duplicate detection
// (edit distance 1) was removed because it produces 100% false positives in
// single-server scans: get/set pairs, data-granularity variants (5Min/1Min),
// and indicator variants (EMA/SMA/WMA) all differ by exactly 1 edit and are
// legitimate intra-server API design patterns, not attacks.  Typo-based
// impersonation is handled by AS-009 (Typosquatting), which has a purpose-built
// corpus of known tool names for comparison.
//
// The checker is stateful: it accumulates seen tool names across successive
// Check() calls so that the engine can stream tools one at a time.
type ShadowingChecker struct {
	// seen maps normalized tool names → first tool name seen with that norm form.
	seen map[string]string
}

func (c *ShadowingChecker) Meta() RuleMeta {
	return RuleMeta{
		ID:          "AS-013",
		Title:       "Tool Shadowing",
		Description: "Detects exact tool name collisions within a scan session, where a malicious server registers an identically-named tool to intercept calls intended for a trusted tool.",
	}
}

// NewShadowingChecker returns a fresh ShadowingChecker with an empty seen set.
func NewShadowingChecker() *ShadowingChecker {
	return &ShadowingChecker{seen: make(map[string]string)}
}

// Check produces an AS-013 finding when tool.Name exactly duplicates (after
// normalization) a tool name already seen in the current scan session.
func (c *ShadowingChecker) Check(tool model.UnifiedTool) ([]model.Issue, error) {
	name := strings.TrimSpace(tool.Name)
	if name == "" {
		return nil, nil
	}
	norm := normalizeToolName(name) // reuse from typosquatting.go

	if first, ok := c.seen[norm]; ok {
		return []model.Issue{{
			RuleID:   "AS-013",
			ToolName: tool.Name,
			Severity: model.SeverityHigh,
			Code:     "TOOL_SHADOWING",
			Description: fmt.Sprintf(
				"tool name %q duplicates %q already registered in this tool set — "+
					"a malicious server can shadow a trusted tool by registering an identical name",
				tool.Name, first,
			),
			Location: "name",
		}}, nil
	}

	c.seen[norm] = name
	return nil, nil
}
