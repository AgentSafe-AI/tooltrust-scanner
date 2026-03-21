package analyzer

import (
	"fmt"
	"strings"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

// ShadowingChecker detects tool name collisions within a multi-server tool set.
// When a user provides tools from multiple MCP servers (e.g. via --input with
// a merged manifest), two tools with identical or near-identical names create
// an ambiguity that an attacker can exploit: a malicious server registers
// "read_file" to intercept calls intended for the trusted filesystem server.
//
// AS-013 fires when a tool name is an exact duplicate of another tool already
// seen in the same scan pass.  Near-duplicate detection (edit distance 1) is
// also applied to catch slight variations used to shadow without an exact clash.
//
// The checker is stateful: it accumulates seen tool names across successive
// Check() calls so that the engine can stream tools one at a time.
type ShadowingChecker struct {
	// seen maps normalized tool names → first tool name seen with that norm form.
	seen map[string]string
}

// NewShadowingChecker returns a fresh ShadowingChecker with an empty seen set.
func NewShadowingChecker() *ShadowingChecker {
	return &ShadowingChecker{seen: make(map[string]string)}
}

// Check produces an AS-013 finding when tool.Name duplicates or near-duplicates
// a previously seen tool name in the current scan session.
func (c *ShadowingChecker) Check(tool model.UnifiedTool) ([]model.Issue, error) {
	name := strings.TrimSpace(tool.Name)
	if name == "" {
		return nil, nil
	}
	norm := normalizeToolName(name) // reuse from typosquatting.go

	// Exact duplicate check.
	if first, ok := c.seen[norm]; ok {
		return []model.Issue{{
			RuleID:   "AS-013",
			ToolName: tool.Name,
			Severity: model.SeverityHigh,
			Code:     "TOOL_SHADOWING",
			Description: fmt.Sprintf(
				"tool name %q duplicates (or near-duplicates) %q already registered in this tool set — "+
					"a malicious server can shadow a trusted tool by registering an identical name",
				tool.Name, first,
			),
			Location: "name",
		}}, nil
	}

	// Near-duplicate check (edit distance 1 on normalised names, min len 5).
	// Skip when one name is a pure suffix extension of the other (e.g. plural
	// +S or +ES): "whatsappgetphonenumbers" vs "whatsappgetphonenumber" — these
	// are intentional plural/singular variants within the same server, not a
	// shadowing attack. Real shadowing uses substitutions mid-name, not appends.
	if len(norm) >= 5 {
		for seenNorm, seenName := range c.seen {
			if len(seenNorm) < 5 {
				continue
			}
			diff := len(norm) - len(seenNorm)
			if diff < 0 {
				diff = -diff
			}
			if diff > 1 {
				continue
			}
			if levenshtein(norm, seenNorm) != 1 {
				continue
			}
			// Skip pure suffix-extension pairs (one is a prefix of the other).
			shorter, longer := norm, seenNorm
			if len(norm) > len(seenNorm) {
				shorter, longer = seenNorm, norm
			}
			if strings.HasPrefix(longer, shorter) {
				// e.g. "getphonenumber" vs "getphonenumbers" — just plural
				c.seen[norm] = name
				continue
			}
			c.seen[norm] = name
			return []model.Issue{{
				RuleID:   "AS-013",
				ToolName: tool.Name,
				Severity: model.SeverityMedium,
				Code:     "TOOL_SHADOWING_NEAR",
				Description: fmt.Sprintf(
					"tool name %q is nearly identical to %q (edit distance 1) — "+
						"could shadow a trusted tool in a multi-server environment",
					tool.Name, seenName,
				),
				Location: "name",
			}}, nil
		}
	}

	c.seen[norm] = name
	return nil, nil
}
