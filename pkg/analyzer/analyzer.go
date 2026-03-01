// Package analyzer provides the scanning engine that runs a set of checkers
// over a UnifiedTool and produces a RiskScore.
package analyzer

import (
	"context"
	"fmt"

	"github.com/AgentSafe-AI/agentsafe/pkg/model"
)

// severityWeight maps a Severity to its numeric risk contribution.
var severityWeight = map[model.Severity]int{
	model.SeverityCritical: 40,
	model.SeverityHigh:     20,
	model.SeverityMedium:   10,
	model.SeverityLow:      5,
	model.SeverityInfo:     1,
}

// checker is an internal interface for a single analysis pass.
type checker interface {
	Check(tool model.UnifiedTool) ([]model.Issue, error)
}

// Scanner orchestrates all registered checkers and aggregates their output
// into a single RiskScore.
type Scanner struct {
	checkers []checker
}

// NewScanner returns a Scanner wired with all default checkers.
func NewScanner() *Scanner {
	return &Scanner{
		checkers: []checker{
			NewPoisoningChecker(),
			NewPermissionChecker(),
			NewScopeChecker(),
		},
	}
}

// Scan runs all checkers against the tool and returns the aggregated RiskScore.
// It respects ctx cancellation.
func (s *Scanner) Scan(ctx context.Context, tool model.UnifiedTool) (model.RiskScore, error) {
	if err := ctx.Err(); err != nil {
		return model.RiskScore{}, fmt.Errorf("analyzer: context cancelled before scan: %w", err)
	}

	var allIssues []model.Issue
	totalScore := 0

	for _, c := range s.checkers {
		if err := ctx.Err(); err != nil {
			return model.RiskScore{}, fmt.Errorf("analyzer: context cancelled during scan: %w", err)
		}
		issues, err := c.Check(tool)
		if err != nil {
			return model.RiskScore{}, fmt.Errorf("analyzer: checker failed: %w", err)
		}
		allIssues = append(allIssues, issues...)
	}

	for _, issue := range allIssues {
		totalScore += severityWeight[issue.Severity]
	}

	return model.NewRiskScore(totalScore, allIssues), nil
}
