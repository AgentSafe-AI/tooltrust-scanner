package analyzer

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

//go:embed data/npm_iocs.json
var npmIOCsJSON []byte

type npmIOCEntry struct {
	Ecosystem       string `json:"ecosystem"`
	IOCType         string `json:"ioc_type,omitempty"`
	Name            string `json:"name"`
	Value           string `json:"value,omitempty"`
	Match           string `json:"match,omitempty"`
	Reason          string `json:"reason"`
	Confidence      string `json:"confidence,omitempty"`
	Source          string `json:"source,omitempty"`
	FirstSeen       string `json:"first_seen,omitempty"`
	SuggestedAction string `json:"suggested_action,omitempty"`
}

type npmIOCIndex struct {
	packageNames map[string]npmIOCEntry
	indicators   []npmIOCEntry
}

func buildNPMIOCIndex(data []byte) (npmIOCIndex, error) {
	var entries []npmIOCEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return npmIOCIndex{}, fmt.Errorf("npm_ioc: unmarshal: %w", err)
	}
	idx := npmIOCIndex{
		packageNames: make(map[string]npmIOCEntry, len(entries)),
		indicators:   make([]npmIOCEntry, 0, len(entries)),
	}
	for i := range entries {
		entry := entries[i]
		if !strings.EqualFold(entry.Ecosystem, "npm") {
			continue
		}

		if strings.TrimSpace(entry.IOCType) == "" {
			entry.IOCType = "package_name"
		}
		if strings.TrimSpace(entry.Match) == "" {
			switch entry.IOCType {
			case "package_name", "dependency_name":
				entry.Match = "exact"
			default:
				entry.Match = "contains"
			}
		}
		if strings.TrimSpace(entry.Value) == "" {
			entry.Value = entry.Name
		}

		switch entry.IOCType {
		case "package_name", "dependency_name":
			if strings.TrimSpace(entry.Value) == "" {
				continue
			}
			idx.packageNames[strings.ToLower(entry.Value)] = entry
		case "script_pattern", "domain", "url":
			if strings.TrimSpace(entry.Value) == "" {
				continue
			}
			idx.indicators = append(idx.indicators, entry)
		}
	}
	return idx, nil
}

// NPMIOCChecker flags npm package versions whose published registry metadata
// references known malicious IOC package names. This is intentionally narrower
// than a full tarball signature scan, but it helps catch compromised releases
// even when the top-level package name changes or the IOC appears transitively.
type NPMIOCChecker struct {
	client npmRegistryClient
	index  npmIOCIndex
}

func NewNPMIOCChecker() *NPMIOCChecker {
	idx, err := buildNPMIOCIndex(npmIOCsJSON)
	if err != nil {
		idx = npmIOCIndex{packageNames: map[string]npmIOCEntry{}}
	}
	return &NPMIOCChecker{client: newHTTPNPMRegistryClient(), index: idx}
}

func NewNPMIOCCheckerWithMock(packages map[string]npmVersionResponse, queryErr error) *NPMIOCChecker {
	idx, err := buildNPMIOCIndex(npmIOCsJSON)
	if err != nil {
		idx = npmIOCIndex{packageNames: map[string]npmIOCEntry{}}
	}
	return &NPMIOCChecker{
		client: &mockNPMRegistryClient{packages: packages, err: queryErr},
		index:  idx,
	}
}

func (c *NPMIOCChecker) Meta() RuleMeta {
	return RuleMeta{
		ID:          "AS-016",
		Title:       "Suspicious NPM IOC Dependency",
		Description: "Flags npm dependency versions whose published metadata or install scripts reference known malicious IOC package names, domains, URLs, or script patterns.",
	}
}

func (c *NPMIOCChecker) Check(tool model.UnifiedTool) ([]model.Issue, error) {
	deps, err := collectDependencies(tool)
	if err != nil || len(deps) == 0 {
		return nil, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), npmQueryTimeout)
	defer cancel()

	var issues []model.Issue
	for _, dep := range deps {
		if !strings.EqualFold(dep.Ecosystem, "npm") {
			continue
		}
		meta, err := c.client.FetchVersion(ctx, dep.Name, dep.Version)
		if err != nil {
			continue
		}

		if issue, ok := buildNPMIOCIssue(tool.Name, dep, meta, c.index); ok {
			issues = append(issues, issue)
		}
	}
	return issues, nil
}

func buildNPMIOCIssue(toolName string, dep dependencyEvidence, meta npmVersionResponse, index npmIOCIndex) (model.Issue, bool) {
	type iocHit struct {
		name   string
		source string
		entry  npmIOCEntry
	}

	var hit iocHit
	for name := range meta.Dependencies {
		if entry, ok := index.packageNames[strings.ToLower(name)]; ok {
			hit = iocHit{name: name, source: "dependencies", entry: entry}
			break
		}
	}
	if hit.name == "" {
		for name := range meta.OptionalDependencies {
			if entry, ok := index.packageNames[strings.ToLower(name)]; ok {
				hit = iocHit{name: name, source: "optionalDependencies", entry: entry}
				break
			}
		}
	}
	if hit.name == "" {
		for _, name := range meta.BundleDependencies {
			if entry, ok := index.packageNames[strings.ToLower(name)]; ok {
				hit = iocHit{name: name, source: "bundleDependencies", entry: entry}
				break
			}
		}
	}
	if hit.name == "" {
		for _, name := range meta.BundledDependencies {
			if entry, ok := index.packageNames[strings.ToLower(name)]; ok {
				hit = iocHit{name: name, source: "bundledDependencies", entry: entry}
				break
			}
		}
	}

	if hit.name != "" {
		return model.Issue{
			RuleID:      "AS-016",
			ToolName:    toolName,
			Severity:    model.SeverityCritical,
			Code:        "NPM_IOC_DEPENDENCY",
			Description: fmt.Sprintf("npm package %s@%s references suspicious IOC package %s via %s. This IOC is %s.", dep.Name, dep.Version, hit.name, hit.source, hit.entry.Reason),
			Location:    fmt.Sprintf("dependency:%s@%s", dep.Name, dep.Version),
			Evidence: []model.Evidence{
				{Kind: "package", Value: dep.Name},
				{Kind: "version", Value: dep.Version},
				{Kind: "ecosystem", Value: dep.Ecosystem},
				{Kind: "dependency_source", Value: dep.Source},
				{Kind: "ioc_type", Value: hit.entry.IOCType},
				{Kind: "ioc_value", Value: hit.name},
				{Kind: "ioc_source", Value: hit.source},
				{Kind: "ioc_confidence", Value: hit.entry.Confidence},
			},
		}, true
	}

	for scriptKey, scriptCmd := range meta.Scripts {
		if matched, ok := matchNPMIOCIndicator(scriptCmd, index.indicators); ok {
			return model.Issue{
				RuleID:      "AS-016",
				ToolName:    toolName,
				Severity:    model.SeverityCritical,
				Code:        "NPM_IOC_INDICATOR",
				Description: fmt.Sprintf("npm package %s@%s publishes a %s script containing suspicious IOC %q (%s). This IOC is %s.", dep.Name, dep.Version, scriptKey, matched.Value, matched.IOCType, matched.Reason),
				Location:    fmt.Sprintf("dependency:%s@%s", dep.Name, dep.Version),
				Evidence: []model.Evidence{
					{Kind: "package", Value: dep.Name},
					{Kind: "version", Value: dep.Version},
					{Kind: "ecosystem", Value: dep.Ecosystem},
					{Kind: "dependency_source", Value: dep.Source},
					{Kind: "lifecycle_script", Value: scriptKey},
					{Kind: "ioc_type", Value: matched.IOCType},
					{Kind: "ioc_value", Value: matched.Value},
					{Kind: "ioc_confidence", Value: matched.Confidence},
				},
			}, true
		}
	}

	return model.Issue{}, false
}

func matchNPMIOCIndicator(script string, indicators []npmIOCEntry) (npmIOCEntry, bool) {
	normalizedScript := strings.ToLower(strings.Join(strings.Fields(script), " "))
	for i := range indicators {
		entry := indicators[i]
		value := strings.ToLower(strings.TrimSpace(entry.Value))
		if value == "" {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(entry.Match)) {
		case "exact":
			if normalizedScript == value {
				return entry, true
			}
		default:
			if strings.Contains(normalizedScript, value) {
				return entry, true
			}
		}
	}
	return npmIOCEntry{}, false
}
