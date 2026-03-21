package analyzer

import (
	"fmt"
	"strings"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

// popularMCPToolNames is a curated list of well-known MCP server tool names.
// A tool name within edit distance ≤ 2 of one of these (but not identical)
// triggers AS-009 (Typosquatting).
//
// Coverage: canonical tools from modelcontextprotocol/servers plus the most
// widely used community MCP servers (filesystem, brave-search, playwright, etc.)
var popularMCPToolNames = []string{
	// Official MCP servers
	"list_files", "list_directory", "read_file", "write_file",
	"create_file", "delete_file", "move_file", "search_files",
	"get_file_info", "list_allowed_directories",
	"brave_web_search", "brave_local_search",
	// GitHub MCP server (github/github-mcp-server + modelcontextprotocol/servers)
	"create_or_edit_file", "push_files", "search_repositories",
	"create_issue", "create_pull_request", "fork_repository",
	"create_repository", "get_file_contents", "get_issue",
	"list_commits", "list_issues",
	"search_code", "search_issues", "search_users",
	"get_pull_request", "list_pull_requests", "merge_pull_request",
	"update_issue", "add_issue_comment", "get_commit",
	"list_branches", "create_branch", "delete_branch",
	"get_repository", "list_tags", "get_tag",
	"fetch", "fetch_url", "get_current_time", "convert_time",
	"sequentialthinking",
	// Playwright / browser tools
	"playwright_navigate", "playwright_click", "playwright_fill",
	"playwright_screenshot", "playwright_evaluate",
	"browser_navigate", "browser_click", "browser_screenshot",
	// Puppeteer
	"puppeteer_navigate", "puppeteer_screenshot", "puppeteer_click",
	"puppeteer_evaluate",
	// Memory / knowledge graph
	"create_entities", "create_relations", "add_observations",
	"search_nodes", "open_nodes", "read_graph",
	// Slack
	"slack_post_message", "slack_get_channels", "slack_get_users",
	// Postgres / SQLite
	"query", "execute_query", "list_tables", "describe_table",
	// Sentry
	"get_sentry_issue", "resolve_sentry_issue",
}

// levenshtein computes the edit distance between two strings.
func levenshtein(a, b string) int {
	la, lb := len(a), len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	// Use two rows to save memory.
	prev := make([]int, lb+1)
	curr := make([]int, lb+1)
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		curr[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			curr[j] = min3(curr[j-1]+1, prev[j]+1, prev[j-1]+cost)
		}
		prev, curr = curr, prev
	}
	return prev[lb]
}

func min3(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}

// normalizeToolName strips common separators for a more intent-focused
// edit-distance comparison (list_files vs listfiles vs list-files all normalize
// to "listfiles" so that separators don't consume edit-distance budget).
func normalizeToolName(name string) string {
	s := strings.ToLower(name)
	s = strings.ReplaceAll(s, "_", "")
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ReplaceAll(s, " ", "")
	return s
}

// TyposquattingChecker detects tool names within edit distance ≤ 2 of a known
// popular MCP tool name — a signal that the tool may be impersonating a trusted
// tool to gain execution in a user's agent environment.
type TyposquattingChecker struct{}

// NewTyposquattingChecker returns a new TyposquattingChecker.
func NewTyposquattingChecker() *TyposquattingChecker { return &TyposquattingChecker{} }

// Check produces an AS-009 finding when tool.Name is suspiciously similar to a
// popular MCP tool name (edit distance 1–2) but is not an exact match.
func (c *TyposquattingChecker) Check(tool model.UnifiedTool) ([]model.Issue, error) {
	name := strings.TrimSpace(tool.Name)
	if len(name) < 4 {
		return nil, nil // too short to be a meaningful typosquat
	}
	normName := normalizeToolName(name)

	// If this name IS a canonical tool, it cannot be a typosquat — bail before
	// the distance loop so we don't accidentally flag it against a different
	// entry that happens to be within edit-distance 2 (e.g. search_code vs
	// search_nodes).
	for _, known := range popularMCPToolNames {
		if normName == normalizeToolName(known) {
			return nil, nil
		}
	}

	for _, known := range popularMCPToolNames {
		normKnown := normalizeToolName(known)
		// Skip if length difference alone exceeds threshold (fast reject).
		diff := len(normName) - len(normKnown)
		if diff < 0 {
			diff = -diff
		}
		if diff > 2 {
			continue
		}
		dist := levenshtein(normName, normKnown)
		if dist >= 1 && dist <= 2 {
			return []model.Issue{{
				RuleID:   "AS-009",
				ToolName: tool.Name,
				Severity: model.SeverityMedium,
				Code:     "TYPOSQUATTING",
				Description: fmt.Sprintf(
					"tool name %q is suspiciously similar to the well-known MCP tool %q (edit distance %d) — possible typosquatting",
					tool.Name, known, dist,
				),
				Location: "name",
			}}, nil
		}
	}
	return nil, nil
}
