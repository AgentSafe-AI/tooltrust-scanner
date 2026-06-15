package mcp_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/adapter/mcp"
	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/analyzer"
	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

func TestAdapter_Protocol(t *testing.T) {
	a := mcp.NewAdapter()
	assert.Equal(t, model.ProtocolMCP, a.Protocol())
}

func TestAdapter_Parse_BasicTool(t *testing.T) {
	payload := mustMarshal(mcp.ListToolsResponse{
		Tools: []mcp.Tool{
			{
				Name:        "read_file",
				Description: "Read the contents of a file from the filesystem",
				InputSchema: mcp.InputSchema{
					Type: "object",
					Properties: map[string]mcp.SchemaProperty{
						"path": {Type: "string", Description: "absolute file path"},
					},
					Required: []string{"path"},
				},
			},
		},
	})

	a := mcp.NewAdapter()
	tools, err := a.Parse(context.Background(), payload)
	require.NoError(t, err)
	require.Len(t, tools, 1)

	tool := tools[0]
	assert.Equal(t, "read_file", tool.Name)
	assert.Equal(t, model.ProtocolMCP, tool.Protocol)
	assert.True(t, tool.InputSchema.HasProperty("path"))
	assert.Contains(t, tool.Permissions, model.PermissionFS)
}

func TestAdapter_Parse_NetworkTool(t *testing.T) {
	payload := mustMarshal(mcp.ListToolsResponse{
		Tools: []mcp.Tool{
			{
				Name:        "fetch_url",
				Description: "Fetch content from a remote URL over the network",
				InputSchema: mcp.InputSchema{
					Type: "object",
					Properties: map[string]mcp.SchemaProperty{
						"url": {Type: "string"},
					},
				},
			},
		},
	})

	tools, err := mcp.NewAdapter().Parse(context.Background(), payload)
	require.NoError(t, err)
	require.Len(t, tools, 1)
	assert.Contains(t, tools[0].Permissions, model.PermissionNetwork)
}

func TestAdapter_Parse_ExecTool(t *testing.T) {
	payload := mustMarshal(mcp.ListToolsResponse{
		Tools: []mcp.Tool{
			{
				Name:        "run_command",
				Description: "Execute a shell command",
				InputSchema: mcp.InputSchema{
					Type: "object",
					Properties: map[string]mcp.SchemaProperty{
						"command": {Type: "string"},
					},
				},
			},
		},
	})

	tools, err := mcp.NewAdapter().Parse(context.Background(), payload)
	require.NoError(t, err)
	assert.Contains(t, tools[0].Permissions, model.PermissionExec)
}

func TestAdapter_Parse_MultipleTools(t *testing.T) {
	payload := mustMarshal(mcp.ListToolsResponse{
		Tools: []mcp.Tool{
			{Name: "tool_a", Description: "first tool"},
			{Name: "tool_b", Description: "second tool"},
		},
	})

	tools, err := mcp.NewAdapter().Parse(context.Background(), payload)
	require.NoError(t, err)
	assert.Len(t, tools, 2)
}

func TestAdapter_Parse_EmptyList(t *testing.T) {
	payload := mustMarshal(mcp.ListToolsResponse{Tools: []mcp.Tool{}})
	tools, err := mcp.NewAdapter().Parse(context.Background(), payload)
	require.NoError(t, err)
	assert.Empty(t, tools)
}

func TestAdapter_Parse_InvalidJSON(t *testing.T) {
	_, err := mcp.NewAdapter().Parse(context.Background(), []byte("not json"))
	assert.Error(t, err)
}

func TestAdapter_Parse_PreservesRawSource(t *testing.T) {
	payload := mustMarshal(mcp.ListToolsResponse{
		Tools: []mcp.Tool{
			{Name: "some_tool", Description: "desc"},
		},
	})

	tools, err := mcp.NewAdapter().Parse(context.Background(), payload)
	require.NoError(t, err)
	assert.NotEmpty(t, tools[0].RawSource)
}

func TestAdapter_Parse_PopulatesSupplyChainMetadata(t *testing.T) {
	payload := mustMarshal(mcp.ListToolsResponse{
		Tools: []mcp.Tool{
			{
				Name:        "deploy_site",
				Description: "Deploy the site",
				RepoURL:     "https://github.com/example/site",
				Metadata: mcp.ToolMeta{
					Dependencies: []mcp.DependencyMetadata{
						{Name: "axios", Version: "1.14.1", Ecosystem: "npm"},
						{Name: "litellm", Version: "1.82.8", Ecosystem: "PyPI"},
					},
				},
			},
		},
	})

	tools, err := mcp.NewAdapter().Parse(context.Background(), payload)
	require.NoError(t, err)
	require.Len(t, tools, 1)

	meta := tools[0].Metadata
	require.NotNil(t, meta)
	assert.Equal(t, "https://github.com/example/site", meta["repo_url"])

	deps, ok := meta["dependencies"].([]map[string]any)
	require.True(t, ok)
	require.Len(t, deps, 2)
	assert.Equal(t, "axios", deps[0]["name"])
	assert.Equal(t, "1.14.1", deps[0]["version"])
	assert.Equal(t, "npm", deps[0]["ecosystem"])
}

func TestAdapter_Parse_PrefersMetadataRepoURL(t *testing.T) {
	payload := mustMarshal(mcp.ListToolsResponse{
		Tools: []mcp.Tool{
			{
				Name:        "deploy_site",
				Description: "Deploy the site",
				RepoURL:     "https://github.com/example/old",
				Metadata: mcp.ToolMeta{
					RepoURL: "https://github.com/example/new",
				},
			},
		},
	})

	tools, err := mcp.NewAdapter().Parse(context.Background(), payload)
	require.NoError(t, err)
	require.Len(t, tools, 1)
	require.NotNil(t, tools[0].Metadata)
	assert.Equal(t, "https://github.com/example/new", tools[0].Metadata["repo_url"])
}

func TestAdapter_Parse_EngineDetectsBlacklistedDependency(t *testing.T) {
	payload := mustMarshal(mcp.ListToolsResponse{
		Tools: []mcp.Tool{
			{
				Name:        "deploy_site",
				Description: "Deploy the site",
				Metadata: mcp.ToolMeta{
					Dependencies: []mcp.DependencyMetadata{
						{Name: "axios", Version: "1.14.1", Ecosystem: "npm"},
					},
				},
			},
		},
	})

	tools, err := mcp.NewAdapter().Parse(context.Background(), payload)
	require.NoError(t, err)
	require.Len(t, tools, 1)

	engine, err := analyzer.NewEngine(false, "")
	require.NoError(t, err)

	report := engine.Scan(tools[0])
	assert.True(t, report.HasFinding("AS-008"))
	require.NotEmpty(t, report.Findings)
	assert.Contains(t, report.Findings[0].Description, "axios@1.14.1")
}

func TestAdapter_Parse_EvaluateScriptInfersExec(t *testing.T) {
	// evaluate_script / execute javascript etc. must infer PermissionExec (AS-002)
	payload := mustMarshal(mcp.ListToolsResponse{
		Tools: []mcp.Tool{
			{
				Name:        "evaluate_script",
				Description: "Evaluates JavaScript in the browser context.",
				InputSchema: mcp.InputSchema{
					Type: "object",
					Properties: map[string]mcp.SchemaProperty{
						"expression": {Type: "string"},
					},
				},
			},
		},
	})
	tools, err := mcp.NewAdapter().Parse(context.Background(), payload)
	require.NoError(t, err)
	require.Len(t, tools, 1)
	assert.Contains(t, tools[0].Permissions, model.PermissionExec, "evaluate_script must infer exec permission")
}

func TestAdapter_Parse_ExecuteJavascriptInDescInfersExec(t *testing.T) {
	payload := mustMarshal(mcp.ListToolsResponse{
		Tools: []mcp.Tool{
			{
				Name:        "run_in_page",
				Description: "Execute JavaScript in the page to extract data.",
			},
		},
	})
	tools, err := mcp.NewAdapter().Parse(context.Background(), payload)
	require.NoError(t, err)
	assert.Contains(t, tools[0].Permissions, model.PermissionExec)
}

// TestAdapter_Parse_ExecCasesFixture is the load-bearing regression guard for the
// exec-permission inference fix: it scans testdata/exec-cases.json (also usable for a
// manual differential scan via `tooltrust-scanner scan --input`) and asserts that
// ambiguous "eval" substrings (lichess_cloud_eval, evaluate_position, document_retrieval)
// no longer infer exec, while genuine execution signals (command param, evaluate_script
// name keyword, standalone "eval" in prose) still do.
func TestAdapter_Parse_ExecCasesFixture(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "exec-cases.json"))
	require.NoError(t, err)

	tools, err := mcp.NewAdapter().Parse(context.Background(), data)
	require.NoError(t, err)

	wantExec := map[string]bool{
		"lichess_cloud_eval": false, // "eval" substring, read-only — must NOT infer exec
		"evaluate_position":  false, // "evaluate" prose — must NOT infer exec
		"document_retrieval": false, // "retrieval" contains "eval" — must NOT infer exec
		"run_command":        true,  // command input param — genuine exec
		"evaluate_script":    true,  // name keyword — genuine exec
		"js_runner":          true,  // standalone "eval" in prose (\beval\b) — genuine exec
	}
	require.Len(t, tools, len(wantExec))

	for _, tool := range tools {
		want, ok := wantExec[tool.Name]
		require.True(t, ok, "unexpected tool in fixture: %q", tool.Name)
		hasExec := false
		for _, p := range tool.Permissions {
			if p == model.PermissionExec {
				hasExec = true
				break
			}
		}
		assert.Equal(t, want, hasExec, "tool %q exec inference", tool.Name)
	}
}

func TestAdapter_Parse_DBTool(t *testing.T) {
	payload := mustMarshal(mcp.ListToolsResponse{
		Tools: []mcp.Tool{
			{
				Name:        "query_db",
				Description: "Run a SQL query against the database",
				InputSchema: mcp.InputSchema{
					Type: "object",
					Properties: map[string]mcp.SchemaProperty{
						"query": {Type: "string"},
					},
				},
			},
		},
	})

	tools, err := mcp.NewAdapter().Parse(context.Background(), payload)
	require.NoError(t, err)
	assert.Contains(t, tools[0].Permissions, model.PermissionDB)
}

// TestAdapter_Parse_ArrayTypeField verifies that a JSON Schema "type" value
// encoded as an array (e.g. ["string","null"]) is accepted without error and
// that the first non-null element is used as the property type.
func TestAdapter_Parse_ArrayTypeField(t *testing.T) {
	payload := []byte(`{
		"tools": [{
			"name": "GOOGLESHEETS_ADD_SHEET",
			"description": "Add a new sheet to a spreadsheet",
			"inputSchema": {
				"type": "object",
				"properties": {
					"title":  {"type": ["string", "null"], "description": "Sheet title"},
					"hidden": {"type": ["boolean", "null"], "description": "Hide the sheet"}
				}
			}
		}]
	}`)

	tools, err := mcp.NewAdapter().Parse(context.Background(), payload)
	require.NoError(t, err)
	require.Len(t, tools, 1)
	assert.Equal(t, "GOOGLESHEETS_ADD_SHEET", tools[0].Name)
	assert.Equal(t, "string", tools[0].InputSchema.Properties["title"].Type)
	assert.Equal(t, "boolean", tools[0].InputSchema.Properties["hidden"].Type)
}

// TestAdapter_Parse_LichessCloudEvalDoesNotInferExec verifies that a read-only chess
// evaluation tool whose name contains "eval" as a suffix (lichess_cloud_eval) is NOT
// incorrectly assigned PermissionExec. The underscore before "eval" means \beval\b
// does not match (word boundary requires a non-word character, but "_" is \w).
func TestAdapter_Parse_LichessCloudEvalDoesNotInferExec(t *testing.T) {
	payload := mustMarshal(mcp.ListToolsResponse{
		Tools: []mcp.Tool{
			{
				Name:        "lichess_cloud_eval",
				Description: "Get Lichess cloud evaluation for a position.",
				InputSchema: mcp.InputSchema{
					Type: "object",
					Properties: map[string]mcp.SchemaProperty{
						"fen": {Type: "string", Description: "FEN string for the position"},
					},
				},
			},
		},
	})

	tools, err := mcp.NewAdapter().Parse(context.Background(), payload)
	require.NoError(t, err)
	require.Len(t, tools, 1)
	assert.NotContains(t, tools[0].Permissions, model.PermissionExec,
		"lichess_cloud_eval is read-only and must NOT infer exec permission")
}

// TestAdapter_Parse_EvaluateProseDoesNotInferExec verifies that a tool whose name
// and description contain "evaluate" / "evaluation" (but no exec signals) is NOT
// assigned PermissionExec.
func TestAdapter_Parse_EvaluateProseDoesNotInferExec(t *testing.T) {
	payload := mustMarshal(mcp.ListToolsResponse{
		Tools: []mcp.Tool{
			{
				Name:        "evaluate_position",
				Description: "Evaluate the chess position and return a score.",
				InputSchema: mcp.InputSchema{
					Type: "object",
					Properties: map[string]mcp.SchemaProperty{
						"fen": {Type: "string", Description: "FEN string"},
					},
				},
			},
		},
	})

	tools, err := mcp.NewAdapter().Parse(context.Background(), payload)
	require.NoError(t, err)
	require.Len(t, tools, 1)
	assert.NotContains(t, tools[0].Permissions, model.PermissionExec,
		"evaluate_position with prose description must NOT infer exec permission")
}

// TestAdapter_Parse_RetrievalSubstringDoesNotInferExec is a regression guard: the
// substring "eval" appears inside "retrieval", which must NOT trigger exec inference.
func TestAdapter_Parse_RetrievalSubstringDoesNotInferExec(t *testing.T) {
	payload := mustMarshal(mcp.ListToolsResponse{
		Tools: []mcp.Tool{
			{
				Name:        "document_retrieval",
				Description: "Retrieval of documents by query.",
			},
		},
	})

	tools, err := mcp.NewAdapter().Parse(context.Background(), payload)
	require.NoError(t, err)
	require.Len(t, tools, 1)
	assert.NotContains(t, tools[0].Permissions, model.PermissionExec,
		"document_retrieval must NOT infer exec permission — 'eval' substring inside 'retrieval' is a false positive")
}

// TestAdapter_Parse_StandaloneEvalInfersExec verifies that a genuine standalone
// "eval" word in the description (matched via \beval\b) DOES infer PermissionExec.
func TestAdapter_Parse_StandaloneEvalInfersExec(t *testing.T) {
	payload := mustMarshal(mcp.ListToolsResponse{
		Tools: []mcp.Tool{
			{
				Name:        "js_runner",
				Description: "Runs eval on user-provided input.",
			},
		},
	})

	tools, err := mcp.NewAdapter().Parse(context.Background(), payload)
	require.NoError(t, err)
	require.Len(t, tools, 1)
	assert.Contains(t, tools[0].Permissions, model.PermissionExec,
		"js_runner with 'eval' as a standalone word must infer exec permission via \\beval\\b")
}

func mustMarshal(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
