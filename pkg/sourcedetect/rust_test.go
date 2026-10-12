package sourcedetect

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRustPresence(t *testing.T) {
	sdk := "use rmcp::{ServerHandler};\nimpl ServerHandler for Server {}"
	manual := `use serde_json::{json, Value}; fn dispatch() { match method { "tools/list" => json!({"tools": [{"inputSchema": schema()}]}), _ => {} } }`
	for _, tc := range []struct {
		name, code string
		want       bool
	}{
		{"sdk", sdk, true}, {"manual", manual, true},
		{"client", "use rmcp::ServiceExt; client.serve().await;", false},
		{"comment", "/* nested /* comment */ " + sdk + " */", false},
		{"raw-string", "const DOC: &str = r###\"" + sdk + "\"###;", false},
		{"line-comment", "// use rmcp::ServerHandler;\n// impl ServerHandler for Server {}", false},
		{"incomplete", `use serde_json::json; fn f() { match m { "tools/list" => json!({}), _ => {} } }`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, "main.rs"), []byte(tc.code), 0o600); err != nil {
				t.Fatal(err)
			}
			result, err := DetectEmbeddedMCP(root, Options{})
			if err != nil {
				t.Fatal(err)
			}
			if result.HasEmbeddedMCP != tc.want {
				t.Fatalf("presence = %v, want %v", result.HasEmbeddedMCP, tc.want)
			}
			if tc.want && result.Detection.Matches[0].Language != "rust" {
				t.Fatal("missing Rust evidence")
			}
		})
	}
}
