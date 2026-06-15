package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDetectLocalProjectRoot_PublishedPackage verifies that a bare published-package
// launch command (npx -y <pkg>) does NOT pick up the CWD as the local project root,
// even if the CWD contains a go.mod / go.sum. This is the core fix for AS-004 FP.
func TestDetectLocalProjectRoot_PublishedPackage(t *testing.T) {
	tmp := t.TempDir()
	// Plant a go.mod so the old CWD-based heuristic would have found this dir.
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "go.mod"), []byte(`module example.com/host

go 1.21
`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "go.sum"), []byte(""), 0o644))

	t.Chdir(tmp)

	// "npx -y lichess-mcp" names a published package — no local path in args.
	got := detectLocalProjectRoot([]string{"npx", "-y", "lichess-mcp"})
	assert.Equal(t, "", got,
		"published-package launch must not infer a local project root from the CWD")
}

// TestDetectLocalProjectRoot_LocalScript verifies that arg-based detection still works:
// "node ./server.js" references a local path, so the project root containing
// package.json in the CWD should be returned.
func TestDetectLocalProjectRoot_LocalScript(t *testing.T) {
	tmp := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "package.json"), []byte(`{"name":"demo"}`), 0o644))
	// Create the script file so os.Stat succeeds on the resolved path.
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "server.js"), []byte("// stub"), 0o644))

	t.Chdir(tmp)

	got := detectLocalProjectRoot([]string{"node", "./server.js"})
	assert.Equal(t, tmp, got,
		"local-script launch must return the project root via arg-based detection")
}
