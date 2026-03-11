package deepscan

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/pterm/pterm"
	"github.com/yalue/onnxruntime_go"
)

// Dummy URLs for Phase 1.
const (
	modelURL  = "https://raw.githubusercontent.com/AgentSafe-AI/tooltrust-scanner/main/README.md" // replace when model is ready
	corpusURL = "https://raw.githubusercontent.com/AgentSafe-AI/tooltrust-scanner/main/LICENSE"   // replace when corpus is ready
)

var (
	// IsInitialized is set to true if ONNX and the models are successfully loaded.
	IsInitialized bool
)

// Init checks for the ONNX shared library, downloads ML models if missing, and initializes the ONNX runtime.
// If the shared library is missing, it returns an error gracefully so the engine can fallback to Regex.
func Init(ctx context.Context) error {
	// Developers need to install the ONNX Runtime Shared Library locally.
	//
	// macOS: brew install onnxruntime (typically installs to /opt/homebrew/lib/libonnxruntime.dylib)
	// Linux: Download .so from GitHub releases and place in /usr/lib or set LD_LIBRARY_PATH.
	// Windows: Download .dll from GitHub releases and place in C:\Windows\System32 or in the app dir.

	onnxLibPath := getONNXSharedLibraryPath()
	if onnxLibPath == "" || !fileExists(onnxLibPath) {
		return fmt.Errorf("ONNX shared library not found. Falling back to pure regex mode. Please install onnxruntime (e.g., brew install onnxruntime)")
	}

	onnxruntime_go.SetSharedLibraryPath(onnxLibPath)
	if err := onnxruntime_go.InitializeEnvironment(); err != nil {
		return fmt.Errorf("failed to initialize ONNX environment: %w", err)
	}

	if err := EnsureModels(ctx); err != nil {
		return err
	}

	IsInitialized = true
	pterm.Info.Println("🧪 ONNX ML Engine active (Semantic Tokenizer is currently in Alpha preview)")
	return nil
}

func getONNXSharedLibraryPath() string {
	switch runtime.GOOS {
	case "darwin":
		if fileExists("/opt/homebrew/lib/libonnxruntime.dylib") {
			return "/opt/homebrew/lib/libonnxruntime.dylib"
		}
		if fileExists("/usr/local/lib/libonnxruntime.dylib") {
			return "/usr/local/lib/libonnxruntime.dylib"
		}
		return "libonnxruntime.dylib"
	case "linux":
		if fileExists("/usr/lib/libonnxruntime.so") {
			return "/usr/lib/libonnxruntime.so"
		}
		if fileExists("/usr/local/lib/libonnxruntime.so") {
			return "/usr/local/lib/libonnxruntime.so"
		}
		return "libonnxruntime.so"
	case "windows":
		return "onnxruntime.dll"
	default:
		return ""
	}
}

// EnsureModels downloads the required ONNX and corpus files if they don't exist.
// If they do not exist, it securely downloads them while displaying a pterm spinner.
func EnsureModels(ctx context.Context) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home dir: %w", err)
	}

	modelDir := filepath.Join(home, ".tooltrust", "models")
	if mkdirErr := os.MkdirAll(modelDir, 0o755); mkdirErr != nil {
		return fmt.Errorf("failed to create models directory %s: %w", modelDir, mkdirErr)
	}

	modelPath := filepath.Join(modelDir, "model.onnx")
	corpusPath := filepath.Join(modelDir, "corpus.json")

	// If already downloaded, fast-path out safely.
	if fileExists(modelPath) && fileExists(corpusPath) {
		return nil
	}

	// Wait up to 2 minutes for downloads.
	dlCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	spinner, err := pterm.DefaultSpinner.Start("Downloading deep-scan ML models (22MB)...")
	if err != nil {
		return fmt.Errorf("failed to start pterm spinner: %w", err)
	}

	if err := downloadFile(dlCtx, modelURL, modelPath); err != nil {
		spinner.Fail("Failed to download model")
		return fmt.Errorf("model download failed: %w", err)
	}

	if err := downloadFile(dlCtx, corpusURL, corpusPath); err != nil {
		spinner.Fail("Failed to download corpus")
		return fmt.Errorf("corpus download failed: %w", err)
	}

	spinner.Success("Deep-scan models loaded!")
	return nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func downloadFile(ctx context.Context, url, targetPath string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("download request failed: %w", err)
	}
	defer func() {
		closeErr := resp.Body.Close()
		if err == nil && closeErr != nil {
			err = closeErr
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	out, err := os.Create(targetPath) //nolint:gosec // user local home directory setup
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer func() {
		closeErr := out.Close()
		if err == nil && closeErr != nil {
			err = closeErr
		}
	}()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return fmt.Errorf("failed during file download completion: %w", err)
	}
	return nil
}
