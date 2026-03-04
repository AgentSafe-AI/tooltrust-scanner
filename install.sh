#!/usr/bin/env bash
set -e

echo "🛡️ Installing ToolTrust Scanner..."

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m | sed -e 's/x86_64/amd64/' -e 's/aarch64/arm64/')"
REPO="AgentSafe-AI/tooltrust-scanner"
LATEST_RELEASE=$(curl -s "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')

if [ -z "$LATEST_RELEASE" ]; then
    echo "❌ Failed to fetch the latest release."
    exit 1
fi

DOWNLOAD_URL="https://github.com/$REPO/releases/download/$LATEST_RELEASE/tooltrust_${OS}_${ARCH}"
TMP_DIR=$(mktemp -d)
TMP_FILE="$TMP_DIR/tooltrust"

echo "⬇️ Downloading version $LATEST_RELEASE for $OS/$ARCH..."
curl -sL "$DOWNLOAD_URL" -o "$TMP_FILE"
chmod +x "$TMP_FILE"

echo "📦 Moving to /usr/local/bin/tooltrust (requires sudo)..."
sudo mv "$TMP_FILE" /usr/local/bin/tooltrust
rm -rf "$TMP_DIR"

echo "✅ Installation complete! Run 'tooltrust --help' to get started."
