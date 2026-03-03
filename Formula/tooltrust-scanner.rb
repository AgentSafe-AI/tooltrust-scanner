# Homebrew Formula for ToolTrust Scanner
# Install: brew install --formula "https://raw.githubusercontent.com/AgentSafe-AI/tooltrust-scanner/main/Formula/tooltrust-scanner.rb"
#
# After releasing v0.1.3+, update the sha256:
#   curl -sL https://github.com/AgentSafe-AI/tooltrust-scanner/archive/refs/tags/v0.1.3.tar.gz | shasum -a 256

class TooltrustScanner < Formula
  desc "Security scanner and trust gateway for AI agent tool ecosystems"
  homepage "https://github.com/AgentSafe-AI/tooltrust-scanner"
  version "0.1.2"
  url "https://github.com/AgentSafe-AI/tooltrust-scanner/archive/refs/tags/v#{version}.tar.gz"
  sha256 "9e4c3beb7e7c5e8d34969ed661e64590b518d87a2341d041c718a58bab369bc9"
  license "MIT"

  depends_on "go" => :build

  def install
    cd "tooltrust-scanner-#{version}" do
      system "go", "build", *std_go_args(ldflags: "-s -w -X main.version=#{version}"), "./cmd/tooltrust-scanner"
    end
  end

  test do
    assert_match "tooltrust-scanner", shell_output("#{bin}/tooltrust-scanner version")
  end
end
