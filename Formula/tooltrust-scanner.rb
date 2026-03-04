# Homebrew Formula for ToolTrust Scanner
# Install: brew install --formula "https://raw.githubusercontent.com/AgentSafe-AI/tooltrust-scanner/main/Formula/tooltrust-scanner.rb"
#
# To update to a new release vX.Y.Z:
#   1. Create the git tag and push: git tag vX.Y.Z && git push origin vX.Y.Z
#   2. curl -sL https://github.com/AgentSafe-AI/tooltrust-scanner/archive/refs/tags/vX.Y.Z.tar.gz | shasum -a 256
#   3. Update version and sha256 below

class TooltrustScanner < Formula
  desc "Security scanner and trust gateway for AI agent tool ecosystems"
  homepage "https://github.com/AgentSafe-AI/tooltrust-scanner"
  version "0.1.3"
  url "https://github.com/AgentSafe-AI/tooltrust-scanner/archive/refs/tags/v#{version}.tar.gz"
  sha256 "8f2f96d41327386f0b64a474c9081cf49469418685676401a3553b803ac056e4"
  license "MIT"

  depends_on "go" => :build

  def install
    system "go", "build", *std_go_args(ldflags: "-s -w -X main.version=#{version}"), "./cmd/tooltrust-scanner"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/tooltrust-scanner version")
  end
end
