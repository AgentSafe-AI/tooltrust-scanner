# Homebrew Formula for ToolTrust Scanner
# Install: brew install --formula "https://raw.githubusercontent.com/AgentSafe-AI/tooltrust-scanner/main/Formula/tooltrust-scanner.rb"
#
# To update to a new release vX.Y.Z:
#   1. Create the git tag and push: git tag vX.Y.Z && git push origin vX.Y.Z
#   2. curl -sL https://github.com/AgentSafe-AI/tooltrust-scanner/archive/refs/tags/vX.Y.Z.tar.gz | shasum -a 256
#   3. Update version and sha256 below

class TooltrustScanner < Formula
  desc "Security scanner for AI agent tool definitions"
  homepage "https://github.com/AgentSafe-AI/tooltrust-scanner"
  version "0.2.0"
  url "https://github.com/AgentSafe-AI/tooltrust-scanner/archive/refs/tags/v#{version}.tar.gz"
  sha256 "9da678baabfeae8225ab8ba9ce38a6f3d2603893bab860ded358b80106878a6a"
  license "MIT"

  depends_on "go" => :build

  def install
    system "go", "build", *std_go_args(ldflags: "-s -w -X main.version=#{version}"), "./cmd/tooltrust-scanner"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/tooltrust-scanner version")
  end
end
