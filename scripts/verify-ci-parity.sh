#!/usr/bin/env bash
set -eu
apt-get update -qq
apt-get install -y -qq bc >/dev/null
cd /src
go mod download
go mod verify
go test -race -count=1 -timeout=120s ./...
go test -race -count=1 -coverprofile=coverage.out ./pkg/... ./internal/...
COVERAGE=$(go tool cover -func=coverage.out | grep total | awk '{print $3}' | tr -d '%')
echo "Total coverage: ${COVERAGE}%"
if (( $(echo "$COVERAGE < 60" | bc -l) )); then
  echo "Coverage below 60%"
  exit 1
fi
go build -v ./cmd/tooltrust-scanner/...
go build -v ./cmd/tooltrust-mcp/...
go build -o /tmp/tt ./cmd/tooltrust-scanner
/tmp/tt scan --protocol mcp --input testdata/tools.json --output json --file /tmp/scan.json
/tmp/tt scan --protocol mcp --input testdata/tools.json --fail-on block
echo "verify-ci-parity: OK"
