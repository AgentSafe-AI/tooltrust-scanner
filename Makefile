.PHONY: check fmt lint test build scan e2e clean

check: fmt lint test build
	@echo "✅ All CI/CD checks passed! Ready to commit."

fmt:
	@echo "🧹 Formatting code..."
	go fmt ./...

lint:
	@echo "🔍 Running linter..."
	go vet ./...
	# If you have golangci-lint installed, uncomment the line below
	# golangci-lint run

test:
	@echo "🧪 Running unit tests..."
	go test -race ./...

build:
	@echo "🔨 Verifying build..."
	go build -o tooltrust-scanner ./cmd/tooltrust-scanner
	go build -o tooltrust-mcp ./cmd/mcpserver

e2e: scan-test

scan-test: build
	@echo "🔎 Running E2E Scanner Test..."
	# Run E2E scan with the newly built binary
	./tooltrust-scanner scan --server "npx -y @modelcontextprotocol/server-memory"

clean:
	@echo "🧹 Cleaning up..."
	rm -f tooltrust-scanner tooltrust-mcp
