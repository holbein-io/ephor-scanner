BINARY_NAME := ephor-scanner
CMD_PATH := ./cmd/scanner
BUILD_DIR := bin
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -s -w -X main.version=$(VERSION)
GOBIN := $(shell go env GOBIN)
# The Dockerfile is the single source of truth for the bundled Trivy version.
TRIVY_IMAGE := $(shell sed -n 's|^FROM \(aquasec/trivy:[^ ]*\).*|\1|p' Dockerfile)

.PHONY: build test test-integration trivy lint clean fmt vet

build:
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) $(CMD_PATH)

test:
	go test -race -count=1 ./...

test-integration: $(BUILD_DIR)/trivy
	PATH="$(CURDIR)/$(BUILD_DIR):$$PATH" go test -race -count=1 -tags=integration ./...

trivy: $(BUILD_DIR)/trivy

# Extract the Trivy binary from the exact image (tag + digest) pinned in the Dockerfile.
# Re-extracted only when the Dockerfile changes.
$(BUILD_DIR)/trivy: Dockerfile
	@test -n "$(TRIVY_IMAGE)" || { echo "no aquasec/trivy FROM line found in Dockerfile" >&2; exit 1; }
	@mkdir -p $(BUILD_DIR)
	@id=$$(docker create "$(TRIVY_IMAGE)") && \
		docker cp "$$id:/usr/local/bin/trivy" $@; rc=$$?; \
		docker rm "$$id" >/dev/null; exit $$rc
	@$@ --version

lint:
	$(GOBIN)/golangci-lint run ./...

fmt:
	gofmt -w .

vet:
	go vet ./...

clean:
	rm -rf $(BUILD_DIR)
	go clean -testcache
