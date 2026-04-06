BINARY    := homepki
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS   := -ldflags "-w -X main.version=$(VERSION) -X main.commit=$(shell git rev-parse --short HEAD 2>/dev/null || echo unknown) -X main.date=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)"
BUILD_DIR := ./dist

# Prefer Homebrew Go over any custom GOROOT-based install to avoid version mismatch on macOS
HOMEBREW_GO := /opt/homebrew/bin/go
ifneq ($(wildcard $(HOMEBREW_GO)),)
  GO := env -u GOROOT $(HOMEBREW_GO)
else
  GO := go
endif

.PHONY: help build test lint install clean tidy snapshot release-check
.DEFAULT_GOAL := help

help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"; printf "Usage: make \033[36m<target>\033[0m\n\nTargets:\n"} \
	  /^[a-zA-Z_-]+:.*##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

build: ## Build the binary into ./dist
	mkdir -p $(BUILD_DIR)
	$(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY) .

test: ## Run all tests
	$(GO) test ./...

lint: ## Run golangci-lint
	golangci-lint run ./...

install: ## Install the binary via go install
	$(GO) install $(LDFLAGS) .

clean: ## Remove build artifacts
	rm -rf $(BUILD_DIR)

tidy: ## Tidy go.mod and go.sum
	$(GO) mod tidy

snapshot: ## Local dry-run release without publishing (requires goreleaser)
	goreleaser release --snapshot --clean

release-check: ## Validate .goreleaser.yaml
	goreleaser check
