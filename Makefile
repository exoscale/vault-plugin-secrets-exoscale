VERSION := $(shell git describe --exact-match --tags $(git log -n1 --pretty='%h') 2> /dev/null | sed 's/^v//')
ifndef VERSION
    VERSION = dev
endif
COMMIT := $(shell git rev-parse HEAD)
GO_PKG := github.com/exoscale/vault-plugin-secrets-exoscale
GO_BUILDOPTS := -ldflags "-s -w -X $(GO_PKG)/version.Version=${VERSION} -X $(GO_PKG)/version.Commit=${COMMIT}"
GO_OPTS := -mod vendor $(GO_BUILDOPTS)
GO_TEST ?= go test
GO_TESTOPTS := $(GO_OPTS) -v -parallel 3 -count=1 -failfast
PLUGIN_BIN := vault-plugin-secrets-exoscale

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-10s\033[0m %s\n", $$1, $$2}'

build: ## Build the Vault plugin binary
	@go build ${GO_BUILDOPTS} -o $(PLUGIN_BIN) ./cmd/vault-plugin-secrets-exoscale

.PHONY: lint
lint:
	@golangci-lint run ./...

.PHONY: test
test: ## Run unit tests
	@$(GO_TEST) $(GO_TESTOPTS) $(TESTARGS) ./...

.PHONY: testacc
testacc: ## Run acceptance tests (requires valid Exoscale API credentials)
	@$(GO_TEST) $(GO_TESTOPTS) --tags=testacc $(TESTARGS) ./...

.PHONY: testall
testall: lint test testacc ## Run all tests (lint + unit + acceptance)

.PHONY: clean
clean:
	@rm -f $(PLUGIN_BIN)
