include go.mk/init.mk

PACKAGE := github.com/exoscale/vault-plugin-secrets-exoscale
GO_LD_FLAGS := -ldflags "-s -w -X $(PACKAGE)/version.Version=${VERSION} \
									-X $(PACKAGE)/version.Commit=${GIT_REVISION}"
GO_MAIN_PKG_PATH := ./cmd/vault-plugin-secrets-exoscale
EXTRA_ARGS := -parallel 3 -count=1 -failfast

.PHONY: test-acc test-verbose test
test: GO_TEST_EXTRA_ARGS=${EXTRA_ARGS}
test-verbose: GO_TEST_EXTRA_ARGS+=$(EXTRA_ARGS)
test-acc: GO_TEST_EXTRA_ARGS=-v $(EXTRA_ARGS)
test-acc: ## Run acceptance tests (requires valid Exoscale API credentials)
	$(GO) test                      \
		-race                       \
		-mod $(GO_VENDOR_DIR)       \
		-timeout $(GO_TEST_TIMEOUT) \
		--tags=testacc              \
		$(GO_TEST_EXTRA_ARGS)       \
		$(GO_TEST_PKGS)
