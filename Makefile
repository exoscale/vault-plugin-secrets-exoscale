GO_MK_REF := v2.0.0

# make go.mk a dependency for all targets
.EXTRA_PREREQS = go.mk

ifndef MAKE_RESTARTS
# This section will be processed the first time that make reads this file.

# This causes make to re-read the Makefile and all included
# makefiles after go.mk has been cloned.
Makefile:
	@touch Makefile
endif

.PHONY: go.mk
.ONESHELL:
go.mk:
	@if [ ! -d "go.mk" ]; then
		git clone https://github.com/exoscale/go.mk.git
	fi
	@cd go.mk
	@if ! git show-ref --quiet --verify "refs/heads/${GO_MK_REF}"; then
		git fetch
	fi
	@if ! git show-ref --quiet --verify "refs/tags/${GO_MK_REF}"; then
		git fetch --tags
	fi
	git checkout --quiet ${GO_MK_REF}

PACKAGE := github.com/exoscale/vault-plugin-secrets-exoscale
PROJECT_URL := https://$(PACKAGE)
GO_MAIN_PKG_PATH := ./cmd/vault-plugin-secrets-exoscale


go.mk/init.mk:
include go.mk/init.mk

GO_LD_FLAGS := -ldflags "-s -w -X $(PACKAGE)/version.Version=${VERSION} -X $(PACKAGE)/version.Commit=${GIT_REVISION}"

go.mk/public.mk:
include go.mk/public.mk

ifeq ($(VERSION), dev)
	VERSION = v0.0.0+dev
endif

EXTRA_ARGS := -parallel 3 -count=1 -failfast
.PHONY: test-acc test-verbose test
test: GO_TEST_EXTRA_ARGS=${EXTRA_ARGS}
test-verbose: GO_TEST_EXTRA_ARGS+=$(EXTRA_ARGS)
test-acc: GO_TEST_EXTRA_ARGS=-v $(EXTRA_ARGS)
test-acc: ## Run acceptance tests (requires valid Exoscale API credentials)
	$(GO) test                      \
		-race                       \
		-timeout $(GO_TEST_TIMEOUT) \
		--tags=testacc              \
		$(GO_TEST_EXTRA_ARGS)       \
		$(GO_TEST_PKGS)

generate-mocks:
	go install github.com/vektra/mockery/v2@v2.30.1
	go generate

cover:
	go test -cover -coverprofile=cover.out ./...
	go tool cover -html cover.out
