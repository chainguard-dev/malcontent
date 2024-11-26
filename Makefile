# Copyright 2024 Chainguard, Inc.
# SPDX-License-Identifier: Apache-2.0


SAMPLES_REPO ?= chainguard-dev/malcontent-samples
SAMPLES_COMMIT ?= 526c096e7350f06dbb4bf5d6761cb3888c9376ba

# BEGIN: lint-install ../malcontent
# http://github.com/tinkerbell/lint-install

.PHONY: lint
lint: _lint

LINT_ARCH := $(shell uname -m)
LINT_OS := $(shell uname)
LINT_OS_LOWER := $(shell echo $(LINT_OS) | tr '[:upper:]' '[:lower:]')
LINT_ROOT := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

# shellcheck and hadolint lack arm64 native binaries: rely on x86-64 emulation
ifeq ($(LINT_OS),Darwin)
	ifeq ($(LINT_ARCH),arm64)
		LINT_ARCH=x86_64
	endif
endif

# yara-x adds an additional string for the platform (apple, unknown)
LINT_PLATFORM :=
ifeq ($(LINT_OS),Darwin)
	LINT_PLATFORM=apple
else
	LINT_PLATFORM=unknown
endif


LINT_PLATFOM_SUFFIX :=
ifeq ($(LINT_OS),Linux)
	LINT_PLATFORM_SUFFIX=-gnu
endif


LINTERS :=
FIXERS :=

GOLANGCI_LINT_CONFIG := $(LINT_ROOT)/.golangci.yml
GOLANGCI_LINT_VERSION ?= v1.62.0
GOLANGCI_LINT_BIN := $(LINT_ROOT)/out/linters/golangci-lint-$(GOLANGCI_LINT_VERSION)-$(LINT_ARCH)
$(GOLANGCI_LINT_BIN):
	mkdir -p $(LINT_ROOT)/out/linters
	rm -rf $(LINT_ROOT)/out/linters/golangci-lint-*
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(LINT_ROOT)/out/linters $(GOLANGCI_LINT_VERSION)
	mv $(LINT_ROOT)/out/linters/golangci-lint $@

YARA_X_VERSION ?= v0.10.0
YARA_X_BIN := $(LINT_ROOT)/out/linters/yr-$(YARA_X_VERSION)-$(LINT_ARCH)
$(YARA_X_BIN):
	mkdir -p $(LINT_ROOT)/out/linters
	rm -rf $(LINT_ROOT)/out/linters/yr
	curl -sSfL https://github.com/VirusTotal/yara-x/releases/download/$(YARA_X_VERSION)/yara-x-$(YARA_X_VERSION)-$(LINT_ARCH)-$(LINT_PLATFORM)-$(LINT_OS_LOWER)$(LINT_PLATFORM_SUFFIX).gzip -o yara-x.gzip
	tar -xzvf yara-x.gzip && mv yr $(LINT_ROOT)/out/linters && rm yara-x.gzip
	mv $(LINT_ROOT)/out/linters/yr $@

LINTERS += golangci-lint-lint
golangci-lint-lint: $(GOLANGCI_LINT_BIN)
	find . -name go.mod -execdir "$(GOLANGCI_LINT_BIN)" run -c "$(GOLANGCI_LINT_CONFIG)" \;

FIXERS += golangci-lint-fix
golangci-lint-fix: $(GOLANGCI_LINT_BIN)
	find . -name go.mod -execdir "$(GOLANGCI_LINT_BIN)" run -c "$(GOLANGCI_LINT_CONFIG)" --fix \;

LINTERS += yara-x-fmt
yara-x-fmt: $(YARA_X_BIN)
	find rules -type f -name "*.yara" -execdir "$(YARA_X_BIN)" fmt {} \;

yara-x-compile: $(YARA_X_BIN)
	"$(YARA_X_BIN)" compile ./rules/

.PHONY: _lint $(LINTERS)
_lint: $(LINTERS)

.PHONY: fix $(FIXERS)
fix: $(FIXERS)

# END: lint-install ../malcontent

# sample checkouts have 3 stages:
# out/samples/.git - I'm a blank git repo
# out/samples/.git/commit-<hash> - I'm checked out to this particular commit
# out/samples/.decompressed-<hash> - I've decompressed to this particular commit

out/${SAMPLES_REPO}/.git/commit-$(SAMPLES_COMMIT):
	mkdir -p out/$(SAMPLES_REPO)
	test -d out/$(SAMPLES_REPO)/.git || git clone --depth 4 https://github.com/$(SAMPLES_REPO).git out/$(SAMPLES_REPO)
	rm out/$(SAMPLES_REPO)/.git/commit-* 2>/dev/null || true
	git -C out/$(SAMPLES_REPO) switch - || true
	git -C out/$(SAMPLES_REPO) pull
	git -C out/$(SAMPLES_REPO) checkout $(SAMPLES_COMMIT)
	touch out/$(SAMPLES_REPO)/.git/commit-$(SAMPLES_COMMIT)

out/$(SAMPLES_REPO)/.decompressed-$(SAMPLES_COMMIT): out/${SAMPLES_REPO}/.git/commit-$(SAMPLES_COMMIT)
	find out/$(SAMPLES_REPO)/ -name "*.xz" -type f -exec xz -dk {} \;
	touch out/$(SAMPLES_REPO)/.decompressed-$(SAMPLES_COMMIT)

# unit tests only
.PHONY: test
test:
	go test ./pkg/...

# integration tests only
.PHONY: integration
integration: out/$(SAMPLES_REPO)/.decompressed-$(SAMPLES_COMMIT)
	go test -timeout 0 ./tests/...

.PHONY: bench
bench: out/$(SAMPLES_REPO)/.decompressed-$(SAMPLES_COMMIT)
	go test -run=^\$$ -bench=. ./... -benchmem

BENCH_CMD := go test -benchmem -run=^\$$ -bench ^BenchmarkRun\$$ github.com/chainguard-dev/malcontent/tests -args

.PHONY: bench-malcontent
bench-malcontent:
	$(BENCH_CMD) -path="macOS/clean/malcontent"

.PHONY: bench-all-samples
bench-all-samples:
	$(BENCH_CMD) -path=""

.PHONY: bench-does-nothing
bench-does-nothing:
	$(BENCH_CMD) -path="does-nothing"

.PHONY: bench-javascript
bench-javascript:
	$(BENCH_CMD) -path="Javascript"

.PHONY: bench-linux
bench-linux:
	$(BENCH_CMD) -path="Linux"

.PHONY: bench-macos
bench-macos:
	$(BENCH_CMD) -path="macOS"

.PHONY: bench-npm
bench-npm:
	$(BENCH_CMD) -path="NPM"

.PHONY: bench-php
bench-php:
	$(BENCH_CMD) -path="PHP"

.PHONY: bench-python
bench-python:
	$(BENCH_CMD) -path="Python"

.PHONY: bench-typescript
bench-typescript:
	$(BENCH_CMD) -path="TypeScript"

.PHONY: bench-windows
bench-windows:
	$(BENCH_CMD) -path="Windows"

.PHONY: out/mal
out/mal:
	mkdir -p out
	go build -o out/mal ./cmd/mal

.PHONY: update-third-party
update-third-party:
	./third_party/yara/update.sh

.PHONY: refresh-sample-testdata
refresh-sample-testdata: out/$(SAMPLES_REPO)/.decompressed-$(SAMPLES_COMMIT) out/mal
	./out/mal refresh

ARCH ?= $(shell uname -m)
CRANE_VERSION=v0.20.2
out/crane-$(ARCH)-$(CRANE_VERSION):
	mkdir -p out
	GOBIN=$(CURDIR)/out go install github.com/google/go-containerregistry/cmd/crane@$(CRANE_VERSION)
	mv out/crane out/crane-$(ARCH)-$(CRANE_VERSION)

export-image: out/crane-$(ARCH)-$(CRANE_VERSION)
	./out/crane-$(ARCH)-$(CRANE_VERSION) \
	export \
	cgr.dev/chainguard/static:latest@sha256:bde549df44d5158013856a778b34d8972cf52bb2038ec886475d857ec7c365ed - | xz > pkg/action/testdata/static.tar.xz
