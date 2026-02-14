# Copyright 2024 Chainguard, Inc.
# SPDX-License-Identifier: Apache-2.0

SAMPLES_REPO ?= chainguard-sandbox/malcontent-samples
SAMPLES_COMMIT ?= f948cfd0f9d2a35a2452fe43ea4d094979652103

# BEGIN: lint-install ../malcontent
# http://github.com/tinkerbell/lint-install

.PHONY: lint
lint: _lint

LINT_ARCH := $(shell uname -m)
LINT_OS := $(shell uname)
LINT_OS_LOWER := $(shell echo $(LINT_OS) | tr '[:upper:]' '[:lower:]')
LINT_ROOT := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

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
GOLANGCI_LINT_VERSION ?= v2.8.0
GOLANGCI_LINT_BIN := $(LINT_ROOT)/out/linters/golangci-lint-$(GOLANGCI_LINT_VERSION)-$(LINT_ARCH)
$(GOLANGCI_LINT_BIN):
	mkdir -p $(LINT_ROOT)/out/linters
	rm -rf $(LINT_ROOT)/out/linters/golangci-lint-*
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(LINT_ROOT)/out/linters $(GOLANGCI_LINT_VERSION)
	mv $(LINT_ROOT)/out/linters/golangci-lint $@

YARA_X_REPO ?= virusTotal/yara-x
YARA_X_VERSION ?= v1.12.0
YARA_X_COMMIT ?= 466a624e381beefde7665433494887d80932a662
YARA_X_SHA :=
ifeq ($(LINT_OS),Darwin)
	ifeq ($(shell uname -m),arm64)
		LINT_ARCH = aarch64
		YARA_X_SHA = 63100b4d6505c366d3c6af5145a26b961d2bf1646a4442716d81bb6f6a4dbee2
	else
		YARA_X_SHA = 29a50a3cf442206b9c116f3a322debc367215d4667cf99512550cbdca7c88fc0
	endif
else ifeq ($(LINT_OS),Linux)
	ifeq ($(shell uname -m),arm64)
		LINT_ARCH = aarch64
		YARA_X_SHA = 614cb7b5a738e1e6e3fe6b98bca207c2dfd012ad95d4a85d5e62a0eac985c554
	else
		YARA_X_SHA = f460a20b78b66b08b6d323f1d1ed00ab94328ae98a3f755f29692e49caa48cb7
	endif
endif
YARA_X_BIN := $(LINT_ROOT)/out/linters/yr-$(YARA_X_VERSION)-$(LINT_ARCH)
$(YARA_X_BIN):
	mkdir -p $(LINT_ROOT)/out/linters
	rm -rf $(LINT_ROOT)/out/linters/yr
	curl -sSfL https://github.com/VirusTotal/yara-x/releases/download/$(YARA_X_VERSION)/yara-x-$(YARA_X_VERSION)-$(LINT_ARCH)-$(LINT_PLATFORM)-$(LINT_OS_LOWER)$(LINT_PLATFORM_SUFFIX).gz -o yara-x.gz
	echo "$(YARA_X_SHA) *yara-x.gz" | shasum -a 256 --check
	tar -xzvf yara-x.gz && mv yr $(LINT_ROOT)/out/linters && rm yara-x.gz
	mv $(LINT_ROOT)/out/linters/yr $@

LINTERS += golangci-lint-lint
golangci-lint-lint: $(GOLANGCI_LINT_BIN)
	find . -maxdepth 1 -name go.mod -print0 | xargs -0 -L1 -I{} /bin/sh -c '"$(GOLANGCI_LINT_BIN)" run -c "$(GOLANGCI_LINT_CONFIG)"' \;

FIXERS += golangci-lint-fix
golangci-lint-fix: $(GOLANGCI_LINT_BIN)
	find . -maxdepth 1 -name go.mod -execdir "$(GOLANGCI_LINT_BIN)" run -c "$(GOLANGCI_LINT_CONFIG)" --fix \;

FIXERS += modernize
modernize:
	go run golang.org/x/tools/gopls/internal/analysis/modernize/cmd/modernize@latest -fix -test ./...

LINTERS += yara-x-fmt
yara-x-fmt: $(YARA_X_BIN)
	find rules -type f -name "*.yara" -execdir "$(YARA_X_BIN)" fmt {} \;

yara-x-compile: $(YARA_X_BIN)
	"$(YARA_X_BIN)" compile --path-as-namespace -w rules/

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

out/$(YARA_X_REPO)/.git/commit-$(YARA_X_COMMIT):
	mkdir -p out/$(YARA_X_REPO)
	test -d out/$(YARA_X_REPO)/.git ||git clone https://github.com/$(YARA_X_REPO).git out/$(YARA_X_REPO)
	rm out/$(YARA_X_REPO)/.git/commit-* 2>/dev/null || true
	git -C out/$(YARA_X_REPO) switch - || true
	git -C out/$(YARA_X_REPO) pull --rebase --autostash
	git -C out/$(YARA_X_REPO) checkout $(YARA_X_COMMIT)
	touch out/$(YARA_X_REPO)/.git/commit-$(YARA_X_COMMIT)

samples: out/$(SAMPLES_REPO)/.decompressed-$(SAMPLES_COMMIT)

.PHONY: install-yara-x
install-yara-x: out/$(YARA_X_REPO)/.git/commit-$(YARA_X_COMMIT)
	mkdir -p out/lib
	mkdir -p out/include
	cd out/$(YARA_X_REPO) && \
	cargo install cargo-c --locked && \
	cargo cinstall -p yara-x-capi --features=native-code-serialization --release --prefix="$(LINT_ROOT)/out" --libdir="$(LINT_ROOT)/out/lib"

.PHONY: update-deps
update-deps:
	go get -u ./...
	go mod tidy

# unit tests only
.PHONY: test
test:
	go test -race ./pkg/...

FUZZ_TIME ?= 10s
.PHONY: fuzz
fuzz:
	@grep -r "^func Fuzz" --include="*_test.go" pkg/ | \
		awk -F'[:(]' '{gsub(/func /, "", $$2); dir=$$1; sub(/\/[^/]+$$/, "/", dir); print $$2, "./" dir}' | \
		while read -r func dir; do \
			echo "--- $$func ($$dir) ---"; \
			CGO_LDFLAGS="-L$(LINT_ROOT)/out/lib -Wl,-rpath,$(LINT_ROOT)/out/lib" \
			CGO_CPPFLAGS="-I$(LINT_ROOT)/out/include" \
			PKG_CONFIG_PATH="$(LINT_ROOT)/out/lib/pkgconfig" \
			go test -timeout 0 -fuzz="^$$func$$" -fuzztime=$(FUZZ_TIME) "$$dir" || exit 1; \
		done

# fuzz tests - runs continuously (use Ctrl+C to stop)
# Usage: make fuzz-continuous FUZZ_TARGET=FuzzExtractArchive FUZZ_PKG=./pkg/archive/
FUZZ_TARGET ?= FuzzExtractArchive
FUZZ_PKG ?= ./pkg/archive/
.PHONY: fuzz-continuous
fuzz-continuous:
	go test -fuzz=$(FUZZ_TARGET) $(FUZZ_PKG)

# unit tests only
.PHONY: coverage
coverage: out/mal.coverage

# generate the html report
.PHONY: coverage-html
coverage-html: out/coverage.html

# pop open the html page in a browser directly
.PHONY: coverage-browser
coverage-browser: out/mal.coverage
	go tool cover -html=$<

# generate the html report
out/coverage.html: out/mal.coverage
	go tool cover -html=$< -o $@

# we always want to regen the coverage data file
.PHONY: out/mal.coverage
out/mal.coverage:
	mkdir -p out
	go test -coverprofile $@ -race ./pkg/... -coverpkg ./pkg/...

# integration tests only
.PHONY: integration
integration: out/$(SAMPLES_REPO)/.decompressed-$(SAMPLES_COMMIT)
	go test -race -timeout 0 ./tests/...

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
	CGO_LDFLAGS="-L$(LINT_ROOT)/out/lib -Wl,-rpath,$(LINT_ROOT)/out/lib" \
	CGO_CPPFLAGS="-I$(LINT_ROOT)/out/include" \
	PKG_CONFIG_PATH="$(LINT_ROOT)/out/lib/pkgconfig" \
	go build -o out/mal ./cmd/mal

.PHONY: update-third-party
update-third-party:
	./third_party/yara/update.sh

.PHONY: refresh-sample-testdata
refresh-sample-testdata: out/$(SAMPLES_REPO)/.decompressed-$(SAMPLES_COMMIT) out/mal
	MALCONTENT_UPX_PATH=$(shell which upx) ./out/mal refresh

ARCH ?= $(shell uname -m)
CRANE_VERSION=v0.20.7
out/crane-$(ARCH)-$(CRANE_VERSION):
	mkdir -p out
	GOBIN=$(CURDIR)/out go install github.com/google/go-containerregistry/cmd/crane@$(CRANE_VERSION)
	mv out/crane out/crane-$(ARCH)-$(CRANE_VERSION)

export-image: out/crane-$(ARCH)-$(CRANE_VERSION)
	./out/crane-$(ARCH)-$(CRANE_VERSION) \
	export \
	cgr.dev/chainguard/static:latest@sha256:bde549df44d5158013856a778b34d8972cf52bb2038ec886475d857ec7c365ed - | xz > pkg/action/testdata/static.tar.xz
