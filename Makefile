# Copyright 2024 Chainguard, Inc.
# SPDX-License-Identifier: Apache-2.0


SAMPLES_REPO ?= chainguard-dev/malcontent-samples
SAMPLES_COMMIT ?= f948cfd0f9d2a35a2452fe43ea4d094979652103
YARA_X_REPO ?= virusTotal/yara-x
YARA_X_COMMIT ?= a01b1be3b4a4a43668036754555a854c779d8df3

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
GOLANGCI_LINT_VERSION ?= v2.1.6
GOLANGCI_LINT_BIN := $(LINT_ROOT)/out/linters/golangci-lint-$(GOLANGCI_LINT_VERSION)-$(LINT_ARCH)
$(GOLANGCI_LINT_BIN):
	mkdir -p $(LINT_ROOT)/out/linters
	rm -rf $(LINT_ROOT)/out/linters/golangci-lint-*
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(LINT_ROOT)/out/linters $(GOLANGCI_LINT_VERSION)
	mv $(LINT_ROOT)/out/linters/golangci-lint $@

YARA_X_VERSION ?= v1.7.0
YARA_X_SHA :=
ifeq ($(LINT_OS),Darwin)
	ifeq ($(shell uname -m),arm64)
		LINT_ARCH = aarch64
		YARA_X_SHA = 1a45a38b823f79c1ea59271c683d0bb06d510fbca4b98b457675e1bb22510fc8
	else
		YARA_X_SHA = 3ec4707b15b2fbe2d8f8d9abd288f5a849164f94ca0351aeef8487052bf0bb7b
	endif
else
	YARA_X_SHA = 58a0efae8412db408c0f566a9e8e1568064098527ff9bfb408f8883a84d50ba3
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
	git -C out/$(YARA_X_REPO) pull
	git -C out/$(YARA_X_REPO) checkout $(YARA_X_COMMIT)
	touch out/$(YARA_X_REPO)/.git/commit-$(YARA_X_COMMIT)

.PHONY: install-yara-x
install-yara-x: out/$(YARA_X_REPO)/.git/commit-$(YARA_X_COMMIT)
	mkdir -p out/lib
	mkdir -p out/include
	cd out/$(YARA_X_REPO) && \
	cargo install cargo-c --locked && \
	cargo cinstall -p yara-x-capi --features=native-code-serialization --release --prefix="$(LINT_ROOT)/out" --libdir="$(LINT_ROOT)/out/lib"

# unit tests only
.PHONY: test
test:
	go test -race ./pkg/...

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
	./out/mal refresh

ARCH ?= $(shell uname -m)
CRANE_VERSION=v0.20.3
out/crane-$(ARCH)-$(CRANE_VERSION):
	mkdir -p out
	GOBIN=$(CURDIR)/out go install github.com/google/go-containerregistry/cmd/crane@$(CRANE_VERSION)
	mv out/crane out/crane-$(ARCH)-$(CRANE_VERSION)

export-image: out/crane-$(ARCH)-$(CRANE_VERSION)
	./out/crane-$(ARCH)-$(CRANE_VERSION) \
	export \
	cgr.dev/chainguard/static:latest@sha256:bde549df44d5158013856a778b34d8972cf52bb2038ec886475d857ec7c365ed - | xz > pkg/action/testdata/static.tar.xz
