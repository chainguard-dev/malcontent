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

# flags required to successfully build malcontent with yara-x's C API
CPPFLAGS ?= "-I$(LINT_ROOT)/out/include"
LDFLAGS :=
PKGCONF_PATH ?= "$(LINT_ROOT)/out/lib/pkgconfig"
ifeq ($(LINT_OS),Darwin)
	LDFLAGS="-L$(LINT_ROOT)/out/lib -Wl,-no_warn_duplicate_libraries,-rpath,$(LINT_ROOT)/out/lib,-lyara_x_capi"
else ifeq ($(LINT_OS),Linux)
	LDFLAGS="-L$(LINT_ROOT)/out/lib -Wl,-rpath,$(LINT_ROOT)/out/lib,-lyara_x_capi,-no-pie"
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
GOLANGCI_LINT_VERSION ?= v2.10.1
GOLANGCI_LINT_BIN := $(LINT_ROOT)/out/linters/golangci-lint-$(GOLANGCI_LINT_VERSION)-$(LINT_ARCH)
$(GOLANGCI_LINT_BIN):
	mkdir -p $(LINT_ROOT)/out/linters
	rm -rf $(LINT_ROOT)/out/linters/golangci-lint-*
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(LINT_ROOT)/out/linters $(GOLANGCI_LINT_VERSION)
	mv $(LINT_ROOT)/out/linters/golangci-lint $@

YARA_X_REPO ?= virusTotal/yara-x
YARA_X_VERSION ?= v1.13.0
YARA_X_COMMIT ?= d397e8c3feee79e91f4b389288ba244264da2813
YARA_X_SHA :=
ifeq ($(LINT_OS),Darwin)
	ifeq ($(shell uname -m),arm64)
		LINT_ARCH = aarch64
		YARA_X_SHA = 0931697b9cfe74cade4a7136610a5cd254ae3bed95831b413c6b54f5760d554f
	else
		YARA_X_SHA = 226dce240b8d674db3c83b5c0b6d336268a46f1fbd6718fa9bdeb3735857f6c4
	endif
else ifeq ($(LINT_OS),Linux)
	ifeq ($(shell uname -m),arm64)
		LINT_ARCH = aarch64
		YARA_X_SHA = a50e9b593c5a6039c227f665b8ade1ea1c4bee3be5789add3e33f033cbf427ae
	else
		YARA_X_SHA = b93fb0b87016c60498c26b8a17d2617bbc49f5d5b1a291cde5b09658ce93bb69
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
	find . -maxdepth 1 -name go.mod -print0 | xargs -0 -L1 -I{} /bin/sh -c 'CGO_LDFLAGS=$(LDFLAGS) CGO_CPPFLAGS=$(CPPFLAGS) PKG_CONFIG_PATH=$(PKGCONF_PATH) "$(GOLANGCI_LINT_BIN)" run -c "$(GOLANGCI_LINT_CONFIG)"' \;

FIXERS += golangci-lint-fix
golangci-lint-fix: $(GOLANGCI_LINT_BIN)
	CGO_LDFLAGS=$(LDFLAGS) \
	CGO_CPPFLAGS=$(CPPFLAGS) \
	PKG_CONFIG_PATH=$(PKGCONF_PATH) \
	find . -maxdepth 1 -name go.mod -execdir "$(GOLANGCI_LINT_BIN)" run -c "$(GOLANGCI_LINT_CONFIG)" --fix \;

FIXERS += modernize
modernize:
	CGO_LDFLAGS=$(LDFLAGS) \
	CGO_CPPFLAGS=$(CPPFLAGS) \
	PKG_CONFIG_PATH=$(PKGCONF_PATH) \
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
	test -d out/$(YARA_X_REPO)/.git || git clone https://github.com/$(YARA_X_REPO).git out/$(YARA_X_REPO)
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
	RUSTFLAGS="-C target-feature=+crt-static" cargo cinstall -p yara-x-capi --features=native-code-serialization --profile release-lto --prefix="$(LINT_ROOT)/out" --libdir="$(LINT_ROOT)/out/lib" --crt-static --library-type="staticlib"

.PHONY: update-deps
update-deps:
	go get -u ./...
	go mod tidy

# unit tests only
.PHONY: test
test:
	CGO_LDFLAGS=$(LDFLAGS) \
	CGO_CPPFLAGS=$(CPPFLAGS) \
	PKG_CONFIG_PATH=$(PKGCONF_PATH) \
	go test -race ./pkg/...

FUZZ_TIME ?= 10s
.PHONY: fuzz
fuzz:
	@grep -r "^func Fuzz" --include="*_test.go" pkg/ | \
		awk -F'[:(]' '{gsub(/func /, "", $$2); dir=$$1; sub(/\/[^/]+$$/, "/", dir); print $$2, "./" dir}' | \
		while read -r func dir; do \
			echo "--- $$func ($$dir) ---"; \
			CGO_LDFLAGS=$(LDFLAGS) \
			CGO_CPPFLAGS=$(CPPFLAGS) \
			PKG_CONFIG_PATH=$(PKGCONF_PATH) \
			go test -timeout 0 -fuzz="^$$func$$" -fuzztime=$(FUZZ_TIME) "$$dir" || exit 1; \
		done

# fuzz tests - runs continuously (use Ctrl+C to stop)
# Usage: make fuzz-continuous FUZZ_TARGET=FuzzExtractArchive FUZZ_PKG=./pkg/archive/
FUZZ_TARGET ?= FuzzExtractArchive
FUZZ_PKG ?= ./pkg/archive/
.PHONY: fuzz-continuous
fuzz-continuous:
	CGO_LDFLAGS=$(LDFLAGS) \
	CGO_CPPFLAGS=$(CPPFLAGS) \
	PKG_CONFIG_PATH=$(PKGCONF_PATH) \
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
	CGO_LDFLAGS=$(LDFLAGS) \
	CGO_CPPFLAGS=$(CPPFLAGS) \
	PKG_CONFIG_PATH=$(PKGCONF_PATH) \
	go tool cover -html=$<

# generate the html report
out/coverage.html: out/mal.coverage
	CGO_LDFLAGS=$(LDFLAGS) \
	CGO_CPPFLAGS=$(CPPFLAGS) \
	PKG_CONFIG_PATH=$(PKGCONF_PATH) \
	go tool cover -html=$< -o $@

# we always want to regen the coverage data file
.PHONY: out/mal.coverage
out/mal.coverage:
	mkdir -p out
	CGO_LDFLAGS=$(LDFLAGS) \
	CGO_CPPFLAGS=$(CPPFLAGS) \
	PKG_CONFIG_PATH=$(PKGCONF_PATH) \
	go test -coverprofile $@ -race ./pkg/... -coverpkg ./pkg/...

# integration tests only
.PHONY: integration
integration: out/$(SAMPLES_REPO)/.decompressed-$(SAMPLES_COMMIT)
	CGO_LDFLAGS=$(LDFLAGS) \
	CGO_CPPFLAGS=$(CPPFLAGS) \
	PKG_CONFIG_PATH=$(PKGCONF_PATH) \
	go test -race -timeout 0 ./tests/...

.PHONY: bench
bench: out/$(SAMPLES_REPO)/.decompressed-$(SAMPLES_COMMIT)
	CGO_LDFLAGS=$(LDFLAGS) \
	CGO_CPPFLAGS=$(CPPFLAGS) \
	PKG_CONFIG_PATH=$(PKGCONF_PATH) \
	go test -run=^\$$ -bench=. ./... -benchmem

BENCH_CMD := CGO_LDFLAGS=$(LDFLAGS) CGO_CPPFLAGS=$(CPPFLAGS) PKG_CONFIG_PATH=$(PKGCONF_PATH) \
	go test -benchmem -run=^\$$ -bench ^BenchmarkRun\$$ github.com/chainguard-dev/malcontent/tests -args

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
	CGO_LDFLAGS=$(LDFLAGS) \
	CGO_CPPFLAGS=$(CPPFLAGS) \
	PKG_CONFIG_PATH=$(PKGCONF_PATH) \
	go build -o out/mal ./cmd/mal

.PHONY: update-third-party
update-third-party:
	./third_party/yara/update.sh

.PHONY: refresh-sample-testdata
refresh-sample-testdata: out/$(SAMPLES_REPO)/.decompressed-$(SAMPLES_COMMIT) out/mal
	MALCONTENT_UPX_PATH=$(shell which upx) ./out/mal refresh

ARCH ?= $(shell uname -m)
CRANE_VERSION=v0.21.0
out/crane-$(ARCH)-$(CRANE_VERSION):
	mkdir -p out
	GOBIN=$(CURDIR)/out go install github.com/google/go-containerregistry/cmd/crane@$(CRANE_VERSION)
	mv out/crane out/crane-$(ARCH)-$(CRANE_VERSION)

export-image: out/crane-$(ARCH)-$(CRANE_VERSION)
	./out/crane-$(ARCH)-$(CRANE_VERSION) \
	export \
	cgr.dev/chainguard/static:latest@sha256:bde549df44d5158013856a778b34d8972cf52bb2038ec886475d857ec7c365ed - | xz > pkg/action/testdata/static.tar.xz
