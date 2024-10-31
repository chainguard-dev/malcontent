# Copyright 2024 Chainguard, Inc.
# SPDX-License-Identifier: Apache-2.0

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

LINTERS :=
FIXERS :=

GOLANGCI_LINT_CONFIG := $(LINT_ROOT)/.golangci.yml
GOLANGCI_LINT_VERSION ?= v1.61.0
GOLANGCI_LINT_BIN := $(LINT_ROOT)/out/linters/golangci-lint-$(GOLANGCI_LINT_VERSION)-$(LINT_ARCH)
$(GOLANGCI_LINT_BIN):
	mkdir -p $(LINT_ROOT)/out/linters
	rm -rf $(LINT_ROOT)/out/linters/golangci-lint-*
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(LINT_ROOT)/out/linters $(GOLANGCI_LINT_VERSION)
	mv $(LINT_ROOT)/out/linters/golangci-lint $@

YARA_X_VERSION ?= v0.10.0
YARA_X_BIN := $(LINT_ROOT)/out/linters/yr
$(YARA_X_BIN):
	mkdir -p $(LINT_ROOT)/out/linters
	rm -rf $(LINT_ROOT)/out/linters/yr
	curl -sSfL https://github.com/VirusTotal/yara-x/releases/download/$(YARA_X_VERSION)/yara-x-$(YARA_X_VERSION)-$(LINT_ARCH)-$(LINT_PLATFORM)-$(LINT_OS_LOWER).gzip -o yara-x.gzip
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

.PHONY: _lint $(LINTERS)
_lint: $(LINTERS)

.PHONY: fix $(FIXERS)
fix: $(FIXERS)

# END: lint-install ../malcontent

SAMPLES_REPO ?= chainguard-dev/malcontent-samples
SAMPLES_COMMIT ?= ec1ba5f2dc0e1f7085a0af73aa0f6fb1043e7534
OUT_DIR=out/samples-$(SAMPLES_COMMIT).tmp
out/samples-$(SAMPLES_COMMIT):
	mkdir -p out
	xz --version
	git clone https://github.com/$(SAMPLES_REPO).git $(OUT_DIR)
	git -C $(OUT_DIR) checkout $(SAMPLES_COMMIT)
	@for file in $$(find $(OUT_DIR) -name "*.xz" -print0 | xargs -0 echo); do \
    dir=$$(dirname "$$file"); \
    base=$$(basename "$$file" .xz); \
    fullpath="$$dir/$$base"; \
    temp_path="$$fullpath".temp; \
    xz -dc "$$file" > "$$temp_path"; \
    if file "$$temp_path" | grep -q "POSIX tar archive"; then \
      if [ "$(shell uname)" = "Darwin" ]; then \
        tar xJvf "$$temp_path" -C $$(dirname "$$temp_path"); \
      elif [ "$(shell uname)" = "Linux" ]; then \
        tar xvf "$$temp_path" -C $$(dirname "$$temp_path"); \
      fi; \
      rm "$$temp_path"; \
    else \
      mv "$$temp_path" "$$fullpath"; \
    fi; \
    done
	mv $(OUT_DIR) $(basename $(OUT_DIR))

prepare-samples: out/samples-$(SAMPLES_COMMIT)
	cp -a test_data/. $(basename $(OUT_DIR))

.PHONY: test
test: prepare-samples
	go test ./out/samples-$(SAMPLES_COMMIT)
	go test ./pkg/...

.PHONY: bench
bench:
	go test -run=^\$$ -bench=. ./... -benchmem

BENCH_CMD := go test -benchmem -run=^\$$ -bench ^BenchmarkRun\$$ github.com/chainguard-dev/malcontent/samples -args

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

.PHONY: refresh-sample-testdata out/mal
refresh-sample-testdata: out/samples-$(SAMPLES_COMMIT) out/mal
	./test_data/refresh-testdata.sh ./out/mal out/samples-$(SAMPLES_COMMIT)

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
