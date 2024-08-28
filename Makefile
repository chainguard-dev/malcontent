# Copyright 2024 Chainguard, Inc.
# SPDX-License-Identifier: Apache-2.0

# BEGIN: lint-install ../bincapz
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

LINTERS :=
FIXERS :=

GOLANGCI_LINT_CONFIG := $(LINT_ROOT)/.golangci.yml
GOLANGCI_LINT_VERSION ?= v1.60.1
GOLANGCI_LINT_BIN := $(LINT_ROOT)/out/linters/golangci-lint-$(GOLANGCI_LINT_VERSION)-$(LINT_ARCH)
$(GOLANGCI_LINT_BIN):
	mkdir -p $(LINT_ROOT)/out/linters
	rm -rf $(LINT_ROOT)/out/linters/golangci-lint-*
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(LINT_ROOT)/out/linters $(GOLANGCI_LINT_VERSION)
	mv $(LINT_ROOT)/out/linters/golangci-lint $@

LINTERS += golangci-lint-lint
golangci-lint-lint: $(GOLANGCI_LINT_BIN)
	find . -name go.mod -execdir "$(GOLANGCI_LINT_BIN)" run -c "$(GOLANGCI_LINT_CONFIG)" \;

FIXERS += golangci-lint-fix
golangci-lint-fix: $(GOLANGCI_LINT_BIN)
	find . -name go.mod -execdir "$(GOLANGCI_LINT_BIN)" run -c "$(GOLANGCI_LINT_CONFIG)" --fix \;

.PHONY: _lint $(LINTERS)
_lint: $(LINTERS)

.PHONY: fix $(FIXERS)
fix: $(FIXERS)

# END: lint-install ../bincapz

.PHONY: test
test: clone-samples
	go test $(shell go list ./... | grep -v test_data)

.PHONY: bench
bench:
	go test -run=^\$$ -bench=. ./... -benchmem

BENCH_CMD := go test -benchmem -run=^\$$ -bench ^BenchmarkRun\$$ github.com/chainguard-dev/bincapz/samples -args

.PHONY: bench-bincapz
bench-bincapz:
	$(BENCH_CMD) -path="macOS/clean/bincapz"

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

.PHONY: out/bincapz
out/bincapz:
	mkdir -p out
	go build -o out/bincapz .

.PHONY: update-third-party
update-third-party:
	./third_party/yara/update.sh

.PHONY: refresh-sample-testdata out/bincapz
refresh-sample-testdata: clone-samples out/bincapz
	cp ./test_data/refresh-testdata.sh samples/
	./samples/refresh-testdata.sh ./out/bincapz

.PHONY: clone-samples
clone-samples:
	rm -rf samples; git clone git@github.com:chainguard-dev/bincapz-samples.git samples
	cp -a test_data/. samples/
	for file in caddy.xz chezmoi.xz minio_x86_64.xz mongosh.xz neuvector_agent_aarch64.xz opa.xz ; do \
		tar -xJvf samples/linux/clean/$$file -C samples/linux/clean; \
	done
	tar -xJvf samples/macOS/clean/bincapz.xz -C samples/macOS/clean
