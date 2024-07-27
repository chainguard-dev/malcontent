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
GOLANGCI_LINT_VERSION ?= v1.58.0
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
test:
	go test ./...

.PHONY: bench
bench:
	go test -run=^\$$ -bench=. ./... -benchmem

.PHONY: bench-bincapz
bench-bincapz:
	go test -benchmem -run=^\$$ -bench ^BenchmarkRun\$$ github.com/chainguard-dev/bincapz/samples -args -path="macOS/clean/bincapz"

.PHONY: bench-all-samples
bench-all-samples:
	go test -benchmem -run=^\$$ -bench ^BenchmarkRun\$$ github.com/chainguard-dev/bincapz/samples -args -path=""

.PHONY: bench-does-nothing
bench-does-nothing:
	go test -benchmem -run=^\$$ -bench ^BenchmarkRun\$$ github.com/chainguard-dev/bincapz/samples -args -path="does-nothing"

.PHONY: bench-javascript
bench-javascript:
	go test -benchmem -run=^\$$ -bench ^BenchmarkRun\$$ github.com/chainguard-dev/bincapz/samples -args -path="Javascript"

.PHONY: bench-linux
bench-linux:
	go test -benchmem -run=^\$$ -bench ^BenchmarkRun\$$ github.com/chainguard-dev/bincapz/samples -args -path="Linux"

.PHONY: bench-macos
bench-macos:
	go test -benchmem -run=^\$$ -bench ^BenchmarkRun\$$ github.com/chainguard-dev/bincapz/samples -args -path="macOS"

.PHONY: bench-npm
bench-npm:
	go test -benchmem -run=^\$$ -bench ^BenchmarkRun\$$ github.com/chainguard-dev/bincapz/samples -args -path="NPM"

.PHONY: bench-php
bench-php:
	go test -benchmem -run=^\$$ -bench ^BenchmarkRun\$$ github.com/chainguard-dev/bincapz/samples -args -path="PHP"

.PHONY: bench-python
bench-python:
	go test -benchmem -run=^\$$ -bench ^BenchmarkRun\$$ github.com/chainguard-dev/bincapz/samples -args -path="Python"

.PHONY: bench-typescript
bench-typescript:
	go test -benchmem -run=^\$$ -bench ^BenchmarkRun\$$ github.com/chainguard-dev/bincapz/samples -args -path="TypeScript"

.PHONY: bench-windows
bench-windows:
	go test -benchmem -run=^\$$ -bench ^BenchmarkRun\$$ github.com/chainguard-dev/bincapz/samples -args -path="Windows"

.PHONY: out/bincapz
out/bincapz:
	mkdir -p out
	go build -o out/bincapz .

.PHONY: update-third-party
update-third-party:
	./third_party/yara/update.sh

.PHONY: refresh-sample-testdata out/bincapz
refresh-sample-testdata: out/bincapz
	./samples/refresh-testdata.sh ./out/bincapz
