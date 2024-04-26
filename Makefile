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
GOLANGCI_LINT_VERSION ?= v1.56.2
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
	go test ./... -v

.PHONY: update-yaraforge
update-yaraforge:
	mkdir -p out
	curl -sL -o out/yaraforge.zip https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-full.zip
	unzip -o -j out/yaraforge.zip packages/full/yara-rules-full.yar -d rules/third_party/


.PHONY: update-huntress
update-huntress:
	mkdir -p out
	curl -sL -o out/huntress.zip https://github.com/huntresslabs/threat-intel/archive/refs/heads/main.zip
	unzip -o out/huntress.zip -d rules/third_party/huntress/
	mv rules/third_party/huntress/threat-intel-main/* rules/third_party/huntress/
	mv rules/third_party/huntress/2*/2* rules/third_party/huntress/
	find rules/third_party/huntress -name "*.yml" -delete
	find rules/third_party/huntress -name "*.ps1" -delete
	find rules/third_party/huntress -name ".*" -type f -delete
	find rules/third_party/huntress -type d -delete

