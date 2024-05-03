# Copyright 2024 Chainguard, Inc.
# SPDX-License-Identifier: Apache-2.0

# BEGIN: lint-install ../bincapz
# http://github.com/tinkerbell/lint-install

.PHONY: lint
lint: _lint

LINT_ARCH := $(shell uname -m)
LINT_DISTRO := $(shell cat /etc/*-release 2>/dev/null | grep '^ID=' | cut -d= -f2 | tr -d '"')
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

.PHONY: update-threathunting-keywords
update-threathunting-keywords:
	@current_sha=a21391e7280a4347dd7faebd7b5f54344b484ec7; \
	upstream_sha=$$(curl -s https://api.github.com/repos/mthcht/ThreatHunting-Keywords-yara-rules/commits/main | grep sha | head -n 1 | cut -d '"' -f 4); \
	if [ "$$current_sha" != "$$upstream_sha" ]; then \
		echo -e "ThreatHunting-Keywords-yara-rules has been updated to $$upstream_sha.\nPlease update the current_sha in the Makefile."; \
	else \
		echo "ThreatHunting-Keywords-yara-rules is up to date."; \
	fi; \
	curl -sL -o rules/third_party/mthcht_thk_yara_rules.yar https://raw.githubusercontent.com/mthcht/ThreatHunting-Keywords-yara-rules/$$current_sha/yara_rules/all.yara
# rewrite Chrome extension ID's to avoid XProtect matching bincapz
	perl -p -i -e 's#\/([a-z]{31})([a-z])\/#\/$$1\[$$2\]\/#;' rules/third_party/mthcht_thk_yara_rules.yar

.PHONY: yara-reqs
yara-reqs:
	@if [ "$(LINT_OS_LOWER)" = "darwin" ]; then \
		brew install automake bison flex gcc libtool m4 make pkg-config; \
	elif [ "$(LINT_OS_LOWER)" = "linux" ]; then \
		if [ "$(LINT_DISTRO)" = "ubuntu" ] || [ "$(LINT_DISTRO)" = "debian" ] || [ "$(LINT_DISTRO)" = "kali" ]; then \
			sudo apt-get -y update && sudo apt-get install -y automake bison flex gcc libtool libssl-dev make pkg-config; \
		elif [ "$(LINT_DISTRO)" = "centos" ] || [ "$(LINT_DISTRO)" = "redhat" ]; then \
			sudo yum -y update && sudo yum install -y automake bison flex gcc libtool make openssl-devel pkg-config; \
		elif [ "$(LINT_DISTRO)" = "fedora" ] || [ "$(LINT_DISTRO)" = "rocky" ]; then \
			sudo dnf -y update && sudo dnf install -y automake bison flex gcc libtool make openssl-devel pkg-config; \
		elif [ "$(LINT_DISTRO)" = "alpine" ]; then \
			sudo apk update && sudo apk add autoconf automake bison build-base flex gcc libtool linux-headers make openssl-dev pkgconf-dev; \
		elif [ "$(LINT_DISTRO)" = "wolfi" ]; then \
			apk update && apk add autoconf automake bison build-base curl flex gcc libtool linux-headers make openssl-dev pkgconf-dev sudo; \
		elif [ "$(LINT_DISTRO)" = "arch" ] || [ "$(LINT_DISTRO)" = "archarm" ]; then \
			sudo pacman -Syu --noconfirm autoconf automake bison flex gcc libtool make openssl pkgconf; \
			sudo mkdir -p /etc/ld.so.conf.d; \
			echo "/usr/local/lib" | sudo tee /etc/ld.so.conf.d/local.conf; \
		elif [ "$(LINT_DISTRO)" = "opensuse" ] || [ "$(LINT_DISTRO)" = "opensuse-leap" ]; then \
			sudo zypper refresh && sudo zypper install -y autoconf automake bison flex gcc libopenssl-devel libtool make pkg-config; \
		else \
			echo "Unsupported Linux distribution: $(LINT_DISTRO)"; \
		fi; \
	fi

.PHONY: build-yara
build-yara: yara-reqs
	@yara_release=4.3.2; \
	mkdir -p out; \
	curl -sL -o out/yara_$$yara_release.tar.gz https://github.com/VirusTotal/yara/archive/refs/tags/v$$yara_release.tar.gz; \
	tar -xzf out/yara_$$yara_release.tar.gz -C out; \
	cd out/yara-$$yara_release; \
	./bootstrap.sh; \
	./configure; \
	make; \
	sudo make install; \
	make check; \
	sudo ldconfig -v; \
	cd -; \
	rm -rf out/yara-$$yara_release out/yara_$$yara_release.tar.gz
