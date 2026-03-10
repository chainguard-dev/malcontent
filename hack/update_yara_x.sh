#!/usr/bin/env bash
# Copyright 2026 Chainguard, Inc.
# SPDX-License-Identifier: Apache-2.0

# hack/update_yara_x.sh - Update yara-x to a new version
#
# Usage: hack/update_yara_x.sh <version>
# Example: hack/update_yara_x.sh 1.14.0
#
# This script:
#   1. Verifies both the release tag (v<version>) and Go tag (go/v<version>) exist
#   2. Gets the commit hash for the release tag
#   3. Downloads all platform release archives and computes SHA-256 checksums
#   4. Updates the Makefile (version, commit, SHAs)
#   5. Updates workflow files (YARA_X_RELEASE)
#   6. Updates go.mod + go.sum via go get + go mod tidy
#
# Prerequisites: gh, git, go

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

VERSION="${1:-}"
if [[ -z "${VERSION}" ]]; then
    echo "Usage: $0 <version>"
    echo "Example: $0 1.14.0"
    exit 1
fi

# Strip leading 'v' if provided
VERSION="${VERSION#v}"

YARA_X_GH_REPO="VirusTotal/yara-x"
RELEASE_TAG="v${VERSION}"
GO_TAG="go/v${VERSION}"

echo "==> Updating yara-x to ${VERSION}"

# ---- Check prerequisites ----
for cmd in gh git go; do
    if ! command -v "${cmd}" &>/dev/null; then
        echo "ERROR: ${cmd} is required but not found"
        exit 1
    fi
done

# ---- Verify tags exist ----
echo "==> Checking that release tag ${RELEASE_TAG} exists..."
if ! gh release view "${RELEASE_TAG}" --repo "${YARA_X_GH_REPO}" &>/dev/null; then
    echo "ERROR: Release ${RELEASE_TAG} not found at ${YARA_X_GH_REPO}"
    exit 1
fi

echo "==> Checking that Go tag ${GO_TAG} exists..."
if ! gh api "repos/${YARA_X_GH_REPO}/git/ref/tags/${GO_TAG}" &>/dev/null; then
    echo "ERROR: Go tag ${GO_TAG} not found at ${YARA_X_GH_REPO}"
    echo "The Go binding tag may not have been published yet."
    exit 1
fi

# ---- Get commit hash for release tag ----
echo "==> Getting commit hash for ${RELEASE_TAG}..."
TAG_TYPE=$(gh api "repos/${YARA_X_GH_REPO}/git/ref/tags/${RELEASE_TAG}" --jq '.object.type')
TAG_SHA=$(gh api "repos/${YARA_X_GH_REPO}/git/ref/tags/${RELEASE_TAG}" --jq '.object.sha')

if [[ "${TAG_TYPE}" == "tag" ]]; then
    # Annotated tag: dereference to get the commit
    COMMIT=$(gh api "repos/${YARA_X_GH_REPO}/git/tags/${TAG_SHA}" --jq '.object.sha')
else
    # Lightweight tag: already points to the commit
    COMMIT="${TAG_SHA}"
fi

if [[ -z "${COMMIT}" ]]; then
    echo "ERROR: Could not determine commit for ${RELEASE_TAG}"
    exit 1
fi
echo "    Commit: ${COMMIT}"

# ---- Portable sha256 ----
sha256() {
    if command -v sha256sum &>/dev/null; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

# ---- Download release archives and compute SHA-256 ----
PLATFORMS=(
    "aarch64-apple-darwin"
    "x86_64-apple-darwin"
    "aarch64-unknown-linux-gnu"
    "x86_64-unknown-linux-gnu"
)

WORK_DIR=$(mktemp -d)
trap 'rm -rf "${WORK_DIR}"' EXIT

echo "==> Downloading release archives..."
gh release download "${RELEASE_TAG}" \
    --repo "${YARA_X_GH_REPO}" \
    --pattern "yara-x-${RELEASE_TAG}-*.gz" \
    --dir "${WORK_DIR}"

DARWIN_ARM64_SHA=""
DARWIN_X86_SHA=""
LINUX_ARM64_SHA=""
LINUX_X86_SHA=""

for platform in "${PLATFORMS[@]}"; do
    archive="yara-x-${RELEASE_TAG}-${platform}.gz"
    filepath="${WORK_DIR}/${archive}"
    if [[ ! -f "${filepath}" ]]; then
        echo "ERROR: Expected asset ${archive} not found in release ${RELEASE_TAG}"
        exit 1
    fi
    sha=$(sha256 "${filepath}")
    echo "    ${archive}: ${sha}"

    case "${platform}" in
        aarch64-apple-darwin)      DARWIN_ARM64_SHA="${sha}" ;;
        x86_64-apple-darwin)       DARWIN_X86_SHA="${sha}" ;;
        aarch64-unknown-linux-gnu) LINUX_ARM64_SHA="${sha}" ;;
        x86_64-unknown-linux-gnu)  LINUX_X86_SHA="${sha}" ;;
    esac
done

# ---- Portable sed -i ----
sed_inplace() {
    if [[ "$(uname)" == "Darwin" ]]; then
        sed -i '' "$@"
    else
        sed -i "$@"
    fi
}

# ---- Update Makefile ----
echo "==> Updating Makefile..."
sed_inplace "s/^YARA_X_VERSION ?= v.*/YARA_X_VERSION ?= v${VERSION}/" Makefile
sed_inplace "s/^YARA_X_COMMIT ?= .*/YARA_X_COMMIT ?= ${COMMIT}/" Makefile

# Replace the 4 YARA_X_SHA values in order:
#   1. Darwin arm64
#   2. Darwin x86_64
#   3. Linux aarch64
#   4. Linux x86_64
awk \
    -v sha1="${DARWIN_ARM64_SHA}" \
    -v sha2="${DARWIN_X86_SHA}" \
    -v sha3="${LINUX_ARM64_SHA}" \
    -v sha4="${LINUX_X86_SHA}" \
    '{
        if ($0 ~ /YARA_X_SHA = [0-9a-f]{64}/) {
            count++
            if (count == 1) sub(/[0-9a-f]{64}/, sha1)
            else if (count == 2) sub(/[0-9a-f]{64}/, sha2)
            else if (count == 3) sub(/[0-9a-f]{64}/, sha3)
            else if (count == 4) sub(/[0-9a-f]{64}/, sha4)
        }
        print
    }' Makefile > "${WORK_DIR}/Makefile.tmp" && mv "${WORK_DIR}/Makefile.tmp" Makefile

# ---- Update workflow files ----
echo "==> Updating workflow files..."
WORKFLOW_FILES=(
    .github/workflows/codeql.yaml
    .github/workflows/fuzz.yaml
    .github/workflows/go-tests.yaml
    .github/workflows/style.yaml
    .github/workflows/third-party.yaml
)

for wf in "${WORKFLOW_FILES[@]}"; do
    if [[ -f "${wf}" ]]; then
        sed_inplace "s/YARA_X_RELEASE: \"[0-9.]*\"/YARA_X_RELEASE: \"${VERSION}\"/" "${wf}"
        echo "    Updated ${wf}"
    else
        echo "    WARNING: ${wf} not found, skipping"
    fi
done

# ---- Update go.mod + go.sum ----
echo "==> Updating go.mod..."
go get "github.com/VirusTotal/yara-x/go@v${VERSION}"
echo "==> Running go mod tidy..."
go mod tidy

echo ""
echo "==> Done! yara-x updated to ${VERSION}"
echo ""
echo "Updated files:"
echo "  - Makefile (version, commit, SHAs)"
for wf in "${WORKFLOW_FILES[@]}"; do
    echo "  - ${wf}"
done
echo "  - go.mod"
echo "  - go.sum"
echo ""
echo "Next steps:"
echo "  1. Review the changes: git diff"
echo "  2. Commit and open a PR"
