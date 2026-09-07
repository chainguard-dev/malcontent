#!/usr/bin/env bash
# Copyright 2026 Chainguard, Inc.
# SPDX-License-Identifier: Apache-2.0

# hack/update_tool.sh - Update a pinned developer tool in the Makefile
#
# Usage: hack/update_tool.sh <golangci-lint|crane> <version>
# Example: hack/update_tool.sh golangci-lint v2.13.2
#
# Before touching the Makefile the script checks that the version is a
# published, non-prerelease GitHub release, that its commit carries a
# signature GitHub marks as verified, and that the commit is on the
# project's default branch. A tag that fails any check is refused.
#
# golangci-lint: downloads install.sh at the release commit, shows how it
#   differs from the currently pinned copy, asks for confirmation, and rewrites
#   GOLANGCI_LINT_VERSION, GOLANGCI_LINT_INSTALL_REF and
#   GOLANGCI_LINT_INSTALL_SHA256. Set UPDATE_TOOL_YES=1 to skip the prompt.
# crane: rewrites CRANE_VERSION. `go install` verifies the module against the
#   Go checksum database when the binary is built.
#
# Prerequisites: gh, curl, diff

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MAKEFILE="${REPO_ROOT}/Makefile"

TOOL="${1:-}"
VERSION="${2:-}"
if [[ -z "${TOOL}" || -z "${VERSION}" ]]; then
    echo "Usage: $0 <golangci-lint|crane> <version>" >&2
    echo "Example: $0 golangci-lint v2.13.2" >&2
    exit 1
fi

# Normalize to a leading 'v' and insist on a plain semantic version.
VERSION="v${VERSION#v}"
if [[ ! "${VERSION}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "error: ${VERSION} is not a release version (expected vX.Y.Z)" >&2
    exit 1
fi

# ---- Portable sha256 ----
sha256() {
    if command -v sha256sum &>/dev/null; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

# ---- Portable sed -i ----
sed_inplace() {
    if [[ "$(uname)" == "Darwin" ]]; then
        sed -i '' "$@"
    else
        sed -i "$@"
    fi
}

# makefile_var prints the current value of a Makefile variable.
makefile_var() {
    sed -nE "s/^$1 *(\?=|:=|=) *//p" "${MAKEFILE}" | head -1
}

# set_var rewrites `NAME <op> value` in the Makefile, keeping the operator.
set_var() {
    local name=$1 value=$2
    if ! grep -qE "^${name} *(\?=|:=|=)" "${MAKEFILE}"; then
        echo "error: ${name} not found in Makefile" >&2
        exit 1
    fi
    sed_inplace -E "s#^(${name} *(\?=|:=|=) *).*\$#\1${value}#" "${MAKEFILE}"
    echo "    ${name} = ${value}"
}

# verified_release_commit checks that <tag> is a published release of <repo>
# whose commit is verified and reachable from the default branch, then prints
# the commit SHA.
verified_release_commit() {
    local repo=$1 tag=$2 release type sha verification branch ancestry
    if ! release=$(gh api "repos/${repo}/releases/tags/${tag}" --jq '"\(.draft) \(.prerelease) \(.published_at)"' 2>/dev/null); then
        echo "error: ${tag} is not a published release of ${repo}" >&2
        exit 1
    fi
    read -r draft prerelease published <<<"${release}"
    if [[ "${draft}" != "false" || "${prerelease}" != "false" ]]; then
        echo "error: ${tag} is a draft or prerelease (draft=${draft} prerelease=${prerelease})" >&2
        exit 1
    fi

    type=$(gh api "repos/${repo}/git/ref/tags/${tag}" --jq '.object.type')
    sha=$(gh api "repos/${repo}/git/ref/tags/${tag}" --jq '.object.sha')
    if [[ "${type}" == "tag" ]]; then
        sha=$(gh api "repos/${repo}/git/tags/${sha}" --jq '.object.sha')
    fi

    verification=$(gh api "repos/${repo}/commits/${sha}" --jq '"\(.commit.verification.verified) \(.commit.verification.reason)"')
    if [[ "${verification}" != "true valid" ]]; then
        echo "error: commit ${sha} for ${tag} is not verified by GitHub (${verification})" >&2
        exit 1
    fi

    branch=$(gh api "repos/${repo}" --jq '.default_branch')
    ancestry=$(gh api "repos/${repo}/compare/${branch}...${sha}" --jq '.status')
    if [[ "${ancestry}" != "identical" && "${ancestry}" != "behind" ]]; then
        echo "error: commit ${sha} for ${tag} is not on ${repo}'s ${branch} branch (${ancestry})" >&2
        exit 1
    fi

    echo "    release ${tag} published ${published}" >&2
    echo "    commit ${sha}: signature verified, on ${branch}" >&2
    echo "${sha}"
}

# confirm shows a diff of the installer and asks before continuing, unless
# UPDATE_TOOL_YES is set.
confirm_installer_change() {
    local old=$1 new=$2
    if cmp -s "${old}" "${new}"; then
        echo "    install.sh unchanged from the pinned copy"
        return
    fi
    echo "    install.sh differs from the pinned copy:"
    diff -u "${old}" "${new}" | sed 's/^/    /' || true
    if [[ "${UPDATE_TOOL_YES:-}" == "1" ]]; then
        return
    fi
    if [[ ! -t 0 ]]; then
        echo "error: install.sh changed and stdin is not a terminal; review the diff and re-run with UPDATE_TOOL_YES=1" >&2
        exit 1
    fi
    read -r -p "    Apply this install.sh? [y/N] " answer
    if [[ "${answer}" != "y" && "${answer}" != "Y" ]]; then
        echo "aborted" >&2
        exit 1
    fi
}

echo "==> Updating ${TOOL} to ${VERSION}"
case "${TOOL}" in
golangci-lint)
    COMMIT=$(verified_release_commit golangci/golangci-lint "${VERSION}")
    TMPDIR_UPDATE=$(mktemp -d)
    trap 'rm -rf "${TMPDIR_UPDATE}"' EXIT
    curl -sSfL "https://raw.githubusercontent.com/golangci/golangci-lint/$(makefile_var GOLANGCI_LINT_INSTALL_REF)/install.sh" -o "${TMPDIR_UPDATE}/install-old.sh"
    curl -sSfL "https://raw.githubusercontent.com/golangci/golangci-lint/${COMMIT}/install.sh" -o "${TMPDIR_UPDATE}/install-new.sh"
    confirm_installer_change "${TMPDIR_UPDATE}/install-old.sh" "${TMPDIR_UPDATE}/install-new.sh"
    set_var GOLANGCI_LINT_VERSION "${VERSION}"
    set_var GOLANGCI_LINT_INSTALL_REF "${COMMIT}"
    set_var GOLANGCI_LINT_INSTALL_SHA256 "$(sha256 "${TMPDIR_UPDATE}/install-new.sh")"
    echo "==> Done. Verify with: make golangci-lint-lint"
    ;;
crane)
    verified_release_commit google/go-containerregistry "${VERSION}" >/dev/null
    set_var CRANE_VERSION "${VERSION}"
    echo "==> Done. Verify with: make out/crane-\$(uname -m)-${VERSION}"
    ;;
*)
    echo "error: unknown tool ${TOOL} (expected golangci-lint or crane)" >&2
    exit 1
    ;;
esac
