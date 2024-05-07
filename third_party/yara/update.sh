#!/bin/bash
# re-pin a third_party YARA dependency to the latest version
#
# usage:
#
#   Upgrade YARAForge rules:
#      ./update.sh YARAForge
#   Upgrade all third party rules:
#      ./update.sh

set -ex -o pipefail

# latest_github_release returns the most recent release tag for a GitHub project
latest_github_release() {
	local org_repo=$1
	basename "$(curl -Ls -o /dev/null -w "%{url_effective}" "https://github.com/${org_repo}/releases/latest")"

}

# fixup_rules fixes rules up, including lightly obfuscating them to avoid XProtect from matching bincapz
function fixup_rules() {
	perl -p -i -e 's#"/Library/Application Support\/Google/Chrome/Default/History"#/\\/Library\\/Application Support\\/Google\\/Chrome\\/Default\\/History\/#' "$@"
	perl -p -i -e 's#\/([a-z]{31})([a-z])\/#\/$1\[$2\]\/#;' "$@"
	# trailing spaces
	perl -p -i -e 's/ +$//;' "$@"
}

# update_dep updates a dependency to the latest release
function update_dep() {
	local kind=$1
	local tmpdir=$(mktemp -d)
	local rel="unknown"

	case $kind in
	YARAForge)
		rel=$(latest_github_release YARAHQ/yara-forge)
		curl -L -o "${tmpdir}/yaraforge.zip" "https://github.com/YARAHQ/yara-forge/releases/download/${rel}/yara-forge-rules-full.zip"
		unzip -o -j "${tmpdir}/yaraforge.zip" packages/full/yara-rules-full.yar -d "${kind}"
		;;
	huntress)
		git clone https://github.com/huntresslabs/threat-intel.git "${tmpdir}"
		pushd "${tmpdir}" || exit 1
		rel="$(git rev-parse head)"
		popd || exit 1
		find "${tmpdir}" \( -name "*.yar*" -o -name "*LICENSE*" \) -print -exec cp {} "${kind}" \;
		;;
	threat_hunting_keywords)
		rel=$(latest_github_release mthcht/ThreatHunting-Keywords-yara-rules)
		curl -L -o "${tmpdir}/keywords.zip" "https://github.com/mthcht/ThreatHunting-Keywords-yara-rules/archive/refs/tags/${rel}.zip"
		unzip -o -j "${tmpdir}/keywords.zip" ThreatHunting-Keywords-yara-rules-1.0.1/yara_rules/all.yara -d "${kind}"
		;;
	*)
		echo "unknown kind: ${kind}"
		exit 2
		;;
	esac

	fixup_rules ${kind}/*.yar* # nolint
	echo "${rel}" >"${kind}/RELEASE"
	echo "updated ${kind} to ${rel}"
}

if [[ "$1" != "" ]]; then
	update_dep "$1"
else
	for dir in *; do
		if [[ -f "${dir}/RELEASE" ]]; then
			update_dep "${dir}"
		fi
	done
fi
