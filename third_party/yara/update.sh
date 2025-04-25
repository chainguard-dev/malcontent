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

# clone clones a git URL and returns the most recent commit
git_clone() {
	local repo=$1
	local dir="${tmpdir}"
	git clone "${repo}" "${dir}"
	pushd "${dir}" >/dev/null || exit 1
	git rev-parse HEAD
	popd >/dev/null || exit 1
}

# fixup_rules fixes rules up, including lightly obfuscating them to avoid XProtect from matching malcontent
function fixup_rules() {
	perl -p -i -e 's#"/Library/Application Support\/Google/Chrome/Default/History"#/\\/Library\\/Application Support\\/Google\\/Chrome\\/Default\\/History\/#' "$@"
	perl -p -i -e 's#\/([a-z]{31})([a-z])\/#\/$1\[$2\]\/#;' "$@"
	# trailing spaces
	perl -p -i -e 's/ +$//;' "$@"
	# VirusTotal-specific YARA
	perl -p -i -e 's#and file_type contains \"\w+\"##;' "$@"
	# Convert problematic string literals
	for file in "$@"; do
		if [[ "$(basename "$file")" == "Macos_Infostealer_Wallets.yar" ]]; then
			perl -p -i -e 'if (/^(\s*)(\$s\d+)\s*=\s*"([^"]+)"\s+ascii wide nocase$/) {
				my $indent = $1;
				my $var = $2;
				my $str = $3;
				my $hex = join(" ", map { sprintf "%02X", ord($_) } split(//, $str));
				$_ = "$indent$var = {$hex}\n";
			}' "$file"
		fi
	done
}

# update_dep updates a dependency to the latest release
function update_dep() {
	local kind=$1
	local tmpdir=$(mktemp -d)
	local rel="unknown"

	mkdir -p "${kind}" || true

	case $kind in
	YARAForge)
		rel=$(latest_github_release YARAHQ/yara-forge)
		curl -L -o "${tmpdir}/yaraforge.zip" "https://github.com/YARAHQ/yara-forge/releases/download/${rel}/yara-forge-rules-full.zip"
		unzip -o -j "${tmpdir}/yaraforge.zip" packages/full/yara-rules-full.yar -d "${kind}"
		;;
	huntress)
		rel=$(git_clone https://github.com/huntresslabs/threat-intel.git "${tmpdir}")
		find "${tmpdir}" \( -name "*.yar*" -o -name "*LICENSE*" \) -print -exec cp {} "${kind}" \;
		# error: rule "BOINC" in boinc.yar(1): syntax error, unexpected identifier, expecting '{'
		rm "${kind}/boinc.yar"
		;;
	InQuest-VT)
		rel=$(git_clone https://github.com/InQuest/yara-rules-vt.git "${tmpdir}")
		find "${tmpdir}" \( -name "*.yar*" -o -name "*LICENSE*" -o -name "README*" \) -print -exec cp {} "${kind}" \;
		;;
	bartblaze)
		rel=$(git_clone https://github.com/bartblaze/Yara-rules.git "${tmpdir}")
		cp -Rp ${tmpdir}/LICENSE ${tmpdir}/README.md ${tmpdir}/rules/* "${kind}/"
		;;
	JPCERT)
		rel=$(git_clone https://github.com/JPCERTCC/jpcert-yara.git "${tmpdir}")
		find "${tmpdir}" \( -name "*.yar*" -o -name "*LICENSE*" -o -name "README*" \) -print -exec cp {} "${kind}" \;
		;;
	TTC-CERT)
		rel=$(git_clone https://github.com/ttc-cert/TTC-CERT-YARA-Rules.git "${tmpdir}")
		cp -Rp ${tmpdir}/* "${kind}/"
		;;
	elastic)
	  rel=$(git_clone https://github.com/elastic/protections-artifacts.git "${tmpdir}")
		find "${tmpdir}" \( -name "*.yar*" -o -name "*LICENSE*" \) -print -exec cp {} "${kind}" \;
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

cd "$(dirname $0)"

if [[ "$1" != "" ]]; then
	update_dep "$1"
else
	for dir in *; do
		if [[ -f "${dir}/RELEASE" ]]; then
			update_dep "${dir}"
		fi
	done
fi
