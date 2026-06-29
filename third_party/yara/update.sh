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
IFS=$'\n\t'

# Pinned SHA256 hashes for HTTPS-downloaded release artifacts, keyed by release tag.
# YARAForge does not publish a SHA256SUMS manifest or a sigstore signature for its
# release zips, so we pin the artifact hash directly (trust-on-first-use). To bump
# a dependency, run this script, copy the computed hash printed in the abort
# message, and append a new pinned entry below.
#
# yara-forge-rules-full.zip @ release tag 20260621
# shellcheck disable=SC2034  # referenced indirectly via ${!pin_var}
YARAFORGE_FULL_ZIP_SHA256_20260621="67d2f19fb6c174e532013f0ec13256aac267a9cd1276f648e0ec9a2241b50b8f"

# sha256_of computes the sha256 of a file using the platform-appropriate tool.
# Prints only the hex digest to stdout.
sha256_of() {
	local path=$1
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "${path}" | awk '{print $1}'
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "${path}" | awk '{print $1}'
	else
		echo "error: no sha256 tool available (need sha256sum or shasum)" >&2
		exit 3
	fi
}

# verify_pinned_sha256 aborts if the file at $1 does not match the pinned hex
# digest $2. $3 is a human-readable label for diagnostics.
verify_pinned_sha256() {
	local path=$1
	local expected=$2
	local label=$3
	local actual
	actual=$(sha256_of "${path}")
	if [[ "${actual}" != "${expected}" ]]; then
		echo "error: sha256 mismatch for ${label}" >&2
		echo "  expected: ${expected}" >&2
		echo "  actual:   ${actual}" >&2
		echo "  path:     ${path}" >&2
		echo "If the upstream release tag has been bumped, update the pinned" >&2
		echo "constant at the top of this script to the actual value above." >&2
		exit 4
	fi
	echo "verified sha256 for ${label}: ${actual}"
}

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

# fixup_rules fixes rules up, including lightly obfuscating them to avoid CrowdStrike/XProtect from matching malcontent
function fixup_rules() {
	perl -p -i -e 's#"/Library/Application Support\/Google/Chrome/Default/History"#/\\/Library\\/Application Support\\/Google\\/Chrome\\/Default\\/History\/#' "$@"
	perl -p -i -e 's#\/([a-z]{31})([a-z])\/#\/$1\[$2\]\/#;' "$@"
	# trailing spaces
	perl -p -i -e 's/ +$//;' "$@"
	# VirusTotal-specific YARA
	perl -p -i -e 's#and file_type contains \"\w+\"##;' "$@"
	# Convert text strings to hex in rules that trigger CrowdStrike/XProtect on macOS.
	# These rules contain malware signature strings that, when embedded in the mal binary
	# via go:embed, cause endpoint protection to kill the process or delete the binary.
	local edr_flagged_rules=(
		"Macos_Infostealer_Wallets.yar"
		"MacOS_Trojan_XScreen.yar"
	)
	for file in "$@"; do
		local base
		base="$(basename "$file")"
		for flagged in "${edr_flagged_rules[@]}"; do
			if [[ "$base" == "$flagged" ]]; then
				perl -i -pe 's/^(\s*)(\$\w+)\s*=\s*"([^"]+)"\s+ascii\s+\w+\s*$/sprintf("%s%s = { %s }\n", $1, $2, join(" ", map { sprintf "%02X", ord($_) } split(m{}, $3)))/e' "$file"
				break
			fi
		done
	done

	# Convert text strings to hex for specific rules inside monolithic YARA files.
	# Format: "rule_name:filename" pairs. The filename is matched against basename.
	local edr_flagged_monolithic_rules=(
		"SEKOIA_Infostealer_Mac_Realst:yara-rules-full.yar"
	)
	for file in "$@"; do
		local base
		base="$(basename "$file")"
		for entry in "${edr_flagged_monolithic_rules[@]}"; do
			local rule_name="${entry%%:*}"
			local target_file="${entry##*:}"
			if [[ "$base" == "$target_file" ]]; then
				perl -i -pe '
					BEGIN { $in_rule = 0; $in_strings = 0; }
					if (/^rule '"${rule_name}"' /) { $in_rule = 1; }
					if ($in_rule && /^\s+strings:/) { $in_strings = 1; next; }
					if ($in_rule && $in_strings && /^\s+condition:/) { $in_rule = 0; $in_strings = 0; next; }
					if ($in_rule && $in_strings) {
						s{^(\s*)(\$\w+)\s*=\s*"((?:[^"\\]|\\.)+)"\s+ascii(\s+\w+)?\s*$}{
							my ($ind, $var, $raw, $mod) = ($1, $2, $3, $4);
							$raw =~ s/\\(.)/$1/g;
							my $hex = join(" ", map { sprintf "%02X", ord($_) } split(//, $raw));
							sprintf("%s%s = { %s }%s\n", $ind, $var, $hex, defined($mod) ? $mod : "");
						}e;
					}
				' "$file"
			fi
		done
	done
}

# inline_includes flattens YARA `include "file"` directives in-place by
# splicing the referenced file's contents into each rule file. Included
# (shared) rules are rewritten to `private` so they act as building blocks
# without producing standalone matches in reports.
#
# malcontent compiles its embedded rules from memory (go:embed), where YARA's
# filesystem-based include resolution is unavailable, so includes must be
# flattened at vendoring time. See:
# https://virustotal.github.io/yara-x/docs/writing_rules/including-files/
function inline_includes() {
	local dir=$1
	local yar
	for yar in "${dir}"/*.yar; do
		[[ -e "${yar}" ]] || continue
		INLINE_DIR="${dir}" perl -i -ne '
			if (/^\s*include\s+"([^"]+)"/) {
				my $inc = $1;
				open(my $fh, "<", "$ENV{INLINE_DIR}/$inc")
					or die "inline_includes: cannot open $ENV{INLINE_DIR}/$inc: $!";
				while (my $line = <$fh>) {
					# Mark top-level (shared) rule declarations private.
					$line =~ s/^rule\s/private rule /;
					print $line;
				}
				close($fh);
			} else {
				print;
			}
		' "${yar}"
	done
}

# update_dep updates a dependency to the latest release
function update_dep() {
	local kind=$1
	local tmpdir=""
	local rel="unknown"

	tmpdir="$(mktemp -d)"

	mkdir -p "${kind}" || true

	case $kind in
	YARAForge)
		rel=$(latest_github_release YARAHQ/yara-forge)
		curl -L -o "${tmpdir}"/yaraforge.zip "https://github.com/YARAHQ/yara-forge/releases/download/${rel}/yara-forge-rules-full.zip"
		local pin_var="YARAFORGE_FULL_ZIP_SHA256_${rel}"
		local expected_sha=${!pin_var:-}
		if [[ -z "${expected_sha}" ]]; then
			local observed_sha
			observed_sha=$(sha256_of "${tmpdir}"/yaraforge.zip)
			echo "error: no pinned sha256 for YARAForge release tag ${rel}" >&2
			echo "  observed sha256: ${observed_sha}" >&2
			echo "Add the following line near the top of this script, then re-run:" >&2
			echo "  ${pin_var}=\"${observed_sha}\"" >&2
			exit 5
		fi
		verify_pinned_sha256 "${tmpdir}"/yaraforge.zip "${expected_sha}" "yara-forge-rules-full.zip@${rel}"
		unzip -o -j "${tmpdir}"/yaraforge.zip packages/full/yara-rules-full.yar -d "${kind}"
		;;
	huntress)
		rel=$(git_clone https://github.com/huntresslabs/threat-intel.git "${tmpdir}")
		find "${tmpdir}" \( -name "*.yar*" -o -name "*LICENSE*" \) -print -exec cp {} "${kind}" \;
		# error: rule "BOINC" in boinc.yar(1): syntax error, unexpected identifier, expecting '{'
		rm "${kind}"/boinc.yar
		# ^ expecting pattern modifier, pattern identifier or `condition`, found `}` (missing condition field)
		rm "${kind}"/defendnot_tool.yar
		;;
	InQuest-VT)
		rel=$(git_clone https://github.com/InQuest/yara-rules-vt.git "${tmpdir}")
		find "${tmpdir}" \( -name "*.yar*" -o -name "*LICENSE*" -o -name "README*" \) -print -exec cp {} "${kind}" \;
		;;
	bartblaze)
		rel=$(git_clone https://github.com/bartblaze/Yara-rules.git "${tmpdir}")
		cp -Rp "${tmpdir}"/LICENSE "${tmpdir}"/README.md "${tmpdir}"/rules/* "${kind}"/
		;;
	JPCERT)
		rel=$(git_clone https://github.com/JPCERTCC/jpcert-yara.git "${tmpdir}")
		find "${tmpdir}" \( -name "*.yar*" -o -name "*LICENSE*" -o -name "README*" \) -print -exec cp {} "${kind}" \;
		;;
	TTC-CERT)
		rel=$(git_clone https://github.com/ttc-cert/TTC-CERT-YARA-Rules.git "${tmpdir}")
		cp -Rp "${tmpdir}"/* "${kind}"/
		;;
	elastic)
	  rel=$(git_clone https://github.com/elastic/protections-artifacts.git "${tmpdir}")
		find "${tmpdir}" \( -name "*.yar*" -o -name "*LICENSE*" \) -print -exec cp {} "${kind}" \;
	  ;;
	guarddog)
		# GuardDog ships its YARA source-code rules on the v3 branch (no release
		# tag carries them yet); revisit this pin once v3 is tagged or merged.
		git clone --depth 1 --branch v3 https://github.com/DataDog/guarddog.git "${tmpdir}/repo"
		rel=$(git -C "${tmpdir}/repo" rev-parse HEAD)
		local src="${tmpdir}/repo/guarddog/analyzer/sourcecode"
		cp "${src}"/*.yar "${kind}"/
		# .meta sidecars hold shared private rules; copy them only if present
		# (guard the glob so `set -e` does not abort if upstream drops them).
		if compgen -G "${src}/*.meta" >/dev/null; then
			cp "${src}"/*.meta "${kind}"/
		fi
		cp "${tmpdir}/repo/LICENSE" "${tmpdir}/repo/NOTICE" "${kind}"/
		# Flatten `include` directives, then drop the now-inlined .meta files so
		# they are not embedded or compiled on their own.
		inline_includes "${kind}"
		rm -f "${kind}"/*.meta
		;;
	*)
		echo "unknown kind: ${kind}"
		exit 2
		;;
	esac

	fixup_rules "${kind}"/*.yar*
	echo "${rel}" > "${kind}"/RELEASE
	echo "updated ${kind} to ${rel}"
}

cd "$(dirname "$0")"

if [[ "$1" != "" ]]; then
	update_dep "$1"
else
	for dir in *; do
		if [[ -f "${dir}/RELEASE" ]]; then
			update_dep "${dir}"
		fi
	done
fi
