#!/bin/bash
# helper script to find samples with missing testdata
#
# usage:
#   ./missing-testdata.sh </path/to/SAMPLE_DIR>
#

set -e -u -o pipefail
samples_rel_path="$(dirname $0)"
cd "${samples_rel_path}"
# assumes sample repo is checked out in directory above malcontent
SAMPLE_DIR=${1:-"../../malcontent-samples"}

# number of days to look back for missing testdata
AGE_IN_DAYS=30

SAMPLE_DIR=$(realpath ${SAMPLE_DIR})

if [[ ! -d "${SAMPLE_DIR}/does-nothing" ]]; then
	echo "${SAMPLE_DIR} does not appear to be a valid sample directory, please pass one in on the command-line"
	exit 1
fi

if [[ ! -f "does-nothing/does-nothing.simple" ]]; then
	echo "working directory $(pwd) does not appear to be a valid tests directory; missing does-nothing/does-nothing.simple"
	exit 1
fi

for sample_path in $(find "${SAMPLE_DIR}" -type f -mtime -"${AGE_IN_DAYS}" -size +100c); do
	if [[ "${sample_path}" =~ ".git" ]]; then
		continue
	fi

	if [[ "${sample_path}" =~ "README" ]]; then
		continue
	fi

	if [[ "${sample_path}" =~ ".txt" ]]; then
		continue
	fi

	if [[ "${sample_path}" =~ "LICENSE" ]]; then
		continue
	fi

	basename="${sample_path/${SAMPLE_DIR}\//}"
	basename="${basename%\.xz}"
	found=0
	for test_path in "${basename}".*; do
		if [[ -f "${test_path}" ]]; then
			found=1
		fi
	done

	relative="${samples_rel_path}/${basename}"

	if [[ "${found}" -eq 0 ]]; then
		real_dir=$(dirname ${basename})
		if [[ ! -d "${real_dir}" ]]; then
			rel_dir=$(dirname ${relative})
			echo "mkdir -p "${rel_dir}" && touch ${relative}.simple"
		else
			echo "touch ${relative}.simple"
		fi
	fi
done
