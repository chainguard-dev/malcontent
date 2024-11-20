#!/bin/bash
# find missing testdata
#
# usage:
#   ./missing-testdata.sh </path/to/SAMPLE_DIR>
#

set -e -u -o pipefail
SAMPLE_DIR=${1:-"$(dirname $0)/../../malcontent-samples"}

SAMPLE_DIR=$(realpath ${SAMPLE_DIR})

if [[ ! -d "${SAMPLE_DIR}/does-nothing" ]]; then
	echo "${SAMPLE_DIR} does not appear to be a valid sample directory, please pass one in on the command-line"
	exit 1
fi

for sample_path in $(find "${SAMPLE_DIR}/" -type f -size +100c); do
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
	relative="./${basename}"
	found=0
	for test_path in "${relative}".*; do
		if [[ -f "${test_path}" ]]; then
			found=1
		fi
	done

	if [[ "${found}" -eq 0 ]]; then
		dir=$(dirname ${relative})
		if [[ ! -d "${dir}" ]]; then
			echo "mkdir -p ${dir} && touch ${relative}.simple"
		else
			echo "touch ${relative}.simple"
		fi
	fi
done
