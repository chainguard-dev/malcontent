#!/bin/bash
# refresh testdata with latest bincapz
#
# usage:
#   ./refresh-testdata.sh </path/to/bincapz> </path/to/samples>
#
# NOTE: This is slow to run, so for small changes you are better
# off manually updating a single test file.

set -eu -o pipefail

MAX_PROCS=${MAX_PROCS:=8}
readonly bincapz=$(realpath $1)
readonly samples=$(realpath $2)

cd "$(dirname $0)"
cd ..
readonly root_dir=$(pwd)
readonly test_data="${root_dir}/test_data"

if [[ -z "${bincapz}" ]]; then
	echo "must pass location of bincapz"
	exit 1
fi

if [[ ! -x "${bincapz}" ]]; then
	echo "bincapz at ${bincapz} is not executable"
	exit 1
fi

readonly qscript=$(mktemp)
function addq() {
	echo "$*" >>"${qscript}"
}

# OCI edge case
cd "${root_dir}/pkg/action"
echo "regenerating test data, max_procs=${MAX_PROCS} ..."
${bincapz} --format=simple \
	--min-risk any \
	--min-file-risk any \
	-o testdata/scan_oci \
	analyze testdata/static.tar.xz &

${bincapz} --format simple \
    -o testdata/scan_archive \
    analyze testdata/apko_nested.tar.gz &

wait

cd "${samples}"

# diffs don't follow an easy rule
addq ${bincapz} --format=markdown \
	-o "${test_data}/macOS/2023.3CX/libffmpeg.dirty.mdiff" \
	diff \
	macOS/2023.3CX/libffmpeg.dylib \
	macOS/2023.3CX/libffmpeg.dirty.dylib

addq ${bincapz} --format=markdown \
	-o "${test_data}/macOS/clean/ls.mdiff" \
	diff \
	linux/clean/ls.x86_64 \
	macOS/clean/ls

addq ${bincapz} --format=simple \
	--min-level 2 \
	--min-file-level 2 \
	-o "${test_data}/macOS/clean/ls.sdiff.level_2" \
	diff \
	linux/clean/ls.x86_64 \
	macOS/clean/ls

addq ${bincapz} --format=simple \
	--min-level 1 \
	--min-file-level 2 \
	-o "${test_data}/macOS/clean/ls.sdiff.trigger_2" \
	diff \
	linux/clean/ls.x86_64 \
	macOS/clean/ls

addq ${bincapz} --format=simple \
	--min-level 1 \
	--min-file-level 3 \
	-o "${test_data}/macOS/clean/ls.sdiff.trigger_3" \
	diff \
	linux/clean/ls.x86_64 \
	macOS/clean/ls

addq ${bincapz} --format=simple \
	-o "${test_data}/linux/2024.sbcl.market/sbcl.sdiff" \
	diff \
	linux/2024.sbcl.market/sbcl.clean \
	linux/2024.sbcl.market/sbcl.dirty

addq ${bincapz} --format=simple \
	-o "${test_data}/linux/2023.FreeDownloadManager/freedownloadmanager.sdiff" \
	diff \
	linux/2023.FreeDownloadManager/freedownloadmanager_clear_postinst \
	linux/2023.FreeDownloadManager/freedownloadmanager_infected_postinst

addq ${bincapz} --format=simple \
	-o "${test_data}/linux/clean/aws-c-io/aws-c-io.sdiff" \
	diff \
	linux/clean/aws-c-io/aws-c-io-0.14.10-r0.spdx.json \
	linux/clean/aws-c-io/aws-c-io-0.14.11-r0.spdx.json

for f in $(find "${test_data}" -name "*.simple"); do
	prog=$(echo $f | sed -e s#"${test_data}/"## -e s#\.simple\$##)
	if [[ -f "${prog}" ]]; then
		addq ${bincapz} --format=simple -o "${f}" analyze "${prog}"
	fi
done

for f in $(find "${test_data}" -name "*.md"); do
	prog=$(echo $f | sed -e s#"${test_data}/"## -e s#\.md\$##)
	if [[ -f "${prog}" ]]; then
		addq ${bincapz} --format=markdown -o "${f}" analyze "${prog}"
	fi
done

for f in $(find "${test_data}" -name "*.json"); do
	prog=$(echo $f | sed -e s#"${test_data}/"## -e s#\.json\$##)
	if [[ -f "${prog}" ]]; then
		addq ${bincapz} --format=json -o "${f}" analyze "${prog}"
	fi
done

echo "processing queue with length: $(wc -l ${qscript})"
tr '\n' '\0' <"${qscript}" | xargs -0 -n1 -P"${MAX_PROCS}" -J% sh -c '%'
echo "test data regeneration complete!!"
