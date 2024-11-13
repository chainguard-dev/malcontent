#!/bin/bash
# refresh testdata with latest malcontent
#
# usage:
#   ./refresh-testdata.sh </path/to/malcontent> </path/to/samples>
#
# NOTE: This is slow to run, so for small changes you are better
# off manually updating a single test file.

set -eu -o pipefail -x

MAX_PROCS=${MAX_PROCS:=8}
readonly malcontent=$(realpath $1)
readonly samples=$(realpath $2)

cd "$(dirname $0)"
cd ..
readonly root_dir=$(pwd)
readonly test_data="${root_dir}/tests"

if [[ -z "${malcontent}" || -z "${samples}" ]]; then
	echo "usage: ./refresh-testdata.sh /path/to/mal/binary /path/to/samples"
	exit 1
fi

if [[ ! -x "${malcontent}" ]]; then
	echo "malcontent at ${malcontent} is not executable"
	exit 1
fi


if [[ ! -d "${samples}" ]]; then
	echo "sample directory ${samples} does not exist"
	exit 1
fi

readonly qscript=$(mktemp)
function addq() {
	echo "$*" >>"${qscript}"
}

# OCI edge case
cd "${root_dir}/pkg/action"
echo "regenerating test data, max_procs=${MAX_PROCS} ..."
${malcontent} \
	--min-risk 0 \
	--min-file-risk 0 \
	--ignore-self=false \
	--format json \
	-o testdata/scan_oci \
	analyze testdata/static.tar.xz &

${malcontent} \
    --min-risk 0 \
    --min-file-risk 0 \
    --ignore-self=false \
    --format json \
    -o testdata/scan_archive \
    analyze testdata/apko_nested.tar.gz &

wait

cd "${samples}"

# diffs don't follow an easy rule
addq ${malcontent} --format=markdown \
	-o "${test_data}/macOS/2023.3CX/libffmpeg.dirty.mdiff" \
	diff \
	macOS/2023.3CX/libffmpeg.dylib \
	macOS/2023.3CX/libffmpeg.dirty.dylib

# --file-risk-change test cases
addq ${malcontent} --format=markdown \
	-o "${test_data}/macOS/2023.3CX/libffmpeg.change_increase.mdiff" \
	diff \
	--file-risk-change \
	macOS/2023.3CX/libffmpeg.dylib \
	macOS/2023.3CX/libffmpeg.dirty.dylib

addq ${malcontent} --format=markdown \
	-o "${test_data}/macOS/2023.3CX/libffmpeg.change_decrease.mdiff" \
	diff \
	--file-risk-change \
	macOS/2023.3CX/libffmpeg.dirty.dylib \
	macOS/2023.3CX/libffmpeg.dylib

addq ${malcontent} --format=markdown \
	-o "${test_data}/macOS/2023.3CX/libffmpeg.change_no_change.mdiff" \
	diff \
	--file-risk-change \
	macOS/2023.3CX/libffmpeg.dylib \
	macOS/2023.3CX/libffmpeg.dylib

addq ${malcontent} --format=markdown \
	-o "${test_data}/macOS/2023.3CX/libffmpeg.change_unrelated.mdiff" \
	diff \
	--file-risk-change \
	macOS/2023.3CX/libffmpeg.dylib \
	macOS/clean/ls \

# --file-risk-increase test cases
addq ${malcontent} --format=markdown \
	-o "${test_data}/macOS/2023.3CX/libffmpeg.increase.mdiff" \
	diff \
	--file-risk-increase \
	macOS/2023.3CX/libffmpeg.dylib \
	macOS/2023.3CX/libffmpeg.dirty.dylib

addq ${malcontent} --format=markdown \
	-o "${test_data}/macOS/2023.3CX/libffmpeg.no_change.mdiff" \
	diff \
	--file-risk-increase \
	macOS/2023.3CX/libffmpeg.dylib \
	macOS/2023.3CX/libffmpeg.dylib

addq ${malcontent} --format=markdown \
	-o "${test_data}/macOS/2023.3CX/libffmpeg.decrease.mdiff" \
	diff \
	--file-risk-increase \
	macOS/2023.3CX/libffmpeg.dirty.dylib \
	macOS/2023.3CX/libffmpeg.dylib

addq ${malcontent} --format=markdown \
	-o "${test_data}/macOS/2023.3CX/libffmpeg.increase_unrelated.mdiff" \
	diff \
	--file-risk-increase \
	macOS/clean/ls \
	macOS/2023.3CX/libffmpeg.dylib

addq ${malcontent} --format=markdown \
	-o "${test_data}/macOS/clean/ls.mdiff" \
	diff \
	linux/clean/ls.x86_64 \
	macOS/clean/ls

addq ${malcontent} --format=simple \
	--min-level 2 \
	--min-file-level 2 \
	-o "${test_data}/macOS/clean/ls.sdiff.level_2" \
	diff \
	linux/clean/ls.x86_64 \
	macOS/clean/ls

addq ${malcontent} --format=simple \
	--min-level 1 \
	--min-file-level 2 \
	-o "${test_data}/macOS/clean/ls.sdiff.trigger_2" \
	diff \
	linux/clean/ls.x86_64 \
	macOS/clean/ls

addq ${malcontent} --format=simple \
	--min-level 1 \
	--min-file-level 3 \
	-o "${test_data}/macOS/clean/ls.sdiff.trigger_3" \
	diff \
	linux/clean/ls.x86_64 \
	macOS/clean/ls

addq ${malcontent} --format=simple \
	-o "${test_data}/linux/2024.sbcl.market/sbcl.sdiff" \
	diff \
	linux/2024.sbcl.market/sbcl.clean \
	linux/2024.sbcl.market/sbcl.dirty

addq ${malcontent} --format=simple \
	-o "${test_data}/linux/2023.FreeDownloadManager/freedownloadmanager.sdiff" \
	diff \
	linux/2023.FreeDownloadManager/freedownloadmanager_clear_postinst \
	linux/2023.FreeDownloadManager/freedownloadmanager_infected_postinst

addq ${malcontent} --format=simple \
	-o "${test_data}/linux/clean/aws-c-io/aws-c-io.sdiff" \
	diff \
	linux/clean/aws-c-io/aws-c-io-0.14.10-r0.spdx.json \
	linux/clean/aws-c-io/aws-c-io-0.14.11-r0.spdx.json

addq ${malcontent} --format=markdown \
	-o "${test_data}/javascript/2024.lottie-player/lottie-player.min.js.mdiff" \
	diff \
	--file-risk-increase \
	javascript/clean/lottie-player.min.js \
	javascript/2024.lottie-player/lottie-player.min.js

for f in $(find "${test_data}" -name "*.simple"); do
	prog=$(echo $f | sed -e s#"${test_data}/"## -e s#\.simple\$##)
	if [[ -s "${prog}" ]]; then
		addq ${malcontent} --format=simple --min-file-risk=1 --min-risk=1 --ignore-tags=harmless -o "${f}" analyze "${prog}"
	else
		"*** ${prog} sample is empty or does not exist"
		exit 1
	fi
done

for f in $(find "${test_data}" -name "*.md"); do
	prog=$(echo $f | sed -e s#"${test_data}/"## -e s#\.md\$##)
	if [[ -s "${prog}" ]]; then
		addq ${malcontent} --format=markdown --min-file-risk=1 --min-risk=1 --ignore-tags=harmless -o "${f}" analyze "${prog}"
	else
		"*** ${prog} sample is empty or does not exist"
		exit 1
	fi
done

for f in $(find "${test_data}" -name "*.json"); do
	prog=$(echo $f | sed -e s#"${test_data}/"## -e s#\.json\$##)
	if [[ -s "${prog}" ]]; then
		addq ${malcontent} --format=json --min-file-risk=1 --min-risk=1 -o "${f}" analyze "${prog}"
	else
		"*** ${prog} sample is empty or does not exist"
		exit 1
	fi
done

echo "processing queue with length: $(wc -l ${qscript})"

# use -J on BSD platforms, as -I is limited to 128 arguments for compatibility
xargs_flag="-J"

if [[ "$(uname)" == "Linux" ]]; then
	xargs_flag="-I"
fi


tr '\n' '\0' <"${qscript}" | xargs -0 -n1 -P"${MAX_PROCS}" "${xargs_flag}%" sh -c '%'
echo "test data regeneration complete!!"
