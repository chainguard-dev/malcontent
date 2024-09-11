#!/bin/bash
# refresh testdata with latest bincapz
#
# usage:
#   ./refresh-testdata.sh </path/to/bincapz>
#
# NOTE: This is slow to run, so for small changes you are better
# off manually updating a single test file.

set -ux -o pipefail

readonly bincapz=$(realpath $1)
readonly root_dir=$(dirname $0)
cd "${root_dir}"

if [[ -z "${bincapz}" ]]; then
    echo "must pass location of bincapz"
    exit 1
fi

if [[ ! -x "${bincapz}" ]]; then
    echo "bincapz at ${bincapz} is not executable"
    exit 1
fi

# OCI edge case
${bincapz} --format=simple \
    --min-risk any \
    --min-file-risk any \
    -o ../pkg/action/testdata/scan_oci \
    ../pkg/action/testdata/static.tar.xz; sed -i.bak 's|\.\.\/pkg\/action\/||g' ../pkg/action/testdata/scan_oci && rm ../pkg/action/testdata/scan_oci.bak &

# diffs don't follow an easy rule
${bincapz} --format=markdown \
    --diff \
    -o ../test_data/macOS/2023.3CX/libffmpeg.dirty.mdiff \
    macOS/2023.3CX/libffmpeg.dylib \
    macOS/2023.3CX/libffmpeg.dirty.dylib &

${bincapz} --format=markdown \
    --diff \
    -o ../test_data/macOS/clean/ls.mdiff \
    linux/clean/ls.x86_64 \
    macOS/clean/ls &

${bincapz} --format=simple \
    --diff \
    --min-level 2 \
    --min-file-level 2 \
    -o ../test_data/macOS/clean/ls.sdiff.level_2 \
    linux/clean/ls.x86_64 \
    macOS/clean/ls &

${bincapz} --format=simple \
    --diff \
    --min-level 1 \
    --min-file-level 2 \
    -o ../test_data/macOS/clean/ls.sdiff.trigger_2 \
    linux/clean/ls.x86_64 \
    macOS/clean/ls &

${bincapz} --format=simple \
    --diff \
    --min-level 1 \
    --min-file-level 3 \
    -o ../test_data/macOS/clean/ls.sdiff.trigger_3 \
    linux/clean/ls.x86_64 \
    macOS/clean/ls &

${bincapz} --format=simple \
    --diff \
    -o ../test_data/linux/2024.sbcl.market/sbcl.sdiff \
    linux/2024.sbcl.market/sbcl.clean \
    linux/2024.sbcl.market/sbcl.dirty &

${bincapz} --format=simple \
    --diff \
    -o ../test_data/linux/2023.FreeDownloadManager/freedownloadmanager.sdiff \
    linux/2023.FreeDownloadManager/freedownloadmanager_clear_postinst \
    linux/2023.FreeDownloadManager/freedownloadmanager_infected_postinst &

${bincapz} --format=simple \
    --diff \
    -o ../test_data/linux/clean/aws-c-io/aws-c-io.sdiff \
    linux/clean/aws-c-io/aws-c-io-0.14.10-r0.spdx.json \
    linux/clean/aws-c-io/aws-c-io-0.14.11-r0.spdx.json &
wait

for f in $(find * -name "*.simple"); do
    prog=$(echo ${f} | sed s/\.simple$//g)
    if [[ -f "${prog}" ]]; then
        ${bincapz} --format=simple -o "../test_data/${f}" "${prog}" &
    fi
done
wait

for f in $(find * -name "*.md"); do
    prog=$(echo ${f} | sed s/\.md$//g)
    if [[ -f "${prog}" ]]; then
        ${bincapz} --format=markdown -o "../test_data/${f}" "${prog}" &
    fi
done
wait

for f in $(find * -name "*.json"); do
    prog=$(echo ${f} | sed s/\.json$//g)
    if [[ -f "${prog}" ]]; then
        ${bincapz} --format=json -o "../test_data/${f}" "${prog}" &
    fi
done
wait
