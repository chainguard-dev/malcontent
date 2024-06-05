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

# diffs don't follow an easy rule
${bincapz} --format=markdown \
    --diff \
    -o macOS/2023.3CX/libffmpeg.dirty.mdiff \
    macOS/2023.3CX/libffmpeg.dylib \
    macOS/2023.3CX/libffmpeg.dirty.dylib &

${bincapz} --format=markdown \
    --diff \
    -o macOS/clean/ls.mdiff \
    Linux/clean/ls.x86_64 \
    macOS/clean/ls &

${bincapz} --format=simple \
    --diff \
    --min-level 2 \
    --min-file-level 2 \
    -o macOS/clean/ls.sdiff.level_2 \
    Linux/clean/ls.x86_64 \
    macOS/clean/ls &

${bincapz} --format=simple \
    --diff \
    --min-level 1 \
    --min-file-level 2 \
    -o macOS/clean/ls.sdiff.trigger_2 \
    Linux/clean/ls.x86_64 \
    macOS/clean/ls &

${bincapz} --format=simple \
    --diff \
    --min-level 1 \
    --min-file-level 3 \
    -o macOS/clean/ls.sdiff.trigger_3 \
    Linux/clean/ls.x86_64 \
    macOS/clean/ls &

${bincapz} --format=simple \
    --diff \
    -o Linux/2024.sbcl.market/sbcl.sdiff \
    Linux/2024.sbcl.market/sbcl.clean \
    Linux/2024.sbcl.market/sbcl.dirty &

${bincapz} --format=simple \
    --diff \
    -o Linux/2023.FreeDownloadManager/freedownloadmanager.sdiff \
    Linux/2023.FreeDownloadManager/freedownloadmanager_clear_postinst \
    Linux/2023.FreeDownloadManager/freedownloadmanager_infected_postinst &

wait

for f in $(find * -name "*.simple"); do
    prog=$(echo ${f} | sed s/\.simple//g)
    ${bincapz} --format=simple -o "${f}" "${prog}" &
done
wait

for f in $(find * -name "*.md"); do
    prog=$(echo ${f} | sed s/\.md//g)
    ${bincapz} --format=markdown -o "${f}" "${prog}" &
done
wait

for f in $(find * -name "*.json"); do
    prog=$(echo ${f} | sed s/\.json//g)
    ${bincapz} --format=json -o "${f}" "${prog}" &
done
wait
