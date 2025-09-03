#!/bin/bash
set -euo pipefail

# This script promotes all changes from a development branch (like
# `testing-devel`) to a production branch (like `testing`) for the
# fedora-coreos-config repo.
#
# Usage: git checkout testing && /path/to/promote-config.sh testing-devel

main() {
    if [ $# -ne 1 ]; then
        fatal "usage: $0 <source-upstream-branch>"
    fi

    # use ls-files instead of `diff --exit-code` since we don't want untracked
    # files either
    if [ -n "$(git ls-files --modified --others)" ]; then
        fatal "repository has modified or untracked files; refusing to proceed"
    fi

    local src_branch=$1; shift
    local fetch_head head

    if [ -z "${LOCAL:-}" ]; then
        git fetch https://github.com/coreos/fedora-coreos-config "${src_branch}"
        fetch_head=$(git rev-parse FETCH_HEAD)
    else
        fetch_head=$(git rev-parse "${src_branch}")
    fi
    head=$(git rev-parse HEAD)

    # take all the changes from the src branch, including any submodules
    git reset --hard "${fetch_head}"
    git submodule update --init
    git reset "${head}"

    # except for manifest.yaml and build-args.conf
    git checkout -- manifest.yaml build-args.conf

    # also strip out the snoozes and warns in the denylist because we don't
    # want changes in the executed tests over time for production streams
    sed -E -i 's/^(\s+)((snooze:|warn:)\s+.*)/\1# \2 (disabled on promotion)/' kola-denylist.yaml

    # Add everything. If we happen to pick up a submodule, it's on purpose, so squash the warning.
    git -c advice.addEmbeddedRepo=false add -A
    if git diff --quiet --staged --exit-code; then
        echo "nothing to promote! exiting..."
        exit 0
    fi

    git commit -m "tree: promote changes from ${src_branch} at ${fetch_head}"
}

fatal() {
    echo "$@" >&2
    exit 1
}

main "$@"
