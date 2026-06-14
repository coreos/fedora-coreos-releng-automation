#!/bin/bash
# make-update-graph-ostree-repo-tarball.sh
#
# Collects OSTree commits for all unique target versions in the
# Fedora CoreOS update graph and packages them into a tarball.
#
# Usage:
#   ./make-update-graph-ostree-repo-tarball.sh <architecture> <stream>
#
# Examples:
#   ./make-update-graph-ostree-repo-tarball.sh x86_64 stable
#
#   OR 
#
#   STREAMS='stable testing next'
#   ARCHES='aarch64 ppc64le s390x x86_64'
#   mkdir -p fedora && pushd fedora
#   for stream in $STREAMS; do
#       for arch in $ARCHES; do
#           ./make-update-graph-ostree-repo-tarball.sh ${arch} ${stream}
#           rm -rf ./repo/
#       done
#   done
#
#
# Then upload with something like:
#   aws s3 sync --no-overwrite ./ s3://fcos-upgrade-test-fixtures/


set -euo pipefail

# --- Validate inputs ---

if [[ $# -ne 2 ]]; then
    echo "Usage: $0 <architecture> <stream>"
    echo "  architecture: e.g. x86_64, aarch64"
    echo "  stream:       e.g. stable, testing, next"
    exit 1
fi

ARCH="$1"
STREAM="$2"

# --- Check required tools ---

for cmd in curl jq ostree tar; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "Error: required command '$cmd' not found in PATH"
        exit 1
    fi
done

# --- Fetch the update graph ---

GRAPH_URL="https://updates.coreos.fedoraproject.org/v1/graph?basearch=${ARCH}&stream=${STREAM}&oci=false"

echo "Fetching update graph from: ${GRAPH_URL}"
GRAPH_JSON=$(curl -sSf "$GRAPH_URL")

# --- Extract unique target versions (>= 32) from graph edges ---
#
# The graph has "nodes" (array of objects with .version) and "edges"
# (array of [from_index, to_index] pairs). We collect unique
# destination indices, map them to versions, and filter to major
# version >= 32.

TARGET_VERSIONS=$(echo "$GRAPH_JSON" | jq -r '
    .nodes as $nodes |
    [.edges[][1]] | unique | .[] |
    $nodes[.].version
' | while IFS= read -r version; do
    major="${version%%.*}"
    if [[ "$major" -ge 32 ]] 2>/dev/null; then
        echo "$version"
    fi
done)

if [[ -z "$TARGET_VERSIONS" ]]; then
    echo "Error: no target versions with major version >= 32 found in update graph"
    exit 1
fi

echo ""
echo "Target versions in update graph (major version >= 32):"
echo "$TARGET_VERSIONS" | while IFS= read -r v; do
    echo "  $v"
done

# --- Fetch releases.json ---

RELEASES_URL="https://builds.coreos.fedoraproject.org/prod/streams/${STREAM}/releases.json"

echo ""
echo "Fetching releases.json from: ${RELEASES_URL}"
RELEASES_JSON=$(curl -sSf "$RELEASES_URL")

# --- Cross-reference versions with releases.json to find commits ---
#
# releases.json has:
#   .releases[] | { .version, .commits[] | { .architecture, .checksum } }
#
# We look up each target version and find the commit checksum for the
# requested architecture. We store the results in an associative array
# mapping version -> commit hash.

declare -A VERSION_TO_COMMIT=()

echo ""
echo "Resolving commits for each target version:"
while IFS= read -r version; do
    commit=$(echo "$RELEASES_JSON" | jq -r \
        --arg version "$version" \
        --arg arch "$ARCH" \
        '.releases[] | select(.version == $version) |
         .commits[] | select(.architecture == $arch) |
         .checksum')

    if [[ -z "$commit" ]]; then
        echo "  Warning: no commit found for version ${version} / arch ${ARCH}, skipping"
        continue
    fi

    echo "  ${version} -> ${commit}"
    VERSION_TO_COMMIT["$version"]="$commit"
done <<< "$TARGET_VERSIONS"

if [[ ${#VERSION_TO_COMMIT[@]} -eq 0 ]]; then
    echo "Error: no commits resolved for any target version"
    exit 1
fi

echo ""
echo "Total commits to pull: ${#VERSION_TO_COMMIT[@]}"

# --- Sort versions in descending order ---
#
# We walk from newest to oldest, creating a cumulative tarball each
# time the Fedora major version changes. Each tarball includes all
# commits pulled so far.

SORTED_VERSIONS=$(for v in "${!VERSION_TO_COMMIT[@]}"; do echo "$v"; done | sort -rV)

# --- Initialize empty ostree repository ---

if [[ -d ./repo ]]; then
    echo "Error: ./repo directory already exists. Remove it first."
    exit 1
fi

echo ""
echo "Initializing ostree repository..."
mkdir ./repo
ostree --repo=./repo init --mode=archive
ostree --repo=./repo remote add fedora \
    https://kojipkgs.fedoraproject.org/ostree/repo/ \
    --set=gpgkeypath=/etc/pki/rpm-gpg/

# --- Lightweight pull of commit metadata for history of the branch ---

# The --commit-metadata-only keeps it lightweight. The --mirror means
# the fedora/${ARCH}/coreos/${STREAM} ref will get created in the local repo.
echo "Pulling lightweight commit history for branch fedora/${ARCH}/coreos/${STREAM}"
ostree --repo=./repo pull --mirror --commit-metadata-only --depth=-1 "fedora:fedora/${ARCH}/coreos/${STREAM}"

# --- Pull commits and create tarballs at major version boundaries ---

echo ""
echo "Pulling commits and creating tarballs..."

CURRENT_MAJOR=""
declare -a TARBALLS=()

while IFS= read -r version; do
    major="${version%%.*}"

    # If the major version changed and we have a previous major to
    # snapshot, create a tarball for it before moving on.
    if [[ -n "$CURRENT_MAJOR" && "$major" != "$CURRENT_MAJOR" ]]; then
        TARBALL="ostree-repo-${STREAM}-${ARCH}-starting-f${CURRENT_MAJOR}.tar"
        echo ""
        echo "Major version boundary: creating ${TARBALL}"
        tar -C ./repo/ -cf "$TARBALL" ./
        TARBALLS+=("$TARBALL")
    fi

    CURRENT_MAJOR="$major"
    commit="${VERSION_TO_COMMIT[$version]}"
    echo "  Pulling ${version} (${commit})..."
    ostree --repo=./repo pull fedora "$commit"
done <<< "$SORTED_VERSIONS"

# Create the final tarball for the last (oldest) major version
TARBALL="ostree-repo-${STREAM}-${ARCH}-starting-f${CURRENT_MAJOR}.tar"
echo ""
echo "Final major version: creating ${TARBALL}"
tar -C ./repo/ -cf "$TARBALL" ./
TARBALLS+=("$TARBALL")

# --- Summary ---

echo ""
echo "Done. Created ${#TARBALLS[@]} tarballs:"
for t in "${TARBALLS[@]}"; do
    echo "  $t"
done
echo ""
echo "Note: the ./repo directory still exists. You may want to remove it with:"
echo "  rm -rf ./repo"
