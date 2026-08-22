#!/bin/sh
# Cargo runner for macOS dev builds: signs the binary (and the sibling `pam`
# CLI/daemon binary, which the GUI spawns as its sidecar) with a stable
# identity before executing, so keychain ACLs survive rebuilds.
set -eu

binary="$1"
shift

dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
"$dir/macos-dev-sign.sh" "$binary" "$(dirname -- "$binary")/pam" || true

exec "$binary" "$@"
