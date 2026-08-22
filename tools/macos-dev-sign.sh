#!/bin/sh
# Signs debug binaries with a stable local codesigning identity so macOS
# keychain ACLs survive rebuilds. Unsigned cargo binaries change identity on
# every build, which makes the keychain re-prompt for the caller credential
# on each access ("infinite keychain loop") and blocks headless callers.
#
# Usage: tools/macos-dev-sign.sh <binary> [binary...]
# Identity: $PAM_DEV_SIGN_IDENTITY, or the first valid codesigning identity.
set -eu

[ "$(uname)" = "Darwin" ] || exit 0

# Sign by certificate hash: names can be ambiguous when the same cert lives
# in more than one keychain.
identity="${PAM_DEV_SIGN_IDENTITY:-}"
if [ -z "$identity" ]; then
  identity=$(security find-identity -p codesigning -v \
    | awk '/[0-9]+\)/ { print $2; exit }')
fi
if [ -z "$identity" ]; then
  echo "macos-dev-sign: no codesigning identity found; skipping" >&2
  exit 0
fi

for binary in "$@"; do
  [ -f "$binary" ] || continue
  # Skip if already carrying a real (non-adhoc) signature; cargo relinks on
  # source changes, which resets the binary to adhoc.
  if codesign -dv "$binary" 2>&1 | grep -q "Authority="; then
    continue
  fi
  codesign --force --sign "$identity" "$binary"
done
