#!/usr/bin/env bash
set -euo pipefail

fail() {
    printf 'package-macos-dmg: %s\n' "$1" >&2
    exit 1
}

[[ $# -eq 2 ]] || fail 'usage: package-macos-dmg.sh /absolute/PAM.app /absolute/output-directory'
readonly app="$1"
readonly output_directory="$2"
[[ "$app" = /* && "$output_directory" = /* ]] || fail 'paths must be absolute'
[[ -d "$app/Contents/MacOS" ]] || fail 'the PAM application bundle is invalid'
mkdir -p "$output_directory"

readonly version="$(plutil -extract CFBundleShortVersionString raw "$app/Contents/Info.plist")"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]] || fail 'the bundle version is invalid'
readonly output="$output_directory/PAM_${version}_aarch64.dmg"
stage="$(mktemp -d "$output_directory/.pam-dmg.XXXXXX")"
cleanup() {
    rm -rf -- "$stage"
}
trap cleanup EXIT

ditto "$app" "$stage/PAM.app"
ln -s /Applications "$stage/Applications"
hdiutil create -quiet -volname PAM -srcfolder "$stage" -ov -format UDZO "$output"
[[ -s "$output" ]] || fail 'hdiutil did not create a disk image'
printf '%s\n' "$output"
