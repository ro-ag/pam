#!/usr/bin/env bash
set -euo pipefail

fail() {
    printf 'package-macos-dmg: %s\n' "$1" >&2
    exit 1
}

note() {
    printf 'package-macos-dmg: %s\n' "$1" >&2
}

# Runs a command under a hard wall clock bound, because every step that touches
# a mounted volume is cosmetic and none of them may ever stall a release. macOS
# ships no coreutils timeout, so the bound is a watchdog process of our own.
run_bounded() {
    local limit="$1"
    shift
    "$@" &
    local job=$!
    (
        sleep "$limit"
        kill -9 "$job"
    ) >/dev/null 2>&1 &
    local watchdog=$!
    local status=0
    wait "$job" 2>/dev/null || status=$?
    kill "$watchdog" >/dev/null 2>&1 || true
    wait "$watchdog" 2>/dev/null || true
    return "$status"
}

[[ $# -eq 2 ]] || fail 'usage: package-macos-dmg.sh /absolute/pam.app /absolute/output-directory'
readonly app="$1"
readonly output_directory="$2"
[[ "$app" = /* && "$output_directory" = /* ]] || fail 'paths must be absolute'
[[ -d "$app/Contents/MacOS" ]] || fail 'the Pam application bundle is invalid'
mkdir -p "$output_directory"

readonly repository="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
readonly art="$repository/tools/dmg"
readonly volume_icon="$repository/crates/pam/icons/icon.icns"
readonly volume=Pam

readonly version="$(plutil -extract CFBundleShortVersionString raw "$app/Contents/Info.plist")"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]] || fail 'the bundle version is invalid'
readonly output="$output_directory/pam_${version}_aarch64.dmg"
stage="$(mktemp -d "$output_directory/.pam-dmg.XXXXXX")"
# mktemp is private to the caller; the volume root this becomes is not.
chmod 755 "$stage"
readonly writable="$stage.dmg"
readonly mountpoint="$stage.mount"
attached=''
cleanup() {
    if [[ -n "$attached" ]]; then
        run_bounded 30 hdiutil detach "$attached" -force -quiet >/dev/null 2>&1 || true
    fi
    rm -rf -- "$stage" "$mountpoint"
    rm -f -- "$writable"
}
trap cleanup EXIT

# The backdrop the Finder window paints behind the two icons. It is committed
# as a pair of PNG renditions (see tools/dmg/render-background.sh); tiffutil
# folds them into the one multi-resolution file AppKit picks the crisp variant
# out of on a Retina display. The name stays background.tiff either way,
# because the committed Finder layout resolves the picture by that path.
install_backdrop() {
    [[ -f "$art/background.png" ]] || return 1
    mkdir -p "$stage/.background"
    if [[ -f "$art/background@2x.png" ]] && command -v tiffutil >/dev/null 2>&1 &&
        tiffutil -cathidpicheck "$art/background.png" "$art/background@2x.png" \
            -out "$stage/.background/background.tiff" >/dev/null 2>&1; then
        return 0
    fi
    note 'tiffutil is unavailable, so the backdrop ships at 1x only'
    cp "$art/background.png" "$stage/.background/background.tiff"
}

# The window geometry, the hidden toolbar and sidebar, the 128pt icon size and
# the two icon positions all live in this .DS_Store, authored once against a
# real Finder (tools/dmg/author-layout.sh) and replayed here as a plain file
# copy. Nothing on this path talks to Finder, so it behaves the same on a
# GitHub runner, which has no window server for Finder to draw into.
install_layout() {
    [[ -f "$art/DS_Store" ]] || return 1
    cp "$art/DS_Store" "$stage/.DS_Store"
}

# A custom volume icon needs the icns at the volume root and the Finder flag
# that says to use it. hdiutil will not carry that flag over from the staging
# directory, so it has to be written onto the mounted volume: that is the only
# reason the image is built read-write first and converted afterwards.
brand_volume() {
    [[ -f "$stage/.VolumeIcon.icns" ]] || return 1
    mkdir -p "$mountpoint"
    run_bounded 120 hdiutil attach "$writable" -quiet -nobrowse -noautoopen \
        -mountpoint "$mountpoint" || return 1
    attached="$mountpoint"
    local flagged=0
    # SetFile comes with Xcode; where it is missing the same flag is written
    # straight into the Finder info of the volume root (kHasCustomIcon, 0x0400,
    # in the folder flags at byte 8 of the 32-byte record).
    if run_bounded 30 SetFile -a C "$mountpoint" 2>/dev/null ||
        run_bounded 30 xattr -wx com.apple.FinderInfo \
            '00000000000000000400000000000000 00000000000000000000000000000000' \
            "$mountpoint" 2>/dev/null; then
        flagged=1
    fi
    run_bounded 60 hdiutil detach "$mountpoint" -quiet >/dev/null 2>&1 ||
        run_bounded 30 hdiutil detach "$mountpoint" -force -quiet >/dev/null 2>&1 ||
        fail 'the staging volume could not be detached'
    attached=''
    ((flagged))
}

ditto "$app" "$stage/pam.app"
ln -s /Applications "$stage/Applications"
install_backdrop || note 'the backdrop art is missing, so the window keeps the Finder default'
install_layout || note 'the Finder layout is missing, so the window opens unstyled'
if [[ -f "$volume_icon" ]]; then
    cp "$volume_icon" "$stage/.VolumeIcon.icns"
fi

hdiutil create -quiet -volname "$volume" -srcfolder "$stage" -ov -format UDRW -fs HFS+ "$writable"
brand_volume || note 'the volume icon was skipped, so the disk mounts with a generic mark'
hdiutil convert "$writable" -quiet -format UDZO -ov -o "$output"
[[ -s "$output" ]] || fail 'hdiutil did not create a disk image'
printf '%s\n' "$output"
