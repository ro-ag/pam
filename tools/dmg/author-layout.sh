#!/usr/bin/env bash
# Regenerates tools/dmg/DS_Store, the Finder layout that package-macos-dmg.sh
# drops into every disk image it builds: window size and position, hidden
# toolbar and sidebar, 128pt icons pinned either side of the backdrop's arrow,
# and the backdrop itself.
#
# Authoring-time only, and it needs a logged-in Mac: it drives Finder over
# AppleScript against a scratch read-write image named exactly like the one
# the packaging script builds, then lifts the .DS_Store Finder wrote. A
# GitHub runner has no window server, so it never runs there -- that is the
# whole point of committing the result.
#
# Usage: author-layout.sh [/absolute/pam.app]
set -euo pipefail

fail() {
    printf 'author-layout: %s\n' "$1" >&2
    exit 1
}

readonly here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly volume=Pam
readonly mount="/Volumes/$volume"
# The design grid, shared with background.svg: a 660x420pt window with the two
# icons centred on y=250, either side of the coral arrow at x=330.
readonly window_width=660
readonly window_height=420
readonly icon_y=250
readonly app_x=165
readonly applications_x=495
# Stored window origin, in Finder's bottom-left screen coordinates. Chosen to
# sit fully on a 1440x900 display, the smallest Mac laptop screen still in use.
readonly origin_x=390
readonly origin_y=340

[[ -e "$mount" ]] && fail "$mount is already in use; eject it first"
[[ -f "$here/background.png" ]] || fail 'background.png is missing; run render-background.sh'

scratch="$(mktemp -d)"
image="$scratch/authoring.dmg"
stage="$scratch/stage"
cleanup() {
    hdiutil detach "$mount" -quiet 2>/dev/null || true
    rm -rf -- "$scratch"
}
trap cleanup EXIT

mkdir -p "$stage/.background"
if [[ $# -ge 1 ]]; then
    [[ -d "$1/Contents/MacOS" ]] || fail 'the application bundle is invalid'
    ditto "$1" "$stage/pam.app"
else
    # Finder keys icon positions by name, so a stub bundle lays out identically
    # to the real one; it only makes the authoring window look right.
    mkdir -p "$stage/pam.app/Contents/MacOS"
    printf '#!/bin/sh\nexit 0\n' >"$stage/pam.app/Contents/MacOS/pam"
    chmod +x "$stage/pam.app/Contents/MacOS/pam"
fi
ln -s /Applications "$stage/Applications"
if command -v tiffutil >/dev/null 2>&1 && [[ -f "$here/background@2x.png" ]]; then
    tiffutil -cathidpicheck "$here/background.png" "$here/background@2x.png" \
        -out "$stage/.background/background.tiff" >/dev/null
else
    cp "$here/background.png" "$stage/.background/background.tiff"
fi

hdiutil create -quiet -volname "$volume" -srcfolder "$stage" -ov -format UDRW -fs HFS+ "$image"
hdiutil attach "$image" -quiet -noautoopen -mountpoint "$mount"

# Finder's `bounds` are measured from the top of the screen while the value it
# stores is measured from the bottom, so the top edge has to be derived from
# the desktop height to make the committed origin reproducible anywhere.
desktop_height="$(osascript -e 'tell application "Finder" to get bounds of window of desktop' | awk -F', *' '{print $4}')"
top=$((desktop_height - window_height - origin_y))
((top >= 0)) || fail 'this display is too short to author the layout on'

osascript >/dev/null <<APPLESCRIPT
tell application "Finder"
  tell disk "$volume"
    open
    delay 1
    set current view of container window to icon view
    set toolbar visible of container window to false
    set statusbar visible of container window to false
    set the bounds of container window to {$origin_x, $top, $((origin_x + window_width)), $((top + window_height))}
    set viewOptions to the icon view options of container window
    set arrangement of viewOptions to not arranged
    set icon size of viewOptions to 128
    set text size of viewOptions to 12
    set label position of viewOptions to bottom
    set shows item info of viewOptions to false
    set shows icon preview of viewOptions to false
    set background picture of viewOptions to file ".background:background.tiff"
    set position of item "pam.app" of container window to {$app_x, $icon_y}
    set position of item "Applications" of container window to {$applications_x, $icon_y}
    delay 1
    update without registering applications
    delay 2
    close
  end tell
end tell
APPLESCRIPT

# Finder flushes the window state on unmount, so the settled copy has to be
# read from a fresh attach rather than from the volume it was just written on.
sync
hdiutil detach "$mount" -quiet
hdiutil attach "$image" -quiet -noautoopen -mountpoint "$mount"
[[ -f "$mount/.DS_Store" ]] || fail 'Finder did not write a layout'
cp "$mount/.DS_Store" "$here/DS_Store"
hdiutil detach "$mount" -quiet

printf 'author-layout: wrote %s\n' "$here/DS_Store"
