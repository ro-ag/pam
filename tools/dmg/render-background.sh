#!/usr/bin/env bash
# Re-renders background.svg into the two PNG renditions that ship inside the
# disk image. Authoring-time only: both PNGs are committed, so neither
# package-macos-dmg.sh nor the release workflow ever needs this script.
set -euo pipefail

fail() {
    printf 'render-background: %s\n' "$1" >&2
    exit 1
}

readonly here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly source="$here/background.svg"
readonly width=660
readonly height=420
[[ -f "$source" ]] || fail 'background.svg is missing'

if command -v rsvg-convert >/dev/null 2>&1; then
    rsvg-convert -w "$width" -h "$height" "$source" -o "$here/background.png"
    rsvg-convert -w $((width * 2)) -h $((height * 2)) "$source" -o "$here/background@2x.png"
else
    # AppKit has read SVG since Ventura, so a stock Mac with the developer
    # tools can render the art with nothing installed. It matches
    # rsvg-convert to within antialiasing. Quick Look also previews SVG, but
    # it thumbnails into a square and does not hold the aspect, so it is no
    # use for producing an exact rendition.
    scratch="$(mktemp -d)"
    trap 'rm -rf -- "$scratch"' EXIT
    cat >"$scratch/render.swift" <<'SWIFT'
import AppKit

let source = URL(fileURLWithPath: CommandLine.arguments[1])
let destination = URL(fileURLWithPath: CommandLine.arguments[2])
let width = Int(CommandLine.arguments[3])!
let height = Int(CommandLine.arguments[4])!
guard let artwork = NSImage(contentsOf: source) else {
    FileHandle.standardError.write(Data("AppKit could not read the artwork\n".utf8))
    exit(1)
}
guard let canvas = NSBitmapImageRep(
    bitmapDataPlanes: nil, pixelsWide: width, pixelsHigh: height,
    bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
    colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0
) else { exit(1) }
canvas.size = NSSize(width: width, height: height)
NSGraphicsContext.saveGraphicsState()
NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: canvas)
artwork.draw(in: NSRect(x: 0, y: 0, width: width, height: height),
             from: .zero, operation: .copy, fraction: 1)
NSGraphicsContext.restoreGraphicsState()
guard let png = canvas.representation(using: .png, properties: [:]) else { exit(1) }
try png.write(to: destination)
SWIFT
    command -v xcrun >/dev/null 2>&1 ||
        fail 'install librsvg (rsvg-convert) or the Xcode command line tools to render the artwork'
    xcrun swift "$scratch/render.swift" "$source" "$here/background.png" "$width" "$height"
    xcrun swift "$scratch/render.swift" "$source" "$here/background@2x.png" \
        $((width * 2)) $((height * 2))
fi

printf 'render-background: wrote %s and %s\n' "$here/background.png" "$here/background@2x.png"
