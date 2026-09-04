# Desktop glass materials

- `chaos.svg`: the exact SVG supplied by the user on 2026-09-04 for this
  treatment (1422 × 800, 28 paths, `ccchaos-grad`). It replaces the previous
  contour texture. No external references, scripts or embedded HTML are present.
- `chaos-soft.webp`: rendered with librsvg at 1422 × 800; its alpha channel is
  extracted and its empty margins trimmed, then Gaussian-blurred with sigma 5
  (half the original 10), normalized and encoded at quality 80. PAM uses
  **only the alpha** as one theme-tinted backdrop mask, stretched independently
  to 100% of the window width and height rather than preserving the original
  aspect ratio. This fills the window with the visible pattern instead of its
  empty margins, without runtime SVG filters or blur.

Source reference: <https://www.fffuel.co/ccchaos/>. The user supplied and
authorized this asset for PAM. No independent redistribution license was
provided: fffuel's published image terms restrict redistribution, so review
the asset rights before publishing the source or packaged app. These files
are not represented as CC0 or relicensed under PAM's code license.
The shell backdrop itself is a soft mask, not an optical refraction filter.

The single wave field is local, static and decorative. The user-supplied
photograph was an alternative, not a second layer, and is not included.
There is no additional grain, linework or second texture. No remote image
requests or animated turbulence run. The shell
animates only this layer's transform: an asymmetric inward zoom, sideways drift,
and opposite rotation on the return path, closing a four-minute loop at 1×.
Movement intensity (0–100%, default70%) scales travel, zoom and rotation independently
of speed; 100% peaks at1.5× zoom and turns from+3° to−4°. Zero keeps it still.
The speed fader runs from 0.5×
(eight minutes) to 12× (20 seconds, useful for previewing motion). Turning motion
off remembers the chosen speed. System reduced motion keeps it still;
reduced transparency hides the layer.
The opaque material preference, reduced-transparency media query and forced
colors remove the decorative layers.

## Bounded optical surfaces

`LiquidGlassBackdrop` uses the pinned MIT-licensed
[`@samasante/liquid-glass` 0.1.1](https://github.com/samasante/liquid-glass)
on the two Appearance control cards and the command/workspace dialogs. It
refracts a clipped, aligned copy of this same wave field with SVG displacement,
1.5px frost, edge highlights and a small RGB split. Copies join the shell's
animation phase; changing speed preserves that phase across all copies.
Only decorative pixels enter the filter: real text and controls remain outside
it, and the copied source is inert and hidden from assistive technology.

The filter stays at 1× resolution, with a 256px map and an 800 × 640px maximum
surface. Larger surfaces retain their normal material. Hidden/offscreen panes,
background windows, reduced transparency and forced colors unmount the renderer;
motion-off, zero intensity and reduced motion disable its live refresh loop.
Renderer failures preserve the normal material and functional controls.
Production CSP permits `data:` only in `img-src` for generated displacement maps;
script and network sources are unchanged.

Windows uses Tauri's Chromium-based WebView2; Linux uses distro-provided
WebKitGTK, while macOS uses WKWebView. Upstream reports Chromium/WebKit support,
but this integration has not been visually certified on these native webviews.
Its WebKit detection relies on a Safari user-agent token, which custom webviews
may lack. We explicitly use 1× resolution and copy-based refraction on all
platforms, not the Chromium-only arbitrary-backdrop path. Actual optical
fidelity and GPU cost still require platform testing.
