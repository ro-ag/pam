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
This is a soft backdrop, not a true optical refraction filter.

The single wave field is local, static and decorative. The user-supplied
photograph was an alternative, not a second layer, and is not included.
There is no grain, linework or texture applied to individual cards.
No remote image requests, animated turbulence or runtime blur runs. The shell
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
