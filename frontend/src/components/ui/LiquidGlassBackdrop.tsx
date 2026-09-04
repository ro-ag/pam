import { Glass, type GlassOptics } from "@samasante/liquid-glass";
import {
  Component,
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
  useSyncExternalStore,
  type ReactNode,
} from "react";
import { subscribeTheme, themeSnapshot } from "../../lib/theme";
import { subscribeWorkspace, workspaceSnapshot } from "../../lib/workspace";

const optics: Partial<GlassOptics> = {
  mapSize: 256,
  strength: 0.12,
  depth: 0.24,
  curvature: 0.35,
  bend: 0.65,
  bendWidth: 0.14,
  dispersion: 0.18,
  frost: 1.5,
  sheen: 0.45,
  sheenWidth: 2,
  glow: 0.08,
  brightness: 0,
};

/** A failed decorative renderer must never take the controls down with it. */
class GlassBoundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  state = { failed: false };
  static getDerivedStateFromError() {
    return { failed: true };
  }
  render() {
    return this.state.failed ? null : this.props.children;
  }
}

const reducedTransparency = "(prefers-reduced-transparency: reduce)";
const reducedMotion = "(prefers-reduced-motion: reduce)";
const forcedColors = "(forced-colors: active)";

function environmentSnapshot() {
  const matches = (query: string) => window.matchMedia?.(query).matches ?? false;
  return (
    Number(matches(reducedTransparency) || matches(forcedColors)) |
    (Number(matches(reducedMotion)) << 1) |
    (Number(document.hidden) << 2)
  );
}

function subscribeEnvironment(notify: () => void) {
  const queries = [reducedTransparency, reducedMotion, forcedColors].map((query) =>
    window.matchMedia?.(query),
  );
  queries.forEach((query) => {
    if (query?.addEventListener) query.addEventListener("change", notify);
    else query?.addListener?.(notify);
  });
  document.addEventListener("visibilitychange", notify);
  return () => {
    queries.forEach((query) => {
      if (query?.removeEventListener) query.removeEventListener("change", notify);
      else query?.removeListener?.(notify);
    });
    document.removeEventListener("visibilitychange", notify);
  };
}

/**
 * Decorative, bounded SVG refraction only. The parent's real controls are siblings,
 * never copied into or filtered by the library. Unsupported/large surfaces retain
 * their normal material; hidden panes and accessibility overrides stop the renderer.
 */
export function LiquidGlassBackdrop() {
  const host = useRef<HTMLDivElement>(null);
  const { material, backgroundMotion, backgroundSpeed, backgroundIntensity } =
    useSyncExternalStore(subscribeTheme, themeSnapshot);
  const environment = useSyncExternalStore(subscribeEnvironment, environmentSnapshot);
  const workspace = useSyncExternalStore(subscribeWorkspace, workspaceSnapshot);
  const [visible, setVisible] = useState(false);
  const [bounded, setBounded] = useState(false);
  const supported =
    typeof CSS !== "undefined" &&
    CSS.supports?.("filter", 'url("#pam-glass")') &&
    typeof ResizeObserver !== "undefined";
  const enabled = supported && material === "glass" && !(environment & 5) && visible && bounded;
  const live =
    enabled && !(environment & 2) && backgroundMotion !== "off" && backgroundIntensity > 0;

  useEffect(() => {
    const element = host.current!;
    if (typeof IntersectionObserver === "undefined") {
      setVisible(true);
      return;
    }
    const observer = new IntersectionObserver(([entry]) => setVisible(entry.isIntersecting));
    observer.observe(element);
    return () => observer.disconnect();
  }, []);

  useLayoutEffect(() => {
    const element = host.current!;
    const surface = element.parentElement!;
    const scene = document.querySelector<HTMLElement>(".desktop-shell");
    if (!supported || !scene) return;
    const measure = () => {
      const rect = element.getBoundingClientRect();
      const frame = scene.getBoundingClientRect();
      // Filter only this cropped region, never a 2K/4K source graphic.
      setBounded(rect.width > 0 && rect.height > 0 && rect.width <= 800 && rect.height <= 640);
      element.style.setProperty("--glass-scene-width", `${frame.width}px`);
      element.style.setProperty("--glass-scene-height", `${frame.height}px`);
      element.style.setProperty("--glass-scene-left", `${frame.left - rect.left}px`);
      element.style.setProperty("--glass-scene-top", `${frame.top - rect.top}px`);
    };
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(surface);
    observer.observe(scene);
    // Capture scrolls in nested Settings panes as well as the main workspace.
    document.addEventListener("scroll", measure, true);
    document.addEventListener("animationend", measure, true);
    window.addEventListener("resize", measure);
    return () => {
      observer.disconnect();
      document.removeEventListener("scroll", measure, true);
      document.removeEventListener("animationend", measure, true);
      window.removeEventListener("resize", measure);
    };
  }, [supported, visible, workspace.sidebar, workspace.width]);

  useLayoutEffect(() => {
    if (!enabled) return;
    const texture = host.current?.querySelector(".liquid-glass-texture");
    const scene = document.querySelector(".desktop-shell");
    const source = scene
      ?.getAnimations?.()
      .find(
        (animation) =>
          "animationName" in animation && animation.animationName === "background-drift",
      );
    // A newly opened pane joins the existing drift, rather than starting a second
    // unrelated wave. Speed changes preserve the phase of every copy in theme.ts.
    if (source?.currentTime != null) {
      texture?.getAnimations?.().forEach((animation) => {
        animation.currentTime = source.currentTime;
      });
    }
  }, [enabled, backgroundMotion, backgroundSpeed, backgroundIntensity]);

  return (
    <div ref={host} className="liquid-glass-backdrop" aria-hidden="true" inert>
      {enabled && (
        <GlassBoundary>
          <Glass
            className="liquid-glass-lens"
            style={{ position: "absolute", inset: 0, borderRadius: "inherit" }}
            filterResolution={1}
            pixelUnits
            live={live}
            optics={optics}
            behind="var(--pam-surface-raised)"
            refract={
              <div className="liquid-glass-source">
                <div className="liquid-glass-scene">
                  <div className="liquid-glass-texture" />
                </div>
              </div>
            }
          />
        </GlassBoundary>
      )}
    </div>
  );
}
