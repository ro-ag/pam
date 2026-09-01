import { Moon, Sun } from "lucide-react";
import { useState } from "react";
import { cn } from "../../lib/cn";
import {
  applyTheme,
  defaultTheme,
  isModeId,
  isThemeId,
  nextMode,
  nextTheme,
  themeDefinition,
  type ModeId,
  type ThemeId,
} from "../../lib/theme";
import { Button } from "../ui/Button";
import { Beacon } from "./Beacon";
import { useDaemonStatus } from "./useDaemonStatus";

/**
 * The chrome strip — our titlebar. The whole strip (and its non-interactive
 * children: Tauri only honors the attribute on the exact element under the
 * pointer) is a drag region; the beacon and the theme/mode controls stay clickable
 * because they never carry the attribute. On macOS the native titlebar is
 * overlaid (tauri.conf.json `titleBarStyle: "Overlay"`), so the traffic
 * lights float over the strip's left edge — the wordmark clears them.
 * The copper hairline underneath is the one theme-independent token, kept
 * from v1 as the brand signature.
 */

/** macOS overlay mode leaves traffic lights at our top-left; clear them. */
function hasTrafficLights(): boolean {
  return navigator.userAgent.includes("Mac");
}

export function TopStrip() {
  const daemon = useDaemonStatus();
  const [theme, setTheme] = useState<ThemeId>(() => {
    const applied = document.documentElement.dataset.theme;
    return isThemeId(applied) ? applied : defaultTheme;
  });
  const [mode, setMode] = useState<ModeId>(() => {
    const applied = document.documentElement.dataset.mode;
    return isModeId(applied) ? applied : "dark";
  });

  const cycleTheme = () => {
    const upcoming = nextTheme(theme);
    applyTheme(upcoming, mode);
    setTheme(upcoming);
  };

  const toggleMode = () => {
    const upcoming = nextMode(mode);
    applyTheme(theme, upcoming);
    setMode(upcoming);
  };

  return (
    <header
      data-tauri-drag-region=""
      className={cn(
        "flex h-12 shrink-0 items-center justify-between border-b border-separator pr-3",
        hasTrafficLights() ? "pl-20" : "pl-5",
      )}
    >
      <div data-tauri-drag-region="" className="flex items-baseline gap-3">
        <span
          data-tauri-drag-region=""
          className="font-display text-sm font-semibold tracking-widest text-ink"
        >
          PAM
        </span>
        <span data-tauri-drag-region="" className="font-data text-xs text-ink-faint">
          personal agent machine
        </span>
      </div>
      <div className="flex items-center gap-2">
        <Beacon state={daemon} />
        <Button variant="ghost" size="sm" onClick={cycleTheme}>
          <span aria-hidden="true">◐</span>
          {themeDefinition(theme).label}
        </Button>
        <Button
          variant="ghost"
          size="sm"
          onClick={toggleMode}
          aria-label={mode === "dark" ? "switch to light mode" : "switch to dark mode"}
        >
          {mode === "dark" ? (
            <Sun size={15} aria-hidden="true" />
          ) : (
            <Moon size={15} aria-hidden="true" />
          )}
        </Button>
      </div>
    </header>
  );
}
