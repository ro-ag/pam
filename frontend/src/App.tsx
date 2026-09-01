import { invoke, isTauri } from "@tauri-apps/api/core";
import { useEffect, useState } from "react";
import { Badge } from "./components/ui/Badge";
import { Button } from "./components/ui/Button";
import { Panel } from "./components/ui/Panel";
import {
  applyTheme,
  defaultTheme,
  isThemeId,
  nextTheme,
  themeDefinition,
  type ThemeId,
} from "./lib/theme";

/**
 * Living style proof — the design system worn as a screen. Chrome is the
 * dark water; one panel floats on it, lit. Every class below is a semantic
 * token utility; this file is the pattern the real shell (task #25) grows
 * from. The only live wire is the `ping` Tauri command.
 */
export default function App() {
  const [shellStatus, setShellStatus] = useState("shell: checking…");
  const [theme, setTheme] = useState<ThemeId>(() => {
    const applied = document.documentElement.dataset.theme;
    return isThemeId(applied) ? applied : defaultTheme;
  });

  useEffect(() => {
    if (!isTauri()) {
      // Plain-browser dev (vite without the Tauri window) and jsdom tests.
      setShellStatus("shell: running outside the Tauri window");
      return;
    }
    let cancelled = false;
    invoke<string>("ping")
      .then((reply) => {
        if (!cancelled) setShellStatus(`shell: ipc ${reply}`);
      })
      .catch((error: unknown) => {
        if (!cancelled) setShellStatus(`shell: ipc failed (${String(error)})`);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const cycleTheme = () => {
    const upcoming = nextTheme(theme);
    applyTheme(upcoming);
    setTheme(upcoming);
  };

  return (
    <main className="relative flex h-screen flex-col overflow-hidden bg-chrome text-ink">
      <div className="atmosphere" aria-hidden="true" />

      {/* Chrome strip: beacon + wordmark left, theme cycle right. The warm
          copper hairline underneath is the one theme-independent token. */}
      <header className="flex items-center justify-between border-b border-separator px-6 py-3">
        <div className="flex items-center gap-3">
          <span className="relative flex size-2" role="status" aria-label="daemon idle">
            <span className="absolute inset-0 animate-breathe rounded-pill bg-beacon-green blur-xs" />
            <span className="relative size-2 rounded-pill bg-beacon-green" />
          </span>
          <span className="font-display text-sm font-semibold tracking-widest">PAM</span>
          <span className="font-data text-xs text-ink-faint">personal agent machine</span>
        </div>
        <Button variant="ghost" size="sm" onClick={cycleTheme}>
          <span aria-hidden="true">◐</span>
          {themeDefinition(theme).label}
        </Button>
      </header>

      {/* The lit tower deck, floating on the dark water. */}
      <div className="grid flex-1 place-items-center overflow-y-auto p-6">
        <Panel className="w-full max-w-2xl space-y-8 p-10">
          <div className="space-y-4">
            <p className="font-data text-xs tracking-widest text-ink-faint uppercase">
              lifeguard tower · watching
            </p>
            <h1 className="font-display text-hero font-semibold text-ink">PAM</h1>
            <p className="max-w-prose font-voice text-lg text-ink-muted italic">
              I&rsquo;m watching the water. Nothing needs your hand right now — when something
              does, I&rsquo;ll raise mine first.
            </p>
          </div>

          {/* Raised ground: machine facts in the data voice. */}
          <Panel ground="raised" className="space-y-4 p-5">
            <div className="flex items-baseline justify-between gap-4">
              <div>
                <p className="font-display text-3xl font-semibold tracking-tight tabular-nums">
                  0
                </p>
                <p className="font-data text-xs text-ink-faint">tokens avoided this week</p>
              </div>
              <Badge tone="accent">odometer</Badge>
            </div>
            <div className="space-y-1 border-t border-line pt-4 font-data text-xs text-ink-muted">
              <p>daemon: not connected yet</p>
              <p>{shellStatus}</p>
            </div>
          </Panel>

          {/* Truth vocabulary — the five verdicts, plus a held approval. */}
          <div className="flex flex-wrap items-center gap-2">
            <Badge tone="success">verified</Badge>
            <Badge tone="accent">changed</Badge>
            <Badge tone="neutral">queued</Badge>
            <Badge tone="warning">approval held</Badge>
            <Badge tone="danger">refused</Badge>
          </div>

          <div className="flex flex-wrap items-center gap-3 border-t border-line pt-6">
            <Button>Ask Pam</Button>
            <Button variant="ghost">Activity</Button>
            <Button variant="danger">Revoke access</Button>
          </div>
        </Panel>
      </div>
    </main>
  );
}
