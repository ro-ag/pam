import { ArrowClockwise, PaintBrush, Power } from "@phosphor-icons/react";
import { StatusDot, ThemeMenu } from "../components/Shell";
import type { DaemonView } from "../selectors";
import type { PamTheme, PamThemeMode } from "../theme";

export interface OptionsViewProps {
  theme: PamTheme;
  themeMode: PamThemeMode;
  onThemeChange: (theme: PamTheme) => void;
  onThemeModeChange: (mode: PamThemeMode) => void;
  daemon: DaemonView;
  pending: boolean;
  onToggleDaemon: () => void;
  onRestartDaemon: () => void;
}

export function OptionsView({
  theme,
  themeMode,
  onThemeChange,
  onThemeModeChange,
  daemon,
  pending,
  onToggleDaemon,
  onRestartDaemon,
}: OptionsViewProps) {
  const running = daemon.state === "running";
  return (
    <main className="canvas" id="main-content">
      <header className="project-header compact">
        <div><h1>Options</h1><p>Appearance and daemon lifecycle, in one calm place.</p></div>
      </header>
      <section className="panel" aria-labelledby="appearance-heading">
        <div className="panel-title">
          <div><span className="eyebrow">Appearance</span><h2 id="appearance-heading">Theme</h2></div>
          <PaintBrush size={22} aria-hidden="true" />
        </div>
        <div className="options-row">
          <div>
            <strong>{theme === "ventisquero" ? "Ventisquero" : "Viña del Mar"} · {themeMode}</strong>
            <p>Pick the palette and variant that suit the light where you work.</p>
          </div>
          <ThemeMenu
            theme={theme}
            themeMode={themeMode}
            onThemeChange={onThemeChange}
            onThemeModeChange={onThemeModeChange}
          />
        </div>
      </section>
      <section className="panel" aria-labelledby="daemon-heading">
        <div className="panel-title">
          <div><span className="eyebrow">Daemon lifecycle</span><h2 id="daemon-heading">PAM daemon</h2></div>
          <Power size={22} aria-hidden="true" />
        </div>
        <div className="options-row">
          <div>
            <strong className="options-daemon-detail">
              <StatusDot state={running ? "coral" : "muted"} />
              {daemon.detail}
            </strong>
            <p>{running
              ? "PAM keeps watching while this window is open. Pausing it stops the watch until you start it again."
              : "PAM is taking a break. Start it again whenever you want it back on watch."}</p>
          </div>
          <div className="options-actions">
            <button
              type="button"
              className={`button ${running ? "button--secondary" : "button--primary"}`}
              disabled={pending || ["starting", "stopping", "unavailable"].includes(daemon.state)}
              onClick={onToggleDaemon}
            >
              <Power size={18} /> {running ? "Pause PAM" : "Start PAM"}
            </button>
            {running && (
              <button
                type="button"
                className="button button--secondary"
                disabled={pending}
                onClick={onRestartDaemon}
              >
                <ArrowClockwise size={18} /> Restart PAM
              </button>
            )}
          </div>
        </div>
      </section>
    </main>
  );
}
