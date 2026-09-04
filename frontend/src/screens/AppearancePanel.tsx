import { Check, Droplets, Moon, Sun, Waves } from "lucide-react";
import { useSyncExternalStore } from "react";
import { Button } from "../components/ui/Button";
import { Panel } from "../components/ui/Panel";
import { PreferenceRange, PreferenceToggle } from "../components/ui/PreferenceControls";
import { cn } from "../lib/cn";
import {
  applyTheme,
  applyMaterial,
  applyBackgroundMotion,
  applyBackgroundSpeed,
  applyBackgroundIntensity,
  applyGlassOpacity,
  modeIds,
  subscribeTheme,
  themes,
  themeSnapshot,
} from "../lib/theme";

export function AppearancePanel() {
  const {
    theme,
    mode,
    material,
    backgroundMotion,
    backgroundSpeed,
    backgroundIntensity,
    glassOpacity,
  } = useSyncExternalStore(subscribeTheme, themeSnapshot);
  const motionOff = backgroundMotion === "off";
  return (
    <div className="appearance-panel">
      <div className="appearance-palette-section">
        <div className="appearance-palette-heading">
          <span>COLOR PALETTE</span>
          <span>Applies instantly · remembered</span>
        </div>
        <div className="appearance-grid grid gap-3">
          {themes.flatMap((family) =>
            modeIds.map((appearance) => {
              const active = family.id === theme && appearance === mode;
              return (
                <button
                  key={`${family.id}-${appearance}`}
                  type="button"
                  aria-label={`${family.label} ${family.appearances[appearance]}`}
                  aria-pressed={active}
                  onClick={() => applyTheme(family.id, appearance)}
                  className={cn("appearance-palette", active && "appearance-palette-selected")}
                >
                  <span
                    data-theme={family.id}
                    data-mode={appearance}
                    className="theme-preview appearance-palette-preview"
                  >
                    <span className="appearance-palette-name">
                      <span>{family.appearances[appearance]}</span>
                      {active && <Check aria-hidden="true" className="size-3.5" />}
                    </span>
                    <span className="appearance-mini-window" aria-hidden="true">
                      <span className="appearance-mini-rail" />
                      <span className="appearance-mini-content">
                        <span />
                        <span />
                        <span />
                      </span>
                      <span className="appearance-mini-accent" />
                    </span>
                    <span className="theme-swatches" aria-hidden="true">
                      <span />
                      <span />
                      <span />
                      <span />
                      <span />
                    </span>
                  </span>
                  <span className="appearance-palette-caption">
                    <span>{family.label}</span>
                    <span>{appearance}</span>
                  </span>
                </button>
              );
            }),
          )}
        </div>
      </div>
      <div className="appearance-control-grid">
        <Panel ground="raised" className="appearance-control-card">
          <header className="appearance-control-heading">
            <span className="appearance-control-icon">
              <Droplets aria-hidden="true" size={18} />
            </span>
            <div>
              <h3>Glass & surfaces</h3>
              <p>Set the balance between depth and clarity.</p>
            </div>
          </header>
          <div className="appearance-mode-row">
            <span>Color mode</span>
            <div role="group" aria-label="Color mode" className="appearance-mode-toggle">
              {modeIds.map((candidate) => (
                <Button
                  key={candidate}
                  size="sm"
                  variant={mode === candidate ? "secondary" : "ghost"}
                  aria-pressed={mode === candidate}
                  onClick={() => applyTheme(theme, candidate)}
                >
                  {candidate === "light" ? (
                    <Sun size={13} aria-hidden="true" />
                  ) : (
                    <Moon size={13} aria-hidden="true" />
                  )}
                  {candidate}
                </Button>
              ))}
            </div>
          </div>
          <PreferenceRange
            label="Glass opacity"
            value={glassOpacity}
            min={60}
            max={100}
            readout={`${glassOpacity}%`}
            low="Clearer"
            high="More solid"
            disabled={material === "opaque"}
            onChange={applyGlassOpacity}
          />
          <div className="appearance-control-footer">
            <PreferenceToggle
              label="Reduce transparency"
              checked={material === "opaque"}
              onChange={(checked) => applyMaterial(checked ? "opaque" : "glass")}
              describedBy="material-help"
            />
            <p id="material-help">
              Use solid surfaces without texture or blur. Your opacity is remembered.
            </p>
          </div>
        </Panel>
        <Panel
          ground="raised"
          className="appearance-control-card"
          role="group"
          aria-label="Background motion"
        >
          <header className="appearance-control-heading">
            <span className="appearance-control-icon">
              <Waves aria-hidden="true" size={18} />
            </span>
            <div>
              <h3>Ambient motion</h3>
              <p>A different path inward and back home.</p>
            </div>
          </header>
          <PreferenceToggle
            label="Animate background"
            checked={!motionOff}
            onChange={(checked) => applyBackgroundMotion(checked ? "slow" : "off")}
          />
          <PreferenceRange
            label="Background animation speed"
            value={backgroundSpeed}
            min={0.5}
            max={12}
            step={0.1}
            readout={`${backgroundSpeed.toFixed(1)}× · ${Math.round(240 / backgroundSpeed)}s loop`}
            valueText={`${backgroundSpeed.toFixed(1)} times speed, ${Math.round(240 / backgroundSpeed)} seconds per loop`}
            low="Unhurried"
            high="Preview speed"
            disabled={motionOff}
            onChange={applyBackgroundSpeed}
          />
          <PreferenceRange
            label="Movement intensity"
            value={backgroundIntensity}
            min={0}
            max={100}
            readout={`${backgroundIntensity}%`}
            valueText={`${backgroundIntensity} percent movement`}
            low="Still"
            high="Immersive"
            disabled={motionOff}
            onChange={applyBackgroundIntensity}
          />
          <p className="appearance-motion-note">
            {material === "opaque"
              ? "Hidden while transparency is reduced. Your settings are remembered."
              : motionOff
                ? "The background stays still."
                : "Intensity controls how far the texture travels, zooms and turns."}{" "}
            System motion and transparency preferences take priority.
          </p>
        </Panel>
      </div>
    </div>
  );
}
