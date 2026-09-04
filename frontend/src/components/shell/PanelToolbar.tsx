import { Moon, Sun } from "lucide-react";
import { useSyncExternalStore } from "react";
import {
  applyTheme,
  nextMode,
  nextTheme,
  subscribeTheme,
  themeDefinition,
  themeSnapshot,
} from "../../lib/theme";
import { Button } from "../ui/Button";
import { Beacon } from "./Beacon";
import { useDaemonStatus } from "./useDaemonStatus";
import { CommandPalette } from "./CommandPalette";
import { WorkspaceMenu } from "./WorkspaceMenu";

/**
 * The panel toolbar — the shell's chrome controls, living INSIDE the work
 * panel's top edge rather than in a band across the window. There is no
 * window-wide strip any more: the sidebar owns the full height on the left
 * and the panel runs to the top on the right, so this row is the panel's
 * first child.
 *
 * The row (and its non-interactive children: Tauri only honors the attribute
 * on the exact element under the pointer) is a drag region, so the window
 * still moves when the user grabs the empty space beside the controls; the
 * theme and mode buttons never carry the attribute and stay clickable.
 * The material hairline and small theme marker use Costa’s shared gradients.
 */
export function PanelToolbar() {
  const daemon = useDaemonStatus();
  // The shared theme store keeps this toolbar and Settings > Appearance in
  // agreement: whichever changes the combination, both re-render.
  const { theme, mode } = useSyncExternalStore(subscribeTheme, themeSnapshot);

  const cycleTheme = () => applyTheme(nextTheme(theme), mode);
  const toggleMode = () => applyTheme(theme, nextMode(mode));

  return (
    <div
      role="toolbar"
      aria-label="panel controls"
      data-tauri-drag-region=""
      className="material-edge flex h-11 shrink-0 items-center justify-end gap-2 px-3"
    >
      <div className="flex min-w-0 items-center gap-1 mr-auto">
        <CommandPalette />
        <WorkspaceMenu />
      </div>
      <span data-tauri-drag-region="" className="flex items-center pr-1">
        <Beacon state={daemon} />
      </span>
      <Button variant="ghost" size="sm" onClick={cycleTheme}>
        <span aria-hidden="true" className="warm-marker size-2 rounded-pill" />
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
  );
}
