import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import type { DaemonView } from "../selectors";
import { OptionsView } from "./OptionsView";

function daemon(overrides: Partial<DaemonView> = {}): DaemonView {
  return {
    state: "running",
    detail: "PAM is on watch",
    model: "Daemon fixture-0.1.0",
    modelMemory: null,
    queueDepth: 2,
    ...overrides,
  };
}

function renderOptions(overrides: Partial<Parameters<typeof OptionsView>[0]> = {}) {
  const props = {
    theme: "ventisquero" as const,
    themeMode: "light" as const,
    onThemeChange: vi.fn(),
    onThemeModeChange: vi.fn(),
    daemon: daemon(),
    pending: false,
    onToggleDaemon: vi.fn(),
    onRestartDaemon: vi.fn(),
    ...overrides,
  };
  render(<OptionsView {...props} />);
  return props;
}

describe("OptionsView", () => {
  it("changes theme and variant through the shared theme controls", async () => {
    const user = userEvent.setup();
    const props = renderOptions();

    await user.click(screen.getByRole("button", { name: "Theme: Ventisquero · light" }));
    await user.click(screen.getByRole("menuitemradio", { name: /^Viña del Mar/ }));
    expect(props.onThemeChange).toHaveBeenCalledWith("vina");

    await user.click(screen.getByRole("button", { name: "Theme: Ventisquero · light" }));
    await user.click(screen.getByRole("menuitemradio", { name: /^Dark/ }));
    expect(props.onThemeModeChange).toHaveBeenCalledWith("dark");
  });

  it("offers pause and restart while the daemon is running", async () => {
    const user = userEvent.setup();
    const props = renderOptions();

    await user.click(screen.getByRole("button", { name: /Pause PAM/ }));
    expect(props.onToggleDaemon).toHaveBeenCalledTimes(1);
    await user.click(screen.getByRole("button", { name: /Restart PAM/ }));
    expect(props.onRestartDaemon).toHaveBeenCalledTimes(1);
  });

  it("offers a calm start control while the daemon is paused", async () => {
    const user = userEvent.setup();
    const props = renderOptions({
      daemon: daemon({ state: "stopped", detail: "PAM is paused", model: null, queueDepth: null }),
    });

    expect(screen.getByText("PAM is paused")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Restart PAM/ })).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /Start PAM/ }));
    expect(props.onToggleDaemon).toHaveBeenCalledTimes(1);
  });

  it("disables lifecycle controls while a command is pending or the daemon is unavailable", () => {
    renderOptions({ pending: true });
    expect(screen.getByRole("button", { name: /Pause PAM/ })).toBeDisabled();
    expect(screen.getByRole("button", { name: /Restart PAM/ })).toBeDisabled();
  });
});
