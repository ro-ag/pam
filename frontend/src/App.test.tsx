import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import App from "./App";

afterEach(() => {
  window.localStorage.clear();
  delete document.documentElement.dataset.theme;
});

describe("App", () => {
  it("renders the PAM mark and the daemon placeholder", async () => {
    render(<App />);
    expect(screen.getByRole("heading", { name: "PAM" })).toBeInTheDocument();
    expect(screen.getByText(/daemon: not connected/)).toBeInTheDocument();
    // jsdom has no Tauri bridge, so the shell line settles on browser mode.
    expect(await screen.findByText(/outside the Tauri window/)).toBeInTheDocument();
  });

  it("shows the beacon and the truth-vocabulary badges", () => {
    render(<App />);
    expect(screen.getByRole("status", { name: "daemon idle" })).toBeInTheDocument();
    for (const verdict of ["verified", "changed", "queued", "refused"]) {
      expect(screen.getByText(verdict)).toBeInTheDocument();
    }
  });

  it("cycles themes by token redefinition on the root element", () => {
    render(<App />);
    // Boot default: Ventisquero Mist.
    const toggle = screen.getByRole("button", { name: /Ventisquero Mist/ });
    fireEvent.click(toggle);
    expect(document.documentElement.dataset.theme).toBe("vina-del-mar-dawn");
    expect(window.localStorage.getItem("pam-theme")).toBe("vina-del-mar-dawn");
    fireEvent.click(screen.getByRole("button", { name: /Viña del Mar Dawn/ }));
    expect(document.documentElement.dataset.theme).toBe("ventisquero-mist");
  });
});
