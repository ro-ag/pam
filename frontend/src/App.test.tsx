import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import App from "./App";

describe("App", () => {
  it("renders the PAM mark and the daemon placeholder", async () => {
    render(<App />);
    expect(screen.getByRole("heading", { name: "PAM" })).toBeInTheDocument();
    expect(screen.getByText(/daemon: not connected/)).toBeInTheDocument();
    // jsdom has no Tauri bridge, so the shell line settles on browser mode.
    expect(await screen.findByText(/outside the Tauri window/)).toBeInTheDocument();
  });
});
