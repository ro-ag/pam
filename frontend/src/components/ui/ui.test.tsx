import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { Badge } from "./Badge";
import { Button } from "./Button";
import { Panel } from "./Panel";

describe("Panel", () => {
  it("defaults to a flat working surface", () => {
    render(<Panel data-testid="panel">deck</Panel>);
    const panel = screen.getByTestId("panel");
    expect(panel.tagName).toBe("SECTION");
    expect(panel.className).toContain("bg-surface");
    expect(panel.className).toContain("rounded-panel");
    expect(panel.className).not.toContain("shadow-float");
  });

  it("renders the raised ground for cards", () => {
    render(
      <Panel ground="raised" data-testid="panel">
        card
      </Panel>,
    );
    const panel = screen.getByTestId("panel");
    expect(panel.className).toContain("bg-surface-raised");
    expect(panel.className).toContain("rounded-card");
    expect(panel.className).not.toContain("shadow-raise");
  });

  it("merges caller overrides through cn", () => {
    render(
      <Panel className="p-10" data-testid="panel">
        deck
      </Panel>,
    );
    expect(screen.getByTestId("panel").className).toContain("p-10");
  });

  it("offers Tailwind translucency with solid accessibility overrides and no effects", () => {
    render(
      <Panel ground="translucent" data-testid="panel">
        card
      </Panel>,
    );
    const classes = screen.getByTestId("panel").className;
    expect(classes).toContain("bg-surface-translucent");
    expect(classes).toContain("material-opaque:bg-surface-raised");
    expect(classes).toContain("transparency-reduce:bg-surface-raised");
    expect(classes).toContain("forced-colors:bg-system-canvas");
    expect(classes).not.toMatch(/blur|shadow|filter/);
  });
});

describe("Badge", () => {
  it("speaks in the data voice with a neutral default", () => {
    render(<Badge>queued</Badge>);
    const badge = screen.getByText("queued");
    expect(badge.className).toContain("font-data");
    expect(badge.className).toContain("text-ink-muted");
  });

  it.each([
    ["success", "text-success"],
    ["warning", "text-warning"],
    ["danger", "text-danger"],
    ["accent", "text-accent"],
  ] as const)("renders the %s tone", (tone, expected) => {
    render(<Badge tone={tone}>{tone}</Badge>);
    expect(screen.getByText(tone).className).toContain(expected);
  });
});

describe("Button", () => {
  it("defaults to the primary accent fill and a safe type", () => {
    render(<Button>Ask Pam</Button>);
    const button = screen.getByRole("button", { name: "Ask Pam" });
    expect(button).toHaveAttribute("type", "button");
    expect(button.className).toContain("bg-accent-strong");
    expect(button.className).toContain("text-on-accent");
  });

  it("renders ghost and danger variants", () => {
    render(
      <>
        <Button variant="ghost">Activity</Button>
        <Button variant="danger">Revoke</Button>
      </>,
    );
    expect(screen.getByRole("button", { name: "Activity" }).className).toContain(
      "text-ink-muted",
    );
    expect(screen.getByRole("button", { name: "Revoke" }).className).toContain(
      "bg-danger-soft",
    );
  });

  it("lets caller utilities win over variant utilities", () => {
    render(<Button className="px-8">Wide</Button>);
    const button = screen.getByRole("button", { name: "Wide" });
    expect(button.className).toContain("px-8");
    expect(button.className).not.toContain("px-4");
  });

  it("respects an explicit submit type", () => {
    render(<Button type="submit">Go</Button>);
    expect(screen.getByRole("button", { name: "Go" })).toHaveAttribute("type", "submit");
  });
});
