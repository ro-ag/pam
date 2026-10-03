import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { EffectiveEntry } from "../lib/ipc";
import {
  ManagedField,
  ManagedNote,
  PolicyDropNotice,
  describeConstraint,
  entryList,
  isLimited,
  isLocked,
  isOrgDefault,
} from "./ManagedField";

/**
 * The shared managed-field wrapper: one entry in, one rendering out. Locked disables the control
 * and names who owns it; a policy default stays editable with a quiet hint; a clamp prints the
 * permitted set; an entry with no policy in play renders nothing at all.
 */

function field(entry: EffectiveEntry | undefined) {
  render(
    <ManagedField entry={entry}>
      {(locked) => <input aria-label="the control" disabled={locked} />}
    </ManagedField>,
  );
}

describe("ManagedField", () => {
  it("disables the control and badges a locked field, with the policy's reason", () => {
    field({ source: "policy", locked: true, mode: "locked", reason: "SEC-114" });
    expect(screen.getByLabelText("the control")).toBeDisabled();
    expect(screen.getByText("Managed by your organization")).toBeInTheDocument();
    expect(screen.getByText("SEC-114")).toBeInTheDocument();
  });

  it("says a held key is paused, not just locked", () => {
    field({ source: "default", locked: true, state: "held" });
    expect(screen.getByLabelText("the control")).toBeDisabled();
    expect(screen.getByText(/paused until the policy file is fixed/)).toBeInTheDocument();
  });

  it("keeps a policy default editable and hints where it came from", () => {
    field({ source: "policy", locked: false, mode: "default" });
    expect(screen.getByLabelText("the control")).toBeEnabled();
    expect(screen.getByText("organization default")).toBeInTheDocument();
    expect(screen.queryByText("Managed by your organization")).toBeNull();
  });

  it("treats a policy source with no mode as a default too", () => {
    field({ source: "policy", locked: false });
    expect(screen.getByText("organization default")).toBeInTheDocument();
  });

  it("prints the permitted set beside an editable, limited control", () => {
    field({
      source: "policy",
      locked: false,
      mode: "allow",
      constraint: { allow: ["git", "cargo"] },
      clamped: true,
    });
    expect(screen.getByLabelText("the control")).toBeEnabled();
    expect(screen.getByText("Limited by your organization")).toBeInTheDocument();
    expect(screen.getByText("allowed: git, cargo")).toBeInTheDocument();
    expect(screen.queryByText("organization default")).toBeNull();
  });

  it("renders nothing for a field no policy owns", () => {
    for (const entry of [
      undefined,
      { source: "user", locked: false } as const,
      { source: "default", locked: false } as const,
    ]) {
      const { container, unmount } = render(<ManagedNote entry={entry} />);
      expect(container).toBeEmptyDOMElement();
      unmount();
    }
    field({ source: "user", locked: false });
    expect(screen.getByLabelText("the control")).toBeEnabled();
  });

  it("shows hidden characters in a reason instead of hiding them", () => {
    field({ source: "policy", locked: true, reason: "ticket‮123" });
    expect(screen.getByTitle("a hidden character, shown as its escape")).toBeInTheDocument();
  });
});

describe("managed entry helpers", () => {
  it("classifies an entry exactly one way", () => {
    const locked: EffectiveEntry = { source: "policy", locked: true };
    const limited: EffectiveEntry = { source: "policy", locked: false, mode: "floor" };
    const clamped: EffectiveEntry = { source: "policy", locked: false, clamped: true };
    const given: EffectiveEntry = { source: "policy", locked: false, mode: "default" };
    expect([locked, limited, clamped, given].map(isLocked)).toEqual([
      true,
      false,
      false,
      false,
    ]);
    expect([locked, limited, clamped, given].map(isLimited)).toEqual([
      false,
      true,
      true,
      false,
    ]);
    expect([locked, limited, clamped, given].map(isOrgDefault)).toEqual([
      false,
      false,
      false,
      true,
    ]);
    expect([isLocked(undefined), isLimited(undefined), isOrgDefault(undefined)]).toEqual([
      false,
      false,
      false,
    ]);
  });

  it("describes ranges and allowlists in words", () => {
    expect(
      describeConstraint({
        source: "policy",
        locked: false,
        constraint: { floor: "standard" },
      }),
    ).toBe("lowest allowed: standard");
    expect(
      describeConstraint({ source: "policy", locked: false, constraint: { max: 90 } }),
    ).toBe("at most: 90");
    expect(
      describeConstraint({
        source: "policy",
        locked: false,
        constraint: { allow: [] },
      }),
    ).toBe("allowed: none");
    expect(describeConstraint({ source: "policy", locked: false })).toBeNull();
  });

  it("reads a list value, or falls back", () => {
    expect(entryList({ source: "policy", locked: true, value: ["a", "b"] }, ["x"])).toEqual([
      "a",
      "b",
    ]);
    expect(entryList({ source: "policy", locked: true, value: 3 }, ["x"])).toEqual(["x"]);
    expect(entryList(undefined, [])).toEqual([]);
  });
});

describe("PolicyDropNotice", () => {
  it("lists what the policy is not using, with the daemon's reason", () => {
    render(
      <PolicyDropNotice
        label="dropped"
        drops={[
          {
            root: "/work/app",
            connector: "jenkins",
            key: "connectors.disabled",
            reason: "your organization's policy disables this connector",
          },
          { root: "/elsewhere", reason: "this repository is outside the approved roots" },
        ]}
      />,
    );
    const note = screen.getByRole("note", { name: "dropped" });
    expect(note).toHaveTextContent("is not using these entries");
    expect(note).toHaveTextContent("/work/app · jenkins");
    expect(note).toHaveTextContent("your organization's policy disables this connector");
    expect(note).toHaveTextContent("/elsewhere");
  });

  it("renders nothing when nothing was dropped", () => {
    const { container } = render(<PolicyDropNotice label="dropped" drops={[]} />);
    expect(container).toBeEmptyDOMElement();
    const missing = render(<PolicyDropNotice label="dropped" drops={undefined} />);
    expect(missing.container).toBeEmptyDOMElement();
  });
});
