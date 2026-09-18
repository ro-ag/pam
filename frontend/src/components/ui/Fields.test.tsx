import { createRef } from "react";
import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { SelectField, TextArea, TextField } from "./Fields";

describe("shared fields", () => {
  it("preserves native refs, labels, input events and text selection", () => {
    const ref = createRef<HTMLInputElement>();
    const change = vi.fn();
    render(
      <label>
        Name
        <TextField ref={ref} defaultValue="PAM" onChange={change} />
      </label>,
    );
    const input = screen.getByRole("textbox", { name: "Name" });
    expect(ref.current).toBe(input);
    ref.current?.focus();
    ref.current?.setSelectionRange(0, 3);
    expect(ref.current?.selectionEnd).toBe(3);
    fireEvent.change(input, { target: { value: "New name" } });
    expect(change).toHaveBeenCalledOnce();
    expect(input).toHaveValue("New name");
  });

  it("preserves textarea and select semantics, including fieldset disabling", () => {
    render(
      <fieldset disabled>
        <TextArea aria-label="Notes" defaultValue="Draft" rows={4} />
        <SelectField aria-label="Mode" defaultValue="b">
          <option value="a">A</option>
          <option value="b">B</option>
        </SelectField>
      </fieldset>,
    );
    expect(screen.getByRole("textbox", { name: "Notes" })).toHaveValue("Draft");
    expect(screen.getByRole("textbox", { name: "Notes" })).toBeDisabled();
    expect(screen.getByRole("combobox", { name: "Mode" })).toHaveValue("b");
    expect(screen.getByRole("combobox", { name: "Mode" })).toBeDisabled();
  });
});
