import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { flowsList, modelsList } from "../../lib/ipc";
import { CommandPalette } from "./CommandPalette";

const navigate = vi.hoisted(() => vi.fn());
vi.mock("@tanstack/react-router", () => ({ useNavigate: () => navigate }));
vi.mock("../../lib/ipc", () => ({ flowsList: vi.fn(), modelsList: vi.fn() }));

const originalShowModal = Object.getOwnPropertyDescriptor(
  HTMLDialogElement.prototype,
  "showModal",
);
const originalClose = Object.getOwnPropertyDescriptor(HTMLDialogElement.prototype, "close");

beforeAll(() => {
  // jsdom has the element but not the native dialog lifecycle/top-layer implementation.
  Object.defineProperty(HTMLDialogElement.prototype, "showModal", {
    configurable: true,
    value(this: HTMLDialogElement) {
      this.open = true;
    },
  });
  Object.defineProperty(HTMLDialogElement.prototype, "close", {
    configurable: true,
    value(this: HTMLDialogElement) {
      this.open = false;
    },
  });
});

afterAll(() => {
  if (originalShowModal)
    Object.defineProperty(HTMLDialogElement.prototype, "showModal", originalShowModal);
  else Reflect.deleteProperty(HTMLDialogElement.prototype, "showModal");
  if (originalClose) Object.defineProperty(HTMLDialogElement.prototype, "close", originalClose);
  else Reflect.deleteProperty(HTMLDialogElement.prototype, "close");
});

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(flowsList).mockResolvedValue({ flows: [] });
  vi.mocked(modelsList).mockResolvedValue({ models: [], models_dir: "/models" });
});

function mount() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <button type="button">Original focus</button>
      <CommandPalette />
    </QueryClientProvider>,
  );
}

function open() {
  const trigger = screen.getByRole("button", { name: "Open command palette" });
  trigger.focus();
  fireEvent.click(trigger);
  return screen.getByRole("combobox");
}

describe("CommandPalette", () => {
  it("loads libraries only while open and keeps six pages and eight settings available", async () => {
    mount();
    expect(flowsList).not.toHaveBeenCalled();
    expect(modelsList).not.toHaveBeenCalled();
    open();
    expect(screen.getByRole("dialog", { name: "Jump to" })).toHaveAttribute("open");
    expect(screen.getAllByRole("option")).toHaveLength(14);
    await waitFor(() => expect(flowsList).toHaveBeenCalledTimes(1));
    expect(modelsList).toHaveBeenCalledTimes(1);
    expect(screen.getByText(/Nothing runs here/)).toBeInTheDocument();
  });

  it.each(["metaKey", "ctrlKey"])(
    "opens with %s+K and restores the original focus on Escape",
    (modifier) => {
      mount();
      const original = screen.getByRole("button", { name: "Original focus" });
      original.focus();
      fireEvent.keyDown(document, { key: "k", [modifier]: true });
      const input = screen.getByRole("combobox");
      expect(input).toHaveFocus();
      fireEvent.keyDown(input, { key: "Escape" });
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
      expect(original).toHaveFocus();
    },
  );

  it("filters case-insensitively by multiple words and opens the exact settings hash", () => {
    mount();
    const input = open();
    fireEvent.change(input, { target: { value: "SETTINGS models" } });
    expect(screen.getAllByRole("option")).toHaveLength(1);
    expect(screen.getByRole("option", { selected: true })).toHaveTextContent("Models");
    fireEvent.keyDown(input, { key: "Enter" });
    expect(navigate).toHaveBeenCalledWith({ to: "/settings", hash: "models", search: {} });
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("wraps arrow navigation and exposes the active option without moving input focus", () => {
    mount();
    const input = open();
    fireEvent.change(input, { target: { value: "models" } });
    fireEvent.keyDown(input, { key: "ArrowUp" });
    const setting = screen.getByRole("option", { selected: true });
    expect(setting).toHaveTextContent("Settings category");
    expect(input).toHaveAttribute("aria-activedescendant", setting.id);
    expect(input).toHaveFocus();
    fireEvent.keyDown(input, { key: "ArrowDown" });
    expect(screen.getByRole("option", { selected: true })).toHaveTextContent("Page");
    fireEvent.keyDown(input, { key: "Enter" });
    expect(navigate).toHaveBeenCalledWith({ to: "/models", hash: "", search: {} });
  });

  it("opens an actual flow deep link without executing anything", async () => {
    vi.mocked(flowsList).mockResolvedValue({
      flows: [
        {
          id: "review-release",
          name: "Review release",
          description: "Inspect release evidence",
          source: "library",
          valid: true,
          digest: "abc",
          steps: 2,
          inputs: [],
        },
      ],
    });
    mount();
    const input = open();
    fireEvent.change(input, { target: { value: "review-release" } });
    const flow = await screen.findByRole("option", { name: /Review release/ });
    expect(flow).toHaveTextContent("Open, never run");
    fireEvent.click(flow);
    expect(navigate).toHaveBeenCalledExactlyOnceWith({
      to: "/flows",
      hash: "",
      search: { flow: "review-release" },
    });
  });

  it("finds real installed models and opens their library, not an unsupported deep link", async () => {
    vi.mocked(modelsList).mockResolvedValue({
      models_dir: "/models",
      models: [
        {
          id: "local-weights",
          file_name: "local-weights.gguf",
          vendor: "Local",
          path: "/models/local-weights.gguf",
          size_bytes: 100,
          info: null,
          info_error: null,
          class: "engine",
          verified: null,
          catalog_id: null,
        },
      ],
    });
    mount();
    const input = open();
    fireEvent.change(input, { target: { value: "local-weights" } });
    fireEvent.click(await screen.findByRole("option", { name: /local-weights.gguf/ }));
    expect(navigate).toHaveBeenCalledWith({ to: "/models", hash: "", search: {} });
  });

  it("keeps static navigation usable offline and handles an empty result list", async () => {
    vi.mocked(flowsList).mockRejectedValue(new Error("offline"));
    vi.mocked(modelsList).mockRejectedValue(new Error("offline"));
    mount();
    const input = open();
    await screen.findByText(/Some library entries are unavailable/);
    fireEvent.change(input, { target: { value: "not-a-destination" } });
    expect(screen.getByText("No matching destinations.")).toBeInTheDocument();
    expect(input).not.toHaveAttribute("aria-activedescendant");
    fireEvent.keyDown(input, { key: "ArrowDown" });
    fireEvent.keyDown(input, { key: "Enter" });
    expect(navigate).not.toHaveBeenCalled();
    fireEvent.change(input, { target: { value: "connectors" } });
    fireEvent.keyDown(input, { key: "Enter" });
    expect(navigate).toHaveBeenCalledWith({ to: "/settings", hash: "connectors", search: {} });
  });

  it("cycles focus inside the modal and restores the trigger after backdrop dismissal", () => {
    mount();
    const input = open();
    const dismiss = screen.getByRole("button", { name: "Close command palette" });
    fireEvent.keyDown(input, { key: "Tab", shiftKey: true });
    expect(dismiss).toHaveFocus();
    fireEvent.keyDown(dismiss, { key: "Tab" });
    expect(input).toHaveFocus();
    fireEvent.click(screen.getByRole("dialog"));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Open command palette" })).toHaveFocus();
  });

  it("does not intercept another modal's shortcut and removes its listener on unmount", () => {
    const view = mount();
    const other = document.createElement("dialog");
    other.open = true;
    document.body.append(other);
    fireEvent.keyDown(document, { key: "k", ctrlKey: true });
    expect(screen.queryByRole("combobox")).not.toBeInTheDocument();
    other.remove();
    view.unmount();
    const event = new KeyboardEvent("keydown", { key: "k", ctrlKey: true, cancelable: true });
    document.dispatchEvent(event);
    expect(event.defaultPrevented).toBe(false);
  });

  it("handles native dialog cancellation", () => {
    mount();
    open();
    fireEvent(screen.getByRole("dialog"), new Event("cancel", { cancelable: true }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("toggles with the shortcut and starts the next search fresh", () => {
    mount();
    const input = open();
    fireEvent.change(input, { target: { value: "retention" } });
    fireEvent.keyDown(input, { key: "k", metaKey: true });
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    fireEvent.keyDown(document, { key: "k", metaKey: true });
    expect(screen.getByRole("combobox")).toHaveValue("");
    expect(screen.getAllByRole("option")).toHaveLength(14);
    fireEvent.click(screen.getByRole("button", { name: "Close command palette" }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });
});
