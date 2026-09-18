import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { EngineCard } from "./EngineCard";
import type { EngineManifest, EngineStatus } from "../lib/ipc";

/**
 * EngineCard against the real `ipc.ts` wrappers, with only the Tauri
 * bridge itself mocked — the same technique `ipc.test.ts` uses — so a
 * click is proven to reach the daemon as `admin.models.engine.install`
 * with `{ confirm: true }`, not just as a call to a mocked wrapper.
 */

const bridge = vi.hoisted(() => ({ inShell: true, invoke: vi.fn() }));

vi.mock("@tauri-apps/api/core", () => ({
  isTauri: () => bridge.inShell,
  invoke: (command: string, args?: Record<string, unknown>) => bridge.invoke(command, args),
}));

beforeEach(() => {
  bridge.inShell = true;
  bridge.invoke.mockReset();
});

function manifest(overrides: Partial<EngineManifest> = {}): EngineManifest {
  return {
    tag: "b1234",
    build: 1234,
    target: "aarch64-apple-darwin",
    asset: "llama-b1234-bin-macos-arm64.zip",
    sha256: "abcdef0123456789abcdef0123456789",
    bytes: 12_000_000,
    version_line: "version: 1234 (abcdef0)",
    installed_at_ms: 1_700_000_000_000,
    ...overrides,
  };
}

function status(overrides: Partial<EngineStatus> = {}): EngineStatus {
  return {
    expected_tag: "b1234",
    expected_build: 1234,
    target: "aarch64-apple-darwin",
    installed: false,
    server_path: null,
    manifest: null,
    cause: "not_installed",
    ...overrides,
  };
}

/** Routes `admin_call` by op, the way the real daemon bridge would. */
function mockBridge(byOp: Record<string, () => unknown>) {
  bridge.invoke.mockImplementation(async (_command: string, args?: { op: string }) => {
    const op = args?.op ?? "";
    const handler = byOp[op];
    if (!handler) throw new Error(`unexpected op ${op}`);
    return handler();
  });
}

function mount() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const invalidateSpy = vi.spyOn(client, "invalidateQueries");
  render(
    <QueryClientProvider client={client}>
      <EngineCard />
    </QueryClientProvider>,
  );
  return invalidateSpy;
}

describe("not installed", () => {
  it("says Not installed and offers Install engine", async () => {
    mockBridge({ "admin.models.engine.status": () => status() });
    mount();
    expect(await screen.findByText("Not installed")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Install engine" })).toBeInTheDocument();
  });
});

describe("installed", () => {
  it("shows the tag, target, version line and sha prefix, and offers Reinstall", async () => {
    mockBridge({
      "admin.models.engine.status": () =>
        status({ installed: true, cause: null, manifest: manifest() }),
    });
    mount();
    expect(
      await screen.findByText("Installed · b1234 · aarch64-apple-darwin"),
    ).toBeInTheDocument();
    expect(screen.getByText(/version: 1234 \(abcdef0\)/)).toBeInTheDocument();
    expect(screen.getByText(/sha abcdef012345/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Reinstall engine" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Install engine" })).not.toBeInTheDocument();
  });

  it.each([
    ["stale_release", "Installed b1233, expected b1234", manifest({ tag: "b1233" })],
    ["server_missing", "Broken install", null],
    ["manifest_invalid", "Broken install", null],
  ] as const)(
    "offers Reinstall engine when %s",
    async (cause, expectedText, brokenManifest) => {
      mockBridge({
        "admin.models.engine.status": () => status({ cause, manifest: brokenManifest }),
      });
      mount();
      expect(await screen.findByText(expectedText)).toBeInTheDocument();
      expect(screen.getByRole("button", { name: "Reinstall engine" })).toBeInTheDocument();
    },
  );
});

describe("unsupported target", () => {
  it("hides the install button when there is no release for this platform", async () => {
    mockBridge({
      "admin.models.engine.status": () => status({ cause: "unsupported_target" }),
    });
    mount();
    expect(await screen.findByText("No release for this platform")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /install engine/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /reinstall engine/i })).not.toBeInTheDocument();
  });
});

describe("install", () => {
  it("calls engine.install once with confirm, shows a pending label, and invalidates status on success", async () => {
    let resolveInstall: (value: EngineStatus) => void = () => {};
    mockBridge({
      "admin.models.engine.status": () => status(),
      "admin.models.engine.install": () =>
        new Promise<EngineStatus>((resolve) => {
          resolveInstall = resolve;
        }),
    });
    const invalidateSpy = mount();
    await screen.findByText("Not installed");
    const button = screen.getByRole("button", { name: "Install engine" });
    await waitFor(() => expect(button).toBeEnabled());
    fireEvent.click(button);

    await waitFor(() =>
      expect(bridge.invoke).toHaveBeenCalledWith("admin_call", {
        op: "admin.models.engine.install",
        args: { confirm: true },
      }),
    );
    expect(
      bridge.invoke.mock.calls.filter(
        ([, args]) =>
          (args as { op?: string } | undefined)?.op === "admin.models.engine.install",
      ),
    ).toHaveLength(1);
    expect(await screen.findByRole("button", { name: "Installing…" })).toBeDisabled();

    resolveInstall(status({ installed: true, cause: null, manifest: manifest() }));
    await waitFor(() =>
      expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ["engine", "status"] }),
    );
    expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ["models", "status"] });
  });

  it("renders a refused install through the uniform failure note", async () => {
    mockBridge({
      "admin.models.engine.status": () => status(),
      "admin.models.engine.install": () => {
        throw {
          cause: "engine_download_failed",
          detail: "GitHub returned 404 for the release asset",
          recovery: "Check network access and try again.",
        };
      },
    });
    mount();
    await screen.findByText("Not installed");
    const button = screen.getByRole("button", { name: "Install engine" });
    await waitFor(() => expect(button).toBeEnabled());
    fireEvent.click(button);
    expect(await screen.findByText(/engine · engine_download_failed/)).toBeInTheDocument();
    expect(screen.getByText(/GitHub returned 404 for the release asset/)).toBeInTheDocument();
    expect(screen.getByText(/Check network access and try again/)).toBeInTheDocument();
  });
});
