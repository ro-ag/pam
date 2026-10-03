import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
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

function mount(onOpenNetwork?: () => void) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const invalidateSpy = vi.spyOn(client, "invalidateQueries");
  render(
    <QueryClientProvider client={client}>
      <EngineCard onOpenNetwork={onOpenNetwork} />
    </QueryClientProvider>,
  );
  return invalidateSpy;
}

const ASSET = "llama-b1234-bin-macos-arm64.tar.gz";
const SHA = "69f236c8aa148eb32bfd76774a0a449e2f9b754c595e8f6d90b12cf7fecb8399";

/** The delivery fields the daemon adds to status: an upstream install that has not happened. */
function plan(overrides: Partial<EngineStatus> = {}): Partial<EngineStatus> {
  return {
    expected_asset: ASSET,
    expected_size: 11_146_574,
    expected_sha256: SHA,
    download_url: `https://github.com/ggml-org/llama.cpp/releases/download/b1234/${ASSET}`,
    download_host: "github.com",
    mirror_in_use: false,
    mirror_host: null,
    upstream_host: "github.com",
    engine_dir: "/Users/dev/.pam/engine",
    install_dir: "/Users/dev/.pam/engine/llama-b1234",
    source: null,
    loaded: false,
    removable: false,
    ...overrides,
  };
}

/** A healthy install with the delivery fields. */
function installed(overrides: Partial<EngineStatus> = {}): EngineStatus {
  return status({
    installed: true,
    cause: null,
    manifest: manifest({ asset: ASSET, sha256: SHA }),
    ...plan({ removable: true }),
    ...overrides,
  });
}

/** The call count of one op on the mocked bridge. */
function callsOf(op: string): unknown[][] {
  return bridge.invoke.mock.calls.filter(
    ([, args]) => (args as { op?: string } | undefined)?.op === op,
  );
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
    expect(screen.getAllByText(/version: 1234 \(abcdef0\)/).length).toBeGreaterThan(0);
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

describe("disclosure before the click", () => {
  it("says what Install does: file, size, host, digest check, location, how it runs, how to remove", async () => {
    mockBridge({ "admin.models.engine.status": () => status(plan()) });
    mount();
    const card = within(await screen.findByLabelText("what install does"));
    expect(card.getByText(/Nothing is downloaded until you press Install/)).toBeInTheDocument();
    expect(card.getByText(ASSET)).toBeInTheDocument();
    expect(card.getByText(/\(11 MB\)/)).toBeInTheDocument();
    expect(card.getByText("github.com")).toBeInTheDocument();
    expect(
      card.getByText(`https://github.com/ggml-org/llama.cpp/releases/download/b1234/${ASSET}`),
    ).toBeInTheDocument();
    expect(card.getByText("69f236c8aa14…cb8399")).toBeInTheDocument();
    expect(card.getByText(/the value built into this version of PAM/)).toBeInTheDocument();
    expect(
      card.getByText(/A file that differs is deleted and nothing is installed/),
    ).toBeInTheDocument();
    expect(card.getByText("/Users/dev/.pam/engine/llama-b1234")).toBeInTheDocument();
    expect(
      card.getByText(/runs as your user, as a child of the\s+PAM daemon/),
    ).toBeInTheDocument();
    expect(card.getByText(/never gives it\s+your connector credentials/)).toBeInTheDocument();
    expect(
      card.getByText(/press Remove engine, or stop the daemon and delete/),
    ).toBeInTheDocument();
    expect(card.getByText("/Users/dev/.pam/engine")).toBeInTheDocument();
    expect(card.getByText(/Cannot reach github.com from this network\?/)).toBeInTheDocument();
    expect(card.queryByText(/your configured mirror/)).not.toBeInTheDocument();
  });

  it("names the configured mirror as the host, with upstream beside it", async () => {
    mockBridge({
      "admin.models.engine.status": () =>
        status(
          plan({
            download_url: `https://artifacts.corp.example/llama/b1234/${ASSET}`,
            download_host: "artifacts.corp.example",
            mirror_in_use: true,
            mirror_host: "artifacts.corp.example",
          }),
        ),
    });
    mount();
    const card = within(await screen.findByLabelText("what install does"));
    expect(card.getByText("artifacts.corp.example")).toBeInTheDocument();
    expect(card.getByText(/your configured mirror/)).toBeInTheDocument();
    expect(card.getByText(/\(upstream is github.com\)/)).toBeInTheDocument();
    expect(card.getByText(/Cannot reach artifacts.corp.example/)).toBeInTheDocument();
  });

  it("says only what it knows when the daemon sent no delivery fields", async () => {
    mockBridge({ "admin.models.engine.status": () => status() });
    mount();
    const card = within(await screen.findByLabelText("what install does"));
    expect(card.getByText(/Nothing is downloaded until you press Install/)).toBeInTheDocument();
    expect(card.queryByText("What Install does")).not.toBeInTheDocument();
  });

  it("links to Settings › Network, and says the network settings are unusable when they are", async () => {
    const open = vi.fn();
    mockBridge({
      "admin.models.engine.status": () =>
        status(
          plan({
            network_issue: {
              cause: "network_settings_invalid",
              detail: "The stored network settings could not be read",
              recovery: "Re-save them in Settings › Network.",
            },
          }),
        ),
    });
    mount(open);
    expect(await screen.findByText(/engine · network_settings_invalid/)).toBeInTheDocument();
    const links = screen.getAllByRole("button", { name: "Open Settings › Network" });
    fireEvent.click(links[0]);
    expect(open).toHaveBeenCalledTimes(1);
  });
});

describe("installing", () => {
  it("states what is happening and the two-minute resume rule while a download runs", async () => {
    mockBridge({
      "admin.models.engine.status": () => status(plan()),
      "admin.models.engine.install": () => new Promise<EngineStatus>(() => {}),
    });
    mount();
    const button = await screen.findByRole("button", { name: "Install engine" });
    await waitFor(() => expect(button).toBeEnabled());
    fireEvent.click(button);
    const note = within(await screen.findByRole("status", { name: "installing" }));
    expect(note.getByText(ASSET)).toBeInTheDocument();
    expect(note.getByText("github.com")).toBeInTheDocument();
    expect(note.getByText(/Then PAM checks the SHA-256/)).toBeInTheDocument();
    expect(note.getByText(/confirm it reports build 1234/)).toBeInTheDocument();
    expect(note.getByText(/times out after two minutes/)).toBeInTheDocument();
    expect(screen.queryByLabelText("what install does")).not.toBeInTheDocument();
  });
});

describe("installed", () => {
  it.each([
    [{ kind: "download", host: "github.com" }, "downloaded from github.com"],
    [
      { kind: "mirror", host: "artifacts.corp.example" },
      "downloaded from your mirror artifacts.corp.example",
    ],
    [
      { kind: "import", path: "/opt/pam/" + ASSET, imported_at_ms: 1_790_000_000_000 },
      `imported from a local file, /opt/pam/${ASSET} on 2026-09-21 (copied; the original was not changed)`,
    ],
    [null, "source not recorded"],
  ] as const)("shows the source %j", async (source, words) => {
    mockBridge({
      "admin.models.engine.status": () =>
        installed({ source: source as EngineStatus["source"] }),
    });
    mount();
    const card = within(await screen.findByLabelText("installed engine"));
    expect(card.getByText(words)).toBeInTheDocument();
    expect(card.getByText(ASSET)).toBeInTheDocument();
    expect(card.getByText("69f236c8aa14…cb8399")).toBeInTheDocument();
    expect(card.getByText(/version: 1234 \(abcdef0\)/)).toBeInTheDocument();
    expect(card.getByText("/Users/dev/.pam/engine/llama-b1234")).toBeInTheDocument();
    expect(card.getByText(/only while a model is loaded/)).toBeInTheDocument();
    expect(
      card.getByText(/press Remove engine, or stop the daemon and delete/),
    ).toBeInTheDocument();
  });

  it("reads the source from the manifest when the top level has none", async () => {
    mockBridge({
      "admin.models.engine.status": () =>
        installed({
          source: undefined,
          manifest: manifest({
            asset: ASSET,
            sha256: SHA,
            source: { kind: "download", host: "github.com" },
          }),
        }),
    });
    mount();
    expect(await screen.findByText("downloaded from github.com")).toBeInTheDocument();
  });
});

describe("remove", () => {
  it("takes two taps, then sends remove with confirm and refreshes status", async () => {
    mockBridge({
      "admin.models.engine.status": () => installed(),
      "admin.models.engine.remove": () => ({
        removed: true,
        engine_dir: "/Users/dev/.pam/engine",
        entries_removed: 4,
        status: status(),
      }),
    });
    const invalidate = mount();
    const button = await screen.findByRole("button", { name: "Remove engine" });
    await waitFor(() => expect(button).toBeEnabled());
    fireEvent.click(button);
    expect(callsOf("admin.models.engine.remove")).toHaveLength(0);
    fireEvent.click(screen.getByRole("button", { name: "Remove the engine?" }));
    await waitFor(() =>
      expect(bridge.invoke).toHaveBeenCalledWith("admin_call", {
        op: "admin.models.engine.remove",
        args: { confirm: true },
      }),
    );
    await waitFor(() =>
      expect(invalidate).toHaveBeenCalledWith({ queryKey: ["engine", "status"] }),
    );
  });

  it("is disabled with the reason while a model is loaded", async () => {
    mockBridge({
      "admin.models.engine.status": () => installed({ removable: false, loaded: true }),
    });
    mount();
    const button = await screen.findByRole("button", { name: "Remove engine" });
    expect(button).toBeDisabled();
    expect(button).toHaveAttribute("title", expect.stringContaining("A model is loaded"));
    expect(
      screen.getByText(/Remove engine is unavailable\. A model is loaded/),
    ).toBeInTheDocument();
    fireEvent.click(button);
    expect(callsOf("admin.models.engine.remove")).toHaveLength(0);
  });

  it("is not offered when nothing is installed", async () => {
    mockBridge({ "admin.models.engine.status": () => status(plan()) });
    mount();
    await screen.findByText("Not installed");
    expect(screen.queryByRole("button", { name: "Remove engine" })).not.toBeInTheDocument();
  });

  it("renders a refused remove through the failure note", async () => {
    mockBridge({
      "admin.models.engine.status": () => installed(),
      "admin.models.engine.remove": () => {
        throw {
          cause: "engine_busy",
          detail: "A model is loaded on the engine",
          recovery: "Unload the model on the Models screen, then remove the engine",
        };
      },
    });
    mount();
    const button = await screen.findByRole("button", { name: "Remove engine" });
    await waitFor(() => expect(button).toBeEnabled());
    fireEvent.click(button);
    fireEvent.click(screen.getByRole("button", { name: "Remove the engine?" }));
    expect(await screen.findByText(/engine · engine_busy/)).toBeInTheDocument();
    expect(screen.getByText(/Unload the model on the Models screen/)).toBeInTheDocument();
  });
});

describe("install from a file", () => {
  async function openPanel() {
    mockBridge({ "admin.models.engine.status": () => status(plan()) });
    mount();
    const open = await screen.findByRole("button", { name: "Install from a file…" });
    await waitFor(() => expect(open).toBeEnabled());
    fireEvent.click(open);
    return within(await screen.findByRole("group", { name: "install from a file" }));
  }

  it("shows the expected file name, size and digest, and says there is no file picker", async () => {
    const panel = await openPanel();
    expect(
      panel.getByText(
        /Give the path of the llama.cpp release archive, or a folder that contains it/,
      ),
    ).toBeInTheDocument();
    expect(panel.getAllByText(ASSET).length).toBeGreaterThan(0);
    expect(panel.getByText(SHA)).toBeInTheDocument();
    expect(panel.getByText(/Type the path: this app has no file picker/)).toBeInTheDocument();
    expect(panel.getByText(/leaves the original untouched/)).toBeInTheDocument();
    expect(panel.getByText(/An\s+archive from any other build is refused/)).toBeInTheDocument();
  });

  it("needs a path and a second tap, then sends engine.import with the path and confirm", async () => {
    const panel = await openPanel();
    const go = panel.getByRole("button", { name: "Install from this file" });
    expect(go).toBeDisabled();
    fireEvent.change(panel.getByLabelText("engine archive path"), {
      target: { value: "/opt/pam" },
    });
    expect(callsOf("admin.models.engine.import")).toHaveLength(0);
    mockBridge({
      "admin.models.engine.status": () => status(plan()),
      "admin.models.engine.import": () => new Promise<EngineStatus>(() => {}),
    });
    fireEvent.click(go);
    expect(callsOf("admin.models.engine.import")).toHaveLength(0);
    fireEvent.click(panel.getByRole("button", { name: "Copy, check and install?" }));
    await waitFor(() =>
      expect(bridge.invoke).toHaveBeenCalledWith("admin_call", {
        op: "admin.models.engine.import",
        args: { path: "/opt/pam", confirm: true },
      }),
    );
    const note = within(await screen.findByRole("status", { name: "installing" }));
    expect(note.getByText("/opt/pam")).toBeInTheDocument();
    expect(note.getByText(/checking its SHA-256/)).toBeInTheDocument();
    expect(callsOf("admin.models.engine.install")).toHaveLength(0);
  });

  it.each([
    [
      "engine_import_not_the_asset",
      "expected llama-b1234-bin-macos-arm64.tar.gz (11146574 bytes)",
      "Give the archive or a folder that holds it by that name.",
    ],
    [
      "engine_digest_mismatch",
      "the copy hashes to 1111, this PAM build pins llama.cpp b1234",
      "Get the archive again from the release page.",
    ],
    ["engine_import_symlink", "the path is a symbolic link", "Give the real file, not a link."],
    [
      "engine_no_space",
      "11 MB needed, 2 MB free",
      "Free space on the volume that holds the engine folder.",
    ],
    [
      "engine_verify_failed",
      "the server reported build 1200, not 1234",
      "Use the archive for this PAM build.",
    ],
    ["engine_import_source_missing", "no such file: /opt/pam", "Check the path."],
    [
      "engine_size_mismatch",
      "the file is 5 bytes, expected 11146574",
      "Use the pinned archive.",
    ],
  ])("renders the refusal %s through the failure note", async (cause, detail, recovery) => {
    const panel = await openPanel();
    mockBridge({
      "admin.models.engine.status": () => status(plan()),
      "admin.models.engine.import": () => {
        throw { cause, detail, recovery };
      },
    });
    fireEvent.change(panel.getByLabelText("engine archive path"), {
      target: { value: "/opt/pam" },
    });
    fireEvent.click(panel.getByRole("button", { name: "Install from this file" }));
    fireEvent.click(panel.getByRole("button", { name: "Copy, check and install?" }));
    expect(await screen.findByText(new RegExp(`engine · ${cause}`))).toBeInTheDocument();
    expect(screen.getByText(new RegExp(detail.replace(/[()]/g, "\\$&")))).toBeInTheDocument();
    expect(screen.getByText(recovery)).toBeInTheDocument();
    // A refusal that is not about the network does not point at Settings › Network.
    expect(screen.queryAllByRole("button", { name: "Open Settings › Network" })).toHaveLength(
      0,
    );
  });

  it("is not offered for a platform with no release", async () => {
    mockBridge({ "admin.models.engine.status": () => status({ cause: "unsupported_target" }) });
    mount();
    await screen.findByText("No release for this platform");
    expect(
      screen.queryByRole("button", { name: "Install from a file…" }),
    ).not.toBeInTheDocument();
  });
});

describe("a network failure", () => {
  it.each([
    ["dns_failed", "github.com did not resolve."],
    ["proxy_unreachable", "Nothing accepted the connection at proxy.corp.example:3128."],
    [
      "tls_untrusted_issuer",
      "The server's certificate was issued by CN=Corp CA, which is not trusted.",
    ],
  ])(
    "shows the daemon's cause %s and recovery, with a link to Settings › Network",
    async (cause, detail) => {
      const open = vi.fn();
      mockBridge({
        "admin.models.engine.status": () => status(plan()),
        "admin.models.engine.install": () => {
          throw {
            cause,
            detail,
            recovery: "Set a proxy or import the root in Settings › Network.",
          };
        },
      });
      mount(open);
      const button = await screen.findByRole("button", { name: "Install engine" });
      await waitFor(() => expect(button).toBeEnabled());
      fireEvent.click(button);
      expect(await screen.findByText(new RegExp(`engine · ${cause}`))).toBeInTheDocument();
      // FailureNote adds the full stop the daemon's sentence already carries.
      expect(screen.getByText(detail)).toBeInTheDocument();
      const failureLinks = screen.getAllByRole("button", { name: "Open Settings › Network" });
      fireEvent.click(failureLinks[failureLinks.length - 1]);
      expect(open).toHaveBeenCalled();
    },
  );

  it("links when the engine download failed and the detail names a network cause", async () => {
    mockBridge({
      "admin.models.engine.status": () => status(plan()),
      "admin.models.engine.install": () => {
        throw {
          cause: "engine_download_failed",
          detail: "the transfer ended: dns_failed",
          recovery: "Check the network.",
        };
      },
    });
    const open = vi.fn();
    mount(open);
    const button = await screen.findByRole("button", { name: "Install engine" });
    await waitFor(() => expect(button).toBeEnabled());
    const before = screen.getAllByRole("button", { name: "Open Settings › Network" }).length;
    fireEvent.click(button);
    await screen.findByText(/engine · engine_download_failed/);
    // One link from the disclosure, one more under the failure.
    expect(screen.getAllByRole("button", { name: "Open Settings › Network" })).toHaveLength(
      before + 1,
    );
  });
});

describe("managed policy", () => {
  const entry = {
    source: "policy" as const,
    locked: false,
    mode: "forbid" as const,
    constraint: { engine_source: "import_only" },
    state: "applied" as const,
  };

  it("closes Install and says why when only import is allowed", async () => {
    mockBridge({
      "admin.models.engine.status": () =>
        status({
          ...plan(),
          source_policy: {
            engine_source: "import_only",
            install_allowed: false,
            install_blocked: "import_only",
            import_allowed: true,
            effective: entry,
          },
        }),
    });
    mount();
    const install = await screen.findByRole("button", { name: "Install engine" });
    await waitFor(() => expect(install).toBeDisabled());
    expect(
      screen.getByText(/only allows installing the engine from a file you already have/),
    ).toBeInTheDocument();
    expect(screen.getByText("Limited by your organization")).toBeInTheDocument();
    // Import is the way in, and stays open.
    expect(screen.getByRole("button", { name: "Install from a file…" })).toBeEnabled();
  });

  it("closes Install when a mirror is required and none is set", async () => {
    mockBridge({
      "admin.models.engine.status": () =>
        status({
          ...plan(),
          source_policy: {
            engine_source: "mirror_only",
            install_allowed: false,
            install_blocked: "mirror_missing",
            import_allowed: true,
          },
        }),
    });
    mount();
    const install = await screen.findByRole("button", { name: "Install engine" });
    await waitFor(() => expect(install).toBeDisabled());
    expect(
      screen.getByText(/from a mirror, and none is set in Settings › Network/),
    ).toBeInTheDocument();
  });

  it("closes the file import when the policy does not allow importing", async () => {
    mockBridge({
      "admin.models.engine.status": () =>
        status({
          ...plan(),
          source_policy: {
            engine_source: "download",
            install_allowed: true,
            install_blocked: null,
            import_allowed: false,
          },
        }),
    });
    mount();
    const file = await screen.findByRole("button", { name: "Install from a file…" });
    await waitFor(() => expect(file).toBeDisabled());
    expect(screen.getByText(/does not allow importing files/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Install engine" })).toBeEnabled();
  });

  it("renders a refused install with the policy's cause, detail and recovery", async () => {
    mockBridge({
      "admin.models.engine.status": () => status(plan()),
      "admin.models.engine.install": () => {
        throw {
          cause: "policy_not_allowed",
          detail: "installing the engine from the network is not allowed on this machine",
          recovery: "Managed by your organisation's policy; ask your administrator.",
        };
      },
    });
    mount();
    await screen.findByText("Not installed");
    const button = screen.getByRole("button", { name: "Install engine" });
    await waitFor(() => expect(button).toBeEnabled());
    fireEvent.click(button);
    expect(await screen.findByText(/engine · policy_not_allowed/)).toBeInTheDocument();
    expect(screen.getByText(/ask your administrator/)).toBeInTheDocument();
  });

  it("says nothing about policy when none is in play", async () => {
    mockBridge({ "admin.models.engine.status": () => status(plan()) });
    mount();
    await screen.findByRole("button", { name: "Install engine" });
    expect(screen.queryByText(/organization/)).toBeNull();
  });
});
