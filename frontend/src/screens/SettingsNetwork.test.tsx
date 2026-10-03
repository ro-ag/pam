import { QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory } from "@tanstack/react-router";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import App, { createAppQueryClient } from "../App";
import type {
  ConnectorSummary,
  NetworkGetReply,
  NetworkSettings,
  NetworkTestResult,
} from "../lib/ipc";
import { applyTheme } from "../lib/theme";
import { createAppRouter } from "../router";
import {
  SettingsNetworkSection,
  checkMirrorUrl,
  checkNoProxy,
  checkProxyUrl,
} from "./SettingsNetwork";

/**
 * Settings → Network against a mocked bridge. The three daemon ops (`admin.network.get`, `.set`
 * and `.test`) are stubbed with the reply shapes of the spec, so these tests pin the contract the
 * daemon side has to meet: validation before the round trip, the typed phrase for a proxy, a
 * password or a CA bundle, a write-only password, the managed-policy read-only line, and every
 * failure cause of the connection test rendered legibly.
 */

const mocks = vi.hoisted(() => ({
  networkGet: vi.fn(),
  networkSet: vi.fn(),
  networkTest: vi.fn(),
  connectorsList: vi.fn(),
  subscribeEvents: vi.fn(),
  daemonStatus: vi.fn(),
  daemonStop: vi.fn(),
  profileGet: vi.fn(),
  grantsList: vi.fn(),
  readDaemonLog: vi.fn(),
}));

vi.mock("../lib/ipc", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/ipc")>();
  return { ...actual, ...mocks };
});

function settings(overrides: Partial<NetworkSettings> = {}): NetworkSettings {
  return {
    proxy: null,
    no_proxy: [],
    ca_bundle: null,
    engine_mirror: null,
    models_mirror: null,
    credential: { present: false, store_available: true },
    ...overrides,
  };
}

function reply(overrides: Partial<NetworkGetReply> = {}): NetworkGetReply {
  return {
    settings: settings(),
    effective: {},
    curl: {
      version: "8.7.1",
      backend: "SecureTransport",
      supports_proxy: true,
      supports_cidr_no_proxy: true,
    },
    ignored_env: [],
    ...overrides,
  };
}

function connector(overrides: Partial<ConnectorSummary> = {}): ConnectorSummary {
  return {
    id: "jenkins",
    name: "Jenkins",
    auth: "basic_user_secret",
    needs_base_url: true,
    enabled: true,
    base_url: "https://jenkins.corp.example",
    credential_present: true,
    store_available: true,
    ...overrides,
  };
}

beforeEach(() => {
  applyTheme("ventisquero", "dark", { persist: false });
  for (const mock of Object.values(mocks)) mock.mockReset();
  mocks.networkGet.mockResolvedValue(reply());
  mocks.networkSet.mockResolvedValue({});
  mocks.networkTest.mockResolvedValue({ results: [] });
  mocks.connectorsList.mockResolvedValue({ connectors: [connector()] });
  mocks.subscribeEvents.mockResolvedValue(() => {});
  mocks.daemonStatus.mockResolvedValue({ connected: false, status: null });
  mocks.daemonStop.mockResolvedValue({ outcome: "not_running", pid: null });
  mocks.profileGet.mockResolvedValue({ profile: "standard" });
  mocks.grantsList.mockResolvedValue({ grants: [] });
  mocks.readDaemonLog.mockResolvedValue({ file: "/tmp/daemon.log", lines: [] });
});

async function renderSection() {
  render(
    <QueryClientProvider client={createAppQueryClient()}>
      <SettingsNetworkSection />
    </QueryClientProvider>,
  );
  const save = await screen.findByRole("button", { name: "Save network settings" });
  await waitFor(() => expect(screen.getByLabelText("no-proxy list")).toBeEnabled());
  return save;
}

function type(label: string, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}

function confirmPhrase(phrase = "network") {
  type("type network to confirm", phrase);
  const buttons = within(screen.getByRole("group")).getAllByRole("button");
  fireEvent.click(buttons[buttons.length - 1]);
}

describe("validation rules", () => {
  it.each([
    ["", null, undefined],
    ["http://proxy.corp.example:3128", "http://proxy.corp.example:3128", undefined],
    ["HTTPS://Proxy.Corp.Example:8443/", "https://proxy.corp.example:8443", undefined],
    ["http://[::1]:3128", "http://[::1]:3128", undefined],
    ["proxy.corp.example:3128", undefined, /did you mean http:\/\/proxy.corp.example:3128/],
    ["socks5://proxy.corp.example:1080", undefined, /SOCKS proxies are not supported/],
    ["ftp://proxy.corp.example:21", undefined, /Only http:\/\/ and https:\/\//],
    ["http://proxy.corp.example", undefined, /Add the port/],
    ["http://user:pw@proxy.corp.example:3128", undefined, /Leave the user name and password/],
    ["http://proxy.corp.example:3128/path", undefined, /cannot have a path/],
    ["http://proxy.corp.example:3128/?a=b", undefined, /cannot have a query/],
    ["http://proxy.corp.example:3128/#x", undefined, /cannot have a fragment/],
    ["http://proxy.corp.example:70000", undefined, /between 1 and 65535/],
  ])("proxy address %j", (raw, value, error) => {
    const checked = checkProxyUrl(raw);
    if (error) expect(checked.error).toMatch(error);
    else expect(checked).toEqual({ value });
  });

  it.each([
    ["", null, undefined],
    [
      "https://artifacts.corp.example/llama.cpp/b10938",
      "https://artifacts.corp.example/llama.cpp/b10938/",
      undefined,
    ],
    ["https://10.1.2.3:8443/x/", "https://10.1.2.3:8443/x/", undefined],
    ["http://artifacts.corp.example/", undefined, /https:\/\//],
    ["https://localhost/x/", undefined, /cannot be on this computer/],
    ["https://127.0.0.1/x/", undefined, /cannot be on this computer/],
    ["https://169.254.169.254/latest/", undefined, /cannot be on this computer/],
    ["https://[::1]/x/", undefined, /cannot be on this computer/],
    ["https://u:p@mirror.corp.example/", undefined, /user name and password/],
    ["https://mirror.corp.example/a/../b/", undefined, /\.\. path segments/],
    ["https://mirror.corp.example/a?x=1", undefined, /cannot have a query/],
  ])("mirror address %j", (raw, value, error) => {
    const checked = checkMirrorUrl(raw);
    if (error) expect(checked.error).toMatch(error);
    else expect(checked).toEqual({ value });
  });

  it("normalizes the no-proxy list and refuses what curl would not match", () => {
    expect(
      checkNoProxy(
        "Jenkins.Corp.Example, .internal.example\n10.0.0.0/8\njenkins.corp.example",
        true,
        "8.7.1",
      ),
    ).toEqual({
      value: ["jenkins.corp.example", ".internal.example", "10.0.0.0/8"],
    });
    expect(checkNoProxy("*", true, "8.7.1")).toEqual({ value: ["*"] });
    expect(checkNoProxy("<local>", true, "8.7.1").error).toMatch(/not supported/);
    expect(checkNoProxy("https://a.example", true, "8.7.1").error).toMatch(/is a URL/);
    expect(checkNoProxy("a.example:8080", true, "8.7.1").error).toMatch(/has a port/);
    expect(checkNoProxy("*.example", true, "8.7.1").error).toMatch(/wildcard/);
    expect(checkNoProxy("10.0.0.0/8", false, "7.79.1").error).toMatch(/7\.86.*7\.79\.1/);
    const many = Array.from({ length: 65 }, (_, i) => `h${i}.example`).join("\n");
    expect(checkNoProxy(many, true, "8.7.1").error).toMatch(/At most 64/);
  });
});

describe("the form", () => {
  it("says what the settings affect and never affect, and that the environment is not read", async () => {
    await renderSection();
    const disclosure = screen.getByText(/These settings apply to requests PAM makes/);
    expect(disclosure).toHaveTextContent(/connector services/);
    expect(disclosure).toHaveTextContent(/inference engine and of models/);
    expect(disclosure).toHaveTextContent(/never apply to the engine's own local socket/);
    expect(disclosure).toHaveTextContent(/nothing here is read from environment variables/);
  });

  it("names ignored environment variables without importing them", async () => {
    mocks.networkGet.mockResolvedValue(
      reply({ ignored_env: ["HTTPS_PROXY", "SSL_CERT_FILE"] }),
    );
    await renderSection();
    expect(
      screen.getByText(/Ignored in the daemon's environment: HTTPS_PROXY, SSL_CERT_FILE/),
    ).toBeInTheDocument();
  });

  it("starts from what the daemon reports and keeps Save disabled until something changes", async () => {
    mocks.networkGet.mockResolvedValue(
      reply({
        settings: settings({
          proxy: { url: "http://proxy.corp.example:3128", auth: "basic", username: "svc-pam" },
          no_proxy: ["jenkins.corp.example", ".internal.example"],
          engine_mirror: "https://artifacts.corp.example/llama.cpp/b10938/",
        }),
      }),
    );
    const save = await renderSection();
    await waitFor(() =>
      expect(screen.getByLabelText("proxy URL")).toHaveValue("http://proxy.corp.example:3128"),
    );
    expect(screen.getByLabelText("proxy sign-in")).toHaveValue("basic");
    expect(screen.getByLabelText("proxy user name")).toHaveValue("svc-pam");
    expect(screen.getByLabelText("no-proxy list")).toHaveValue(
      "jenkins.corp.example\n.internal.example",
    );
    expect(screen.getByLabelText("engine mirror URL")).toHaveValue(
      "https://artifacts.corp.example/llama.cpp/b10938/",
    );
    expect(save).toBeDisabled();
    expect(save).toHaveAttribute("title", "Nothing has changed");
  });

  it("shows why a proxy address is refused and blocks Save", async () => {
    const save = await renderSection();
    type("proxy URL", "socks5://proxy.corp.example:1080");
    expect(await screen.findByRole("alert")).toHaveTextContent(
      /SOCKS proxies are not supported/,
    );
    expect(save).toBeDisabled();
    expect(save).toHaveAttribute("title", "Fix the highlighted fields first");
    type("proxy URL", "proxy.corp.example:3128");
    expect(screen.getByRole("alert")).toHaveTextContent(
      /did you mean http:\/\/proxy.corp.example:3128/,
    );
    type("proxy URL", "http://proxy.corp.example:3128");
    expect(screen.queryByRole("alert")).toBeNull();
    expect(save).toBeEnabled();
  });

  it("refuses a mirror that is not https or points at this computer", async () => {
    const save = await renderSection();
    type("engine mirror URL", "http://artifacts.corp.example/");
    expect(screen.getByRole("alert")).toHaveTextContent(/https:\/\//);
    type("engine mirror URL", "");
    type("models mirror URL", "https://127.0.0.1/hf/");
    expect(screen.getByRole("alert")).toHaveTextContent(/cannot be on this computer/);
    expect(save).toBeDisabled();
  });
});

describe("saving", () => {
  it("asks for the typed phrase before a proxy, then sends exactly the validated patch", async () => {
    const save = await renderSection();
    type("proxy URL", "HTTP://Proxy.Corp.Example:3128/");
    fireEvent.change(screen.getByLabelText("proxy sign-in"), { target: { value: "basic" } });
    type("proxy user name", " svc-pam ");
    type("proxy password", "s3cret");
    type("no-proxy list", "Jenkins.Corp.Example, .internal.example");
    fireEvent.click(save);

    expect(mocks.networkSet).not.toHaveBeenCalled();
    const group = screen.getByRole("group", { name: "Change how PAM reaches the network?" });
    const confirm = within(group).getByRole("button", { name: "Save network settings" });
    expect(confirm).toBeDisabled();
    fireEvent.change(within(group).getByLabelText("type network to confirm"), {
      target: { value: "nope" },
    });
    expect(confirm).toBeDisabled();
    fireEvent.change(within(group).getByLabelText("type network to confirm"), {
      target: { value: "network" },
    });
    fireEvent.click(confirm);

    await waitFor(() => expect(mocks.networkSet).toHaveBeenCalledTimes(1));
    expect(mocks.networkSet).toHaveBeenCalledWith(
      {
        proxy: { url: "http://proxy.corp.example:3128", auth: "basic", username: "svc-pam" },
        credential: { set: "s3cret" },
        no_proxy: ["jenkins.corp.example", ".internal.example"],
      },
      "network",
    );
    expect(await screen.findByText(/Saved\. Run the test below/)).toBeInTheDocument();
  });

  it("cancels the phrase prompt without saving", async () => {
    const save = await renderSection();
    type("proxy URL", "http://proxy.corp.example:3128");
    fireEvent.click(save);
    const group = screen.getByRole("group", { name: "Change how PAM reaches the network?" });
    fireEvent.click(within(group).getByRole("button", { name: "Cancel" }));
    expect(
      screen.queryByRole("group", { name: "Change how PAM reaches the network?" }),
    ).toBeNull();
    expect(mocks.networkSet).not.toHaveBeenCalled();
  });

  it("saves the no-proxy list and mirrors with no typed phrase", async () => {
    const save = await renderSection();
    type("no-proxy list", "jenkins.corp.example");
    type("engine mirror URL", "https://artifacts.corp.example/llama.cpp/b10938");
    fireEvent.click(save);
    await waitFor(() => expect(mocks.networkSet).toHaveBeenCalledTimes(1));
    expect(screen.queryByRole("group")).toBeNull();
    expect(mocks.networkSet).toHaveBeenCalledWith(
      {
        no_proxy: ["jenkins.corp.example"],
        engine_mirror: "https://artifacts.corp.example/llama.cpp/b10938/",
      },
      undefined,
    );
  });

  it("clears the proxy with null and no phrase, and sends nothing for unchanged fields", async () => {
    mocks.networkGet.mockResolvedValue(
      reply({
        settings: settings({
          proxy: { url: "http://proxy.corp.example:3128", auth: "none", username: null },
          no_proxy: ["a.example"],
        }),
      }),
    );
    const save = await renderSection();
    await waitFor(() =>
      expect(screen.getByLabelText("proxy URL")).toHaveValue("http://proxy.corp.example:3128"),
    );
    type("proxy URL", "");
    fireEvent.click(save);
    await waitFor(() => expect(mocks.networkSet).toHaveBeenCalledTimes(1));
    expect(mocks.networkSet).toHaveBeenCalledWith({ proxy: null }, undefined);
  });

  it("refetches after a save and drops the draft it consumed", async () => {
    const save = await renderSection();
    type("engine mirror URL", "https://artifacts.corp.example/llama.cpp/b10938/");
    mocks.networkGet.mockResolvedValue(
      reply({
        settings: settings({
          engine_mirror: "https://artifacts.corp.example/llama.cpp/b10938/",
        }),
      }),
    );
    fireEvent.click(save);
    await waitFor(() => expect(mocks.networkGet).toHaveBeenCalledTimes(2));
    expect(await screen.findByText(/Saved\./)).toBeInTheDocument();
    expect(screen.getByLabelText("engine mirror URL")).toHaveValue(
      "https://artifacts.corp.example/llama.cpp/b10938/",
    );
    expect(save).toBeDisabled();
  });

  it("renders a daemon refusal with its cause and recovery, and keeps the draft", async () => {
    mocks.networkSet.mockRejectedValue({
      cause: "setting_locked",
      detail: "the proxy is managed by your organization's policy",
      recovery: "Managed by your organization's policy; ask your administrator.",
    });
    const save = await renderSection();
    type("no-proxy list", "jenkins.corp.example");
    fireEvent.click(save);
    expect(await screen.findByText(/network · setting_locked/)).toBeInTheDocument();
    expect(screen.getByText(/ask your administrator/)).toBeInTheDocument();
    expect(screen.getByLabelText("no-proxy list")).toHaveValue("jenkins.corp.example");
    expect(save).toBeEnabled();
  });

  it("reloads when another save won the race", async () => {
    mocks.networkSet.mockRejectedValue({
      cause: "network_settings_conflict",
      detail: "the settings changed while you were editing",
      recovery: "Reload and apply your change again.",
    });
    const save = await renderSection();
    type("engine mirror URL", "https://artifacts.corp.example/x/");
    fireEvent.click(save);
    expect(await screen.findByText(/network_settings_conflict/)).toBeInTheDocument();
    await waitFor(() => expect(mocks.networkGet).toHaveBeenCalledTimes(2));
  });
});

describe("the proxy password", () => {
  it("is write-only: only a stored flag comes back, and the field clears after a save", async () => {
    mocks.networkGet.mockResolvedValue(
      reply({
        settings: settings({
          proxy: { url: "http://proxy.corp.example:3128", auth: "basic", username: "svc" },
          credential: { present: true, store_available: true },
        }),
      }),
    );
    const save = await renderSection();
    expect(await screen.findByText("password is set")).toBeInTheDocument();
    const field = screen.getByLabelText("proxy password");
    expect(field).toHaveValue("");
    expect(field).toHaveAttribute("type", "password");
    expect(field).toHaveAttribute("placeholder", "Stored; type to replace it");

    fireEvent.change(field, { target: { value: "n3w-secret" } });
    fireEvent.click(save);
    confirmPhrase();
    await waitFor(() => expect(mocks.networkSet).toHaveBeenCalledTimes(1));
    expect(mocks.networkSet).toHaveBeenCalledWith(
      { credential: { set: "n3w-secret" } },
      "network",
    );
    await waitFor(() => expect(screen.getByLabelText("proxy password")).toHaveValue(""));
    expect(document.body.textContent).not.toContain("n3w-secret");
  });

  it("clears the stored password only after an explicit second tap, without the phrase", async () => {
    mocks.networkGet.mockResolvedValue(
      reply({
        settings: settings({
          proxy: { url: "http://proxy.corp.example:3128", auth: "basic", username: "svc" },
          credential: { present: true, store_available: true },
        }),
      }),
    );
    await renderSection();
    const clear = await screen.findByRole("button", { name: "Clear password" });
    await waitFor(() => expect(clear).toBeEnabled());
    fireEvent.click(clear);
    expect(mocks.networkSet).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "clear it?" }));
    await waitFor(() => expect(mocks.networkSet).toHaveBeenCalledTimes(1));
    expect(mocks.networkSet).toHaveBeenCalledWith({ credential: { clear: true } }, undefined);
  });

  it("refuses a password with no sign-in mode, and warns when none is stored", async () => {
    mocks.networkGet.mockResolvedValue(
      reply({
        settings: settings({
          proxy: { url: "http://proxy.corp.example:3128", auth: "basic", username: "svc" },
        }),
      }),
    );
    await renderSection();
    expect(await screen.findByText(/needs a password, and none is stored/)).toBeInTheDocument();
    expect(screen.getByText("no password stored")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("proxy sign-in"), { target: { value: "none" } });
    expect(screen.getByLabelText("proxy password")).toBeDisabled();
  });

  it("flags an unavailable keychain", async () => {
    mocks.networkGet.mockResolvedValue(
      reply({ settings: settings({ credential: { present: false, store_available: false } }) }),
    );
    await renderSection();
    expect(await screen.findByText(/credential store is unavailable/)).toBeInTheDocument();
  });
});

describe("the CA bundle", () => {
  it("imports a path behind the typed phrase and shows the private copy's facts", async () => {
    await renderSection();
    expect(screen.getByText(/uses this computer's own trust/)).toBeInTheDocument();
    const importButton = screen.getByRole("button", { name: "Import CA bundle" });
    expect(importButton).toBeDisabled();
    type("CA bundle path", "relative/ca.pem");
    expect(screen.getByRole("alert")).toHaveTextContent(/full path/);
    expect(importButton).toBeDisabled();
    type("CA bundle path", "C:\\ProgramData\\corp\\ca.pem");
    fireEvent.click(importButton);
    expect(mocks.networkSet).not.toHaveBeenCalled();
    confirmPhrase();
    await waitFor(() => expect(mocks.networkSet).toHaveBeenCalledTimes(1));
    expect(mocks.networkSet).toHaveBeenCalledWith(
      { ca_bundle: { path: "C:\\ProgramData\\corp\\ca.pem" } },
      "network",
    );
  });

  it("shows the digest prefix, count and a source-changed note, and removes it with two taps", async () => {
    mocks.networkGet.mockResolvedValue(
      reply({
        settings: settings({
          ca_bundle: {
            sha256: "ab12cd34ef56".padEnd(64, "0"),
            certificates: 3,
            source_path: "/etc/corp/ca.pem",
            imported_ts: Math.floor(Date.now() / 1000) - 60,
            source_changed: true,
          },
        }),
        curl: {
          version: "8.7.1",
          backend: "SecureTransport",
          supports_proxy: true,
          supports_cidr_no_proxy: true,
        },
      }),
    );
    await renderSection();
    const card = await screen.findByLabelText("imported CA bundle");
    expect(card).toHaveTextContent("3 certificates");
    expect(card).toHaveTextContent("ab12cd34ef56…");
    expect(card).not.toHaveTextContent("ab12cd34ef560");
    expect(card).toHaveTextContent("/etc/corp/ca.pem");
    expect(card).toHaveTextContent(/source file changed since it was imported/);
    expect(screen.getByText("curl 8.7.1 · SecureTransport")).toBeInTheDocument();
    expect(screen.getByLabelText("CA bundle path")).toHaveValue("/etc/corp/ca.pem");

    fireEvent.click(screen.getByRole("button", { name: "Remove CA bundle" }));
    expect(mocks.networkSet).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "remove it?" }));
    await waitFor(() =>
      expect(mocks.networkSet).toHaveBeenCalledWith({ ca_bundle: null }, undefined),
    );
  });
});

describe("managed policy", () => {
  it("locks what policy owns and lists the allowed mirror hosts", async () => {
    mocks.networkGet.mockResolvedValue(
      reply({
        settings: settings({
          proxy: { url: "http://proxy.corp.example:3128", auth: "none", username: null },
          mirror_allowed_hosts: ["artifacts.corp.example", ".mirror.example"],
        }),
        effective: {
          proxy: { source: "policy", locked: true },
          engine_mirror: { source: "policy", locked: true },
          models_mirror: { source: "user", locked: false },
        },
      }),
    );
    await renderSection();
    await waitFor(() =>
      expect(screen.getByLabelText("proxy URL")).toHaveValue("http://proxy.corp.example:3128"),
    );
    expect(screen.getByLabelText("proxy URL")).toBeDisabled();
    expect(screen.getByLabelText("proxy sign-in")).toBeDisabled();
    expect(screen.getByLabelText("proxy password")).toBeDisabled();
    expect(screen.getByLabelText("engine mirror URL")).toBeDisabled();
    expect(screen.getByLabelText("models mirror URL")).toBeEnabled();
    expect(screen.getAllByText("Managed by your organization").length).toBeGreaterThan(0);
    expect(screen.getByLabelText("allowed mirror hosts")).toHaveTextContent(
      "artifacts.corp.example, .mirror.example",
    );
  });

  it("shows a policy default as editable with the organization default hint", async () => {
    mocks.networkGet.mockResolvedValue(
      reply({
        settings: settings({ no_proxy: ["api.github.test"] }),
        effective: { no_proxy: { source: "policy", locked: false, mode: "default" } },
      }),
    );
    await renderSection();
    await waitFor(() => expect(screen.getByLabelText("no-proxy list")).toBeEnabled());
    expect(screen.getByText("organization default")).toBeInTheDocument();
    expect(screen.queryByText("Managed by your organization")).toBeNull();
  });

  it("says the policy closed the network and why, through the failure note", async () => {
    mocks.networkGet.mockResolvedValue(
      reply({
        settings: settings({}),
        closed_by_policy: {
          key: "network.ca_bundle",
          code: "network_policy_invalid",
          detail: "the pinned CA bundle could not be imported.",
          recovery: "The managed policy's network setting is invalid: ask your administrator.",
        },
      }),
    );
    await renderSection();
    expect(
      await screen.findByText(/network closed by policy · network_policy_invalid/),
    ).toBeInTheDocument();
    expect(screen.getByText("the pinned CA bundle could not be imported.")).toBeInTheDocument();
    expect(screen.getByText(/ask your administrator/)).toBeInTheDocument();
  });

  it("hides the allowed-hosts line when no policy sets one", async () => {
    await renderSection();
    expect(screen.queryByLabelText("allowed mirror hosts")).toBeNull();
    expect(screen.queryByText("Managed by your organization")).toBeNull();
  });
});

describe("test network settings", () => {
  it("offers only enabled, addressed connectors, and says so when there are none", async () => {
    mocks.connectorsList.mockResolvedValue({
      connectors: [
        connector(),
        connector({ id: "sonarqube", name: "SonarQube", base_url: undefined }),
        connector({ id: "jira", name: "Jira", enabled: false }),
        connector({ id: "github", name: "GitHub", needs_base_url: false, base_url: undefined }),
      ],
    });
    await renderSection();
    const select = await screen.findByLabelText("connector to test");
    await waitFor(() => expect(select).toBeEnabled());
    expect(
      within(select)
        .getAllByRole("option")
        .map((o) => o.textContent),
    ).toEqual(["Jenkins · https://jenkins.corp.example", "GitHub"]);
  });

  it("disables the test with a plain note when no connector is configured", async () => {
    mocks.connectorsList.mockResolvedValue({ connectors: [] });
    await renderSection();
    expect(await screen.findByText(/nothing to test/)).toBeInTheDocument();
    expect(screen.getByLabelText("connector to test")).toBeDisabled();
    expect(screen.getByRole("button", { name: "Test network settings" })).toBeDisabled();
  });

  it("shows a running state, then what was proven", async () => {
    mocks.networkGet.mockResolvedValue(
      reply({
        settings: settings({
          proxy: { url: "http://proxy.corp.example:3128", auth: "none", username: null },
        }),
      }),
    );
    let finish: (value: { results: NetworkTestResult[] }) => void = () => {};
    mocks.networkTest.mockReturnValue(new Promise((resolve) => (finish = resolve)));
    await renderSection();
    await waitFor(() => expect(screen.getByLabelText("connector to test")).toBeEnabled());
    fireEvent.click(screen.getByRole("button", { name: "Test network settings" }));
    expect(await screen.findByRole("button", { name: "Testing…" })).toBeDisabled();
    expect(
      screen.getByText(/Reaching the connector through your settings/),
    ).toBeInTheDocument();
    expect(mocks.networkTest).toHaveBeenCalledWith("jenkins");

    await act(async () =>
      finish({
        results: [
          {
            target: "jenkins",
            host: "jenkins.corp.example",
            route: "proxy",
            stage: "http",
            ok: true,
            http_status: 401,
          },
        ],
      }),
    );
    const row = await screen.findByLabelText("result jenkins");
    expect(row).toHaveTextContent("reached");
    expect(row).toHaveTextContent("jenkins.corp.example");
    expect(row).toHaveTextContent("through the proxy proxy.corp.example:3128");
    expect(row).toHaveTextContent("TLS certificate was verified");
    expect(row).toHaveTextContent("HTTP 401");
    expect(screen.getByRole("button", { name: "Test network settings" })).toBeEnabled();
  });

  it("names a bypassed host as direct, matched your no-proxy list", async () => {
    mocks.networkTest.mockResolvedValue({
      results: [
        {
          target: "jenkins",
          host: "jenkins.corp.example",
          route: "bypass",
          stage: "http",
          ok: true,
          http_status: 200,
        },
      ],
    });
    await renderSection();
    await waitFor(() => expect(screen.getByLabelText("connector to test")).toBeEnabled());
    fireEvent.click(screen.getByRole("button", { name: "Test network settings" }));
    expect(await screen.findByLabelText("result jenkins")).toHaveTextContent(
      "direct, matched your no-proxy list",
    );
  });

  it.each<[string, Partial<NetworkTestResult>, string[]]>([
    [
      "proxy unreachable",
      {
        route: "proxy",
        stage: "proxy",
        cause: "proxy_unreachable",
        detail: "Nothing accepted the connection at proxy.corp.example:3128.",
        recovery: "Check the proxy address and port, and that this network can reach it.",
      },
      [
        "jenkins · jenkins.corp.example · proxy_unreachable",
        "Nothing accepted the connection at proxy.corp.example:3128.",
        "Check the proxy address and port",
        "connected to the proxy, then stopped",
      ],
    ],
    [
      "proxy authentication required",
      {
        route: "proxy",
        stage: "proxy",
        cause: "proxy_auth_required",
        detail: "The proxy wants authentication. It offers: Basic, NTLM.",
        recovery: "Set the sign-in mode and a user name and password under Proxy.",
      },
      [
        "proxy_auth_required",
        "The proxy wants authentication. It offers: Basic, NTLM.",
        "Set the sign-in mode",
      ],
    ],
    [
      "TLS untrusted issuer",
      {
        route: "proxy",
        stage: "tunnel",
        cause: "tls_untrusted_issuer",
        detail:
          "The server's certificate was issued by CN=Corp Inspection CA, which is not trusted.",
        recovery:
          "If your organization inspects TLS, import its root CA in Settings › Network, or ask IT to deploy it to this computer's trust store.",
      },
      [
        "tls_untrusted_issuer",
        "issued by CN=Corp Inspection CA, which is not trusted.",
        "import its root CA",
        "the proxy tunnel opened, then stopped before TLS",
      ],
    ],
    [
      "DNS",
      {
        route: "bypass",
        stage: "proxy",
        cause: "dns_failed",
        detail: "jenkins.corp.example did not resolve.",
        recovery: "Check the host name, and that this network's DNS can resolve it.",
      },
      [
        "dns_failed",
        "jenkins.corp.example did not resolve.",
        "direct, matched your no-proxy list",
        "connecting, and the first connection did not complete",
      ],
    ],
    [
      "connect timeout",
      {
        route: "direct",
        stage: "proxy",
        cause: "timeout",
        detail: "The connection timed out after 5 seconds.",
        recovery: "Check that the host is reachable from this network.",
      },
      [
        "jenkins · jenkins.corp.example · timeout",
        "The connection timed out after 5 seconds.",
        "connecting, and the first connection did not complete",
      ],
    ],
    [
      "direct connection refused, reported with the explicit connect stage",
      {
        route: "direct",
        stage: "connect",
        cause: "connect_failed",
        detail: "Nothing accepted the connection.",
        recovery: "Check that the host is reachable from this network.",
      },
      ["connect_failed", "Nothing accepted the connection.", "Route: direct connection"],
    ],
  ])(
    "renders the %s failure as cause, sentence and recovery",
    async (_name, partial, expected) => {
      mocks.networkTest.mockResolvedValue({
        results: [
          {
            target: "jenkins",
            host: "jenkins.corp.example",
            route: "direct",
            stage: "proxy",
            ok: false,
            http_status: null,
            ...partial,
          },
        ],
      });
      await renderSection();
      await waitFor(() => expect(screen.getByLabelText("connector to test")).toBeEnabled());
      fireEvent.click(screen.getByRole("button", { name: "Test network settings" }));
      const row = await screen.findByLabelText("result jenkins");
      for (const text of expected) expect(row).toHaveTextContent(text);
      // The daemon's sentence ends with a full stop and the note adds none of its own.
      expect(row.textContent).not.toMatch(/\.\./);
      expect(row).not.toHaveTextContent("reached");
    },
  );

  it("makes hidden characters in a certificate name visible", async () => {
    mocks.networkTest.mockResolvedValue({
      results: [
        {
          target: "jenkins",
          host: "jenkins.corp.example",
          route: "direct",
          stage: "tunnel",
          ok: false,
          http_status: null,
          cause: "tls_untrusted_issuer",
          detail:
            "The server's certificate was issued by CN=Evil\u202ECA, which is not trusted.",
          recovery: "Import the root.",
        },
      ],
    });
    await renderSection();
    await waitFor(() => expect(screen.getByLabelText("connector to test")).toBeEnabled());
    fireEvent.click(screen.getByRole("button", { name: "Test network settings" }));
    const row = await screen.findByLabelText("result jenkins");
    expect(row).toHaveTextContent("Evil\\u{202E}CA");
    expect(row.textContent).not.toContain("\u202E");
  });

  it("renders a refused test op through the failure note, and never shows the proxy password", async () => {
    mocks.networkGet.mockResolvedValue(
      reply({
        settings: settings({
          proxy: { url: "http://proxy.corp.example:3128", auth: "basic", username: "svc" },
          credential: { present: true, store_available: true },
        }),
      }),
    );
    mocks.networkTest.mockRejectedValue({
      cause: "network_settings_invalid",
      detail: "the stored network settings do not validate",
      recovery: "Open Settings › Network and save them again.",
    });
    await renderSection();
    await waitFor(() => expect(screen.getByLabelText("connector to test")).toBeEnabled());
    fireEvent.click(screen.getByRole("button", { name: "Test network settings" }));
    expect(
      await screen.findByText(/network test · network_settings_invalid/),
    ).toBeInTheDocument();
    expect(screen.getByText(/save them again/)).toBeInTheDocument();
  });

  it("tells you the test uses the saved settings when there are unsaved edits", async () => {
    await renderSection();
    expect(screen.queryByText(/unsaved edits; save them first/)).toBeNull();
    type("no-proxy list", "a.example");
    expect(screen.getByText(/unsaved edits; save them first to test them/)).toBeInTheDocument();
  });
});

describe("in Settings", () => {
  it("opens from the Network tab and keeps the draft when you switch tabs", async () => {
    const router = createAppRouter(
      createMemoryHistory({ initialEntries: ["/settings#network"] }),
    );
    render(<App router={router} />);
    const field = await screen.findByLabelText("no-proxy list");
    await waitFor(() => expect(field).toBeEnabled());
    fireEvent.change(field, { target: { value: "jenkins.corp.example" } });
    fireEvent.change(screen.getByLabelText("proxy URL"), {
      target: { value: "http://proxy.corp.example:3128" },
    });

    fireEvent.click(screen.getByRole("tab", { name: "Retention" }));
    await waitFor(() =>
      expect(screen.getByRole("tab", { name: "Retention" })).toHaveAttribute(
        "aria-selected",
        "true",
      ),
    );
    expect(screen.queryByRole("textbox", { name: "no-proxy list" })).toBeNull();

    fireEvent.click(screen.getByRole("tab", { name: "Network" }));
    expect(await screen.findByLabelText("no-proxy list")).toHaveValue("jenkins.corp.example");
    expect(screen.getByLabelText("proxy URL")).toHaveValue("http://proxy.corp.example:3128");
    expect(screen.getByRole("tabpanel", { name: "Network" })).toHaveTextContent(
      /How PAM reaches connector services and download hosts/,
    );
  });
});
