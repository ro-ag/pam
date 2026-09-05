import { QueryClientProvider } from "@tanstack/react-query";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, expect, it, vi } from "vitest";
import { createAppQueryClient } from "../App";
import type { ConnectorSummary } from "../lib/ipc";
import { SettingsConnectorsSection, STORE_UNAVAILABLE_COPY } from "./SettingsConnectors";
const mocks = vi.hoisted(() => ({
  connectorsList: vi.fn(),
  connectorsConfigure: vi.fn(),
  connectorsTest: vi.fn(),
}));
vi.mock("../lib/ipc", async (original) => ({
  ...(await original<typeof import("../lib/ipc")>()),
  ...mocks,
}));
const passed = { status: "passed" as const, detail: "signed in as octocat", ts: 1000 };
const github: ConnectorSummary = {
  id: "github",
  name: "GitHub",
  auth: "bearer",
  needs_base_url: true,
  enabled: true,
  base_url: "https://api.github.com",
  credential_present: true,
  store_available: true,
};
let current: ConnectorSummary[];
beforeEach(() => {
  current = [
    { ...github },
    {
      ...github,
      id: "confluence",
      name: "Confluence",
      auth: "basic_user_secret",
      username_label: "email",
      enabled: false,
      base_url: undefined,
      credential_present: false,
    },
    {
      ...github,
      id: "aws",
      name: "AWS",
      auth: "aws_profile",
      username_label: "profile",
      needs_base_url: false,
      credential_present: false,
    },
  ];
  mocks.connectorsList.mockImplementation(async () => ({ connectors: current }));
  mocks.connectorsConfigure.mockImplementation(async (id, patch) => {
    const { credential, ...fields } = patch;
    current = current.map((row) =>
      row.id !== id
        ? row
        : {
            ...row,
            ...fields,
            ...(credential ? { credential_present: "set" in credential } : {}),
            ...("enabled" in patch ? {} : { last_test: undefined }),
          },
    );
    return current.find((row) => row.id === id);
  });
  mocks.connectorsTest.mockImplementation(async (id) => {
    current = current.map((row) => (row.id === id ? { ...row, last_test: passed } : row));
    return passed;
  });
});
async function setup(targetId?: string) {
  const client = createAppQueryClient();
  render(
    <QueryClientProvider client={client}>
      <SettingsConnectorsSection targetId={targetId} />
    </QueryClientProvider>,
  );
  await screen.findByLabelText("connector GitHub");
  await waitFor(() => expect(screen.getByLabelText("GitHub base URL")).toBeEnabled());
  return client;
}
function row(name = "GitHub") {
  return within(screen.getByLabelText(`connector ${name}`));
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((yes) => {
    resolve = yes;
  });
  return { promise, resolve };
}

it("explains URL, credentials, disabled and untested states without an AWS secret field", async () => {
  await setup();
  expect(row("Confluence").getByText("Disabled")).toBeInTheDocument();
  expect(row("Confluence").getByText("Needs URL")).toBeInTheDocument();
  expect(row("Confluence").getByLabelText("Confluence base URL")).toHaveAttribute(
    "placeholder",
    "https://your-team.atlassian.net/wiki",
  );
  fireEvent.change(row("Confluence").getByLabelText("Confluence base URL"), {
    target: { value: "https://team.test/wiki" },
  });
  expect(row("Confluence").getByText("Needs credentials")).toBeInTheDocument();
  expect(row().getByText("Untested")).toBeInTheDocument();
  expect(row("AWS").queryByLabelText("AWS credential")).not.toBeInTheDocument();
  expect(row("AWS").getByText(/named AWS profile/)).toBeInTheDocument();
});
it("saves current edits then tests without enabling or retaining a secret in mutation state", async () => {
  const client = await setup();
  const service = row("Confluence");
  fireEvent.change(service.getByLabelText("Confluence base URL"), {
    target: { value: "https://team.test/wiki" },
  });
  fireEvent.change(service.getByLabelText("Confluence email"), {
    target: { value: "dev@test" },
  });
  const secret = service.getByLabelText("Confluence credential");
  expect(secret).toHaveAttribute("type", "password");
  fireEvent.change(secret, { target: { value: "private-token" } });
  fireEvent.click(service.getByRole("button", { name: "Save and test" }));
  await waitFor(() => expect(mocks.connectorsTest).toHaveBeenCalledWith("confluence"));
  expect(mocks.connectorsConfigure).toHaveBeenCalledWith("confluence", {
    base_url: "https://team.test/wiki",
    username: "dev@test",
    credential: { set: "private-token" },
  });
  expect(mocks.connectorsConfigure.mock.invocationCallOrder[0]).toBeLessThan(
    mocks.connectorsTest.mock.invocationCallOrder[0],
  );
  expect(secret).toHaveValue("");
  expect(
    JSON.stringify(
      client
        .getMutationCache()
        .getAll()
        .map((item) => item.state.variables),
    ),
  ).not.toContain("private-token");
  expect(service.getByLabelText("enable Confluence")).not.toBeChecked();
  await waitFor(() => expect(service.getByLabelText("enable Confluence")).toBeEnabled());
  expect(service.getByText("Test passed")).toBeInTheDocument();
  fireEvent.click(service.getByLabelText("enable Confluence"));
  expect(await service.findByText("Ready")).toBeInTheDocument();
  expect(mocks.connectorsConfigure).toHaveBeenLastCalledWith("confluence", { enabled: true });
});
it("serializes double clicks and refuses edits until both saving and testing finish", async () => {
  const saving = deferred<ConnectorSummary>();
  const testing = deferred<typeof passed>();
  mocks.connectorsConfigure.mockReturnValue(saving.promise);
  mocks.connectorsTest.mockReturnValue(testing.promise);
  await setup();
  const button = row().getByRole("button", { name: "Save and test" });
  act(() => {
    fireEvent.click(button);
    fireEvent.click(button);
    fireEvent.click(row().getByLabelText("enable GitHub"));
  });
  await waitFor(() => expect(mocks.connectorsConfigure).toHaveBeenCalledTimes(1));
  expect(mocks.connectorsTest).not.toHaveBeenCalled();
  fireEvent.change(row().getByLabelText("GitHub base URL"), {
    target: { value: "https://stale.test" },
  });
  expect(row().getByLabelText("GitHub base URL")).toHaveValue("https://api.github.com");
  await act(async () => saving.resolve(github));
  await waitFor(() => expect(mocks.connectorsTest).toHaveBeenCalledTimes(1));
  expect(button).toBeDisabled();
  expect(row().getByLabelText("enable GitHub")).toBeDisabled();
  await act(async () => testing.resolve(passed));
  await waitFor(() => expect(button).toBeEnabled());
});
it("removes Ready immediately on edits and preserves drafts across refresh", async () => {
  current[0].last_test = passed;
  const client = await setup();
  expect(row().getByText("Ready")).toBeInTheDocument();
  fireEvent.change(row().getByLabelText("GitHub base URL"), {
    target: { value: "https://new.test" },
  });
  await act(async () => {
    await client.invalidateQueries({ queryKey: ["connectors"] });
  });
  expect(row().getByText("Untested")).toBeInTheDocument();
  expect(row().getByLabelText("GitHub base URL")).toHaveValue("https://new.test");
  expect(row().queryByText("signed in as octocat")).not.toBeInTheDocument();
});
it("does not test after a denied save", async () => {
  mocks.connectorsConfigure.mockRejectedValue({
    cause: "store_denied",
    detail: "store denied access",
    recovery: "Allow keychain access",
  });
  await setup();
  fireEvent.click(row().getByRole("button", { name: "Save and test" }));
  expect(await screen.findByText("Store access denied")).toBeInTheDocument();
  expect(mocks.connectorsTest).not.toHaveBeenCalled();
  expect(screen.queryByText(STORE_UNAVAILABLE_COPY)).not.toBeInTheDocument();
});
it("distinguishes service authentication rejection from credential store failures", async () => {
  mocks.connectorsTest.mockImplementation(async (id) => {
    const verdict = {
      ...passed,
      status: "failed" as const,
      detail: "the stored credential was rejected",
    };
    current = current.map((item) => (item.id === id ? { ...item, last_test: verdict } : item));
    return verdict;
  });
  await setup();
  fireEvent.click(row().getByRole("button", { name: "Save and test" }));
  expect(
    await screen.findByText(/Authentication was rejected by the service/),
  ).toBeInTheDocument();
  expect(row().getByText("Test failed")).toBeInTheDocument();
  expect(screen.queryByText(STORE_UNAVAILABLE_COPY)).not.toBeInTheDocument();
});
it("shows unavailable store separately from absent credentials", async () => {
  current[0].store_available = false;
  current[0].credential_present = false;
  await setup();
  expect(row().getByText("Store unavailable")).toBeInTheDocument();
  expect(row().getByText(STORE_UNAVAILABLE_COPY)).toBeInTheDocument();
});
it("requires confirmation to clear stored credentials", async () => {
  await setup();
  fireEvent.click(row().getByRole("button", { name: "Clear" }));
  expect(mocks.connectorsConfigure).not.toHaveBeenCalled();
  fireEvent.click(row().getByRole("button", { name: "clear it?" }));
  await waitFor(() =>
    expect(mocks.connectorsConfigure).toHaveBeenCalledWith("github", {
      credential: { clear: true },
    }),
  );
  expect(mocks.connectorsTest).not.toHaveBeenCalled();
});
it("focuses the requested connector form", async () => {
  await setup("confluence");
  expect(screen.getByLabelText("connector Confluence")).toHaveFocus();
});

it.each(["credential_missing", "store_unavailable"])(
  "keeps a %s test refusal distinct and clears a saved secret",
  async (cause) => {
    mocks.connectorsTest.mockRejectedValue({
      cause,
      detail: cause,
      recovery: "Check the credential store",
    });
    await setup();
    fireEvent.change(row().getByLabelText("GitHub credential"), {
      target: { value: "new-private-token" },
    });
    fireEvent.click(row().getByRole("button", { name: "Save and test" }));
    expect(await screen.findByText(`github · ${cause}`)).toBeInTheDocument();
    expect(row().getByLabelText("GitHub credential")).toHaveValue("");
    expect(
      row().getByText(
        cause === "credential_missing" ? "Needs credentials" : "Store unavailable",
      ),
    ).toBeInTheDocument();
  },
);

it.each([undefined, { ...passed, status: "failed" as const, detail: "configuration changed" }])(
  "uses the authoritative verdict after the locked post-save refetch (%j)",
  async (last_test) => {
    await setup();
    const refresh = deferred<{ connectors: ConnectorSummary[] }>();
    mocks.connectorsList.mockReturnValue(refresh.promise);
    fireEvent.click(row().getByRole("button", { name: "Save and test" }));
    await waitFor(() => expect(mocks.connectorsList).toHaveBeenCalledTimes(2));
    expect(row().getByRole("button", { name: "Save and test" })).toBeDisabled();
    expect(row().queryByText("Ready")).not.toBeInTheDocument();
    await act(async () => refresh.resolve({ connectors: [{ ...github, last_test }] }));
    await waitFor(() =>
      expect(row().getByRole("button", { name: "Save and test" })).toBeEnabled(),
    );
    expect(row().queryByText("Ready")).not.toBeInTheDocument();
    expect(row().getByText(last_test ? "Test failed" : "Untested")).toBeInTheDocument();
    expect(row().queryByText("signed in as octocat")).not.toBeInTheDocument();
  },
);
it("does not report cached Ready when the current read failed", async () => {
  current[0].last_test = passed;
  const client = await setup();
  expect(row().getByText("Ready")).toBeInTheDocument();
  mocks.connectorsList.mockRejectedValue({
    cause: "offline",
    detail: "read failed",
    recovery: "Retry",
  });
  await act(async () => {
    await client.invalidateQueries({ queryKey: ["connectors"] });
  });
  expect(await row().findByText("Readiness unavailable")).toBeInTheDocument();
  expect(row().queryByText("Ready")).not.toBeInTheDocument();
  expect(row().getByRole("button", { name: "Save and test" })).toBeDisabled();
});
