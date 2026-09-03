import { QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { createAppQueryClient } from "../App";
import type { ConnectorSummary } from "../lib/ipc";
import { SettingsConnectorsSection, STORE_UNAVAILABLE_COPY } from "./SettingsConnectors";

/**
 * Settings → Connectors against a mocked bridge: the row each connector
 * becomes, the three credential states kept apart, and the promise that
 * a typed secret is never echoed back.
 */

const mocks = vi.hoisted(() => ({
  connectorsList: vi.fn(),
  connectorsConfigure: vi.fn(),
  connectorsTest: vi.fn(),
}));

vi.mock("../lib/ipc", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/ipc")>();
  return { ...actual, ...mocks };
});

const nowSec = Math.floor(Date.now() / 1000);

function connector(overrides: Partial<ConnectorSummary>): ConnectorSummary {
  return {
    id: "github",
    name: "GitHub",
    auth: "bearer",
    needs_base_url: false,
    enabled: false,
    credential_present: false,
    store_available: true,
    ...overrides,
  };
}

const CONNECTORS: ConnectorSummary[] = [
  connector({ credential_present: true, enabled: true }),
  connector({ id: "gitlab", name: "GitLab", needs_base_url: true }),
  connector({
    id: "jira",
    name: "Jira",
    auth: "basic_user_secret",
    username_label: "account email",
    needs_base_url: true,
  }),
  connector({ id: "jenkins", name: "Jenkins", auth: "token_as_user", needs_base_url: true }),
  connector({ id: "sonarqube", name: "SonarQube", needs_base_url: true }),
  connector({ id: "artifactory", name: "Artifactory", needs_base_url: true }),
  connector({ id: "aws", name: "AWS", auth: "aws_profile", username_label: "profile" }),
];

beforeEach(() => {
  mocks.connectorsList.mockResolvedValue({ connectors: CONNECTORS });
  mocks.connectorsConfigure.mockImplementation((id: string) =>
    Promise.resolve(connector({ id })),
  );
  mocks.connectorsTest.mockResolvedValue({
    status: "passed",
    detail: "signed in as octocat",
    ts: nowSec - 30,
  });
});

async function renderSection() {
  render(
    <QueryClientProvider client={createAppQueryClient()}>
      <SettingsConnectorsSection />
    </QueryClientProvider>,
  );
  await screen.findByLabelText("connector GitHub");
}

/** The row one connector renders as. */
function row(name: string) {
  return within(screen.getByLabelText(`connector ${name}`));
}

describe("the connector rows", () => {
  it("gives every connector pam knows a row of its own", async () => {
    await renderSection();
    for (const entry of CONNECTORS) {
      expect(screen.getByLabelText(`connector ${entry.name}`)).toBeInTheDocument();
    }
  });

  it("shows a base URL field only where one is needed", async () => {
    await renderSection();
    expect(row("GitLab").getByLabelText("GitLab base URL")).toBeInTheDocument();
    expect(row("GitHub").queryByLabelText("GitHub base URL")).not.toBeInTheDocument();
  });

  it("labels the user field with the connector's own word for it", async () => {
    await renderSection();
    expect(row("Jira").getByLabelText("Jira account email")).toBeInTheDocument();
    expect(row("GitHub").queryByLabelText(/user/)).not.toBeInTheDocument();
  });

  it("offers no credential field at all where AWS uses a profile", async () => {
    await renderSection();
    const aws = row("AWS");
    expect(aws.queryByLabelText("AWS credential")).not.toBeInTheDocument();
    expect(aws.queryByRole("button", { name: "Set" })).not.toBeInTheDocument();
    expect(aws.queryByRole("button", { name: "Clear" })).not.toBeInTheDocument();
    expect(aws.getByText(/named AWS profile/)).toBeInTheDocument();
  });

  it("badges a stored credential and leaves an empty one unbadged", async () => {
    await renderSection();
    expect(row("GitHub").getByText("credential set")).toBeInTheDocument();
    expect(row("GitLab").queryByText("credential set")).not.toBeInTheDocument();
  });

  it("says the store is unavailable in its own words, not as a failure", async () => {
    mocks.connectorsList.mockResolvedValue({
      connectors: [connector({ store_available: false })],
    });
    await renderSection();
    expect(row("GitHub").getByText("store unavailable")).toBeInTheDocument();
    expect(row("GitHub").getByText(STORE_UNAVAILABLE_COPY)).toBeInTheDocument();
  });
});

describe("configuring one", () => {
  it("toggles enabled straight through the daemon", async () => {
    await renderSection();
    fireEvent.click(screen.getByLabelText("enable GitLab"));
    await waitFor(() =>
      expect(mocks.connectorsConfigure).toHaveBeenCalledWith("gitlab", { enabled: true }),
    );
  });

  it("saves the base URL and the user name together", async () => {
    await renderSection();
    const jira = row("Jira");
    fireEvent.change(jira.getByLabelText("Jira base URL"), {
      target: { value: "https://jira.test" },
    });
    fireEvent.change(jira.getByLabelText("Jira account email"), {
      target: { value: "dev@test" },
    });
    fireEvent.click(jira.getByRole("button", { name: "Save" }));
    await waitFor(() =>
      expect(mocks.connectorsConfigure).toHaveBeenCalledWith("jira", {
        base_url: "https://jira.test",
        username: "dev@test",
      }),
    );
  });

  it("sends a secret once and never echoes it back", async () => {
    await renderSection();
    const gitlab = row("GitLab");
    const field = gitlab.getByLabelText("GitLab credential") as HTMLInputElement;
    expect(field).toHaveAttribute("type", "password");
    fireEvent.change(field, { target: { value: "glpat-secret" } });
    fireEvent.click(gitlab.getByRole("button", { name: "Set" }));
    await waitFor(() =>
      expect(mocks.connectorsConfigure).toHaveBeenCalledWith("gitlab", {
        credential: { set: "glpat-secret" },
      }),
    );
    await waitFor(() => expect(field.value).toBe(""));
  });

  it("clears a stored credential behind the two-tap confirm", async () => {
    await renderSection();
    const github = row("GitHub");
    fireEvent.click(github.getByRole("button", { name: "Clear" }));
    expect(mocks.connectorsConfigure).not.toHaveBeenCalled();
    fireEvent.click(github.getByRole("button", { name: "clear it?" }));
    await waitFor(() =>
      expect(mocks.connectorsConfigure).toHaveBeenCalledWith("github", {
        credential: { clear: true },
      }),
    );
  });

  it("keeps a denied store distinct from an absent one", async () => {
    mocks.connectorsConfigure.mockRejectedValue({
      cause: "store_denied",
      detail: "the OS credential store refused pam access to this item",
      recovery: "Allow pam in the keychain prompt, then set the credential again.",
    });
    await renderSection();
    const gitlab = row("GitLab");
    fireEvent.change(gitlab.getByLabelText("GitLab credential"), {
      target: { value: "glpat-secret" },
    });
    fireEvent.click(gitlab.getByRole("button", { name: "Set" }));
    expect(await screen.findByText("access denied")).toBeInTheDocument();
    expect(screen.getByText(/gitlab · store_denied/)).toBeInTheDocument();
    expect(screen.queryByText("store unavailable")).not.toBeInTheDocument();
  });
});

describe("testing one", () => {
  it("puts the verdict, its detail and its age next to the connector", async () => {
    await renderSection();
    fireEvent.click(row("GitHub").getByRole("button", { name: "Test" }));
    const github = row("GitHub");
    expect(await screen.findByText("passed")).toBeInTheDocument();
    await waitFor(() => expect(github.getByText("signed in as octocat")).toBeInTheDocument());
    expect(github.getByText(/^\d+s ago$/)).toBeInTheDocument();
    expect(mocks.connectorsTest).toHaveBeenCalledWith("github");
  });

  it("shows a failing test as an answer, not as a broken screen", async () => {
    mocks.connectorsTest.mockResolvedValue({
      status: "failed",
      detail: "401 from https://api.github.com/user",
      ts: nowSec,
    });
    await renderSection();
    fireEvent.click(row("GitHub").getByRole("button", { name: "Test" }));
    expect(await screen.findByText("failed")).toBeInTheDocument();
    expect(row("GitHub").getByText(/401 from/)).toBeInTheDocument();
  });
});
