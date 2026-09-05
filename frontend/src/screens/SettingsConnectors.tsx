import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { LoaderCircle } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { Badge } from "../components/ui/Badge";
import { Button } from "../components/ui/Button";
import { ConfirmButton } from "../components/ui/ConfirmButton";
import { FailureNote } from "../components/ui/FailureNote";
import { Panel } from "../components/ui/Panel";
import {
  connectorsConfigure,
  connectorsList,
  connectorsTest,
  toBridgeFailure,
  type BridgeFailure,
  type ConnectorSummary,
} from "../lib/ipc";
import { exactTime, relativeTime } from "../lib/time";

export const CAUSE_STORE_DENIED = "store_denied";
export const STORE_UNAVAILABLE_COPY =
  "the OS credential store is unavailable; see the daemon log";
const fieldClasses =
  "h-8 w-full rounded-control field-control border border-control-line bg-inset px-2.5 font-data text-xs text-ink placeholder:text-ink-faint disabled:opacity-50";

// These examples follow PAM's actual adapter contracts, especially Jira's
// bearer token and SharePoint's Microsoft Graph endpoint.
const GUIDANCE: Record<string, { url?: string; help: string }> = {
  github: {
    url: "https://api.github.com",
    help: "Use a GitHub access token with read access to the repositories and workflow runs your flows inspect. For Enterprise, use its API base URL.",
  },
  jenkins: {
    url: "https://jenkins.example.com",
    help: "Use your Jenkins user name and an API token from that user's configuration, with permission to read the required jobs and builds.",
  },
  sonarqube: {
    url: "https://sonar.example.com",
    help: "Use a SonarQube user token with permission to browse the projects and read their quality gates and issues.",
  },
  jira: {
    url: "https://jira.example.com",
    help: "This adapter uses a bearer personal access token, such as Jira Data Center provides. A Cloud email/API-token pair is not supported here. Grant only the issue and project read access your flows need.",
  },
  confluence: {
    url: "https://your-team.atlassian.net/wiki",
    help: "Use your account email and API token for this Confluence site, with permission to read the spaces and pages your flows use. Keep any site path, such as /wiki, in the URL.",
  },
  sharepoint: {
    url: "https://graph.microsoft.com/v1.0",
    help: "Use a Microsoft Graph bearer access token authorized to read the required SharePoint sites and files. This form does not sign in or renew expiring tokens.",
  },
  aws: {
    help: "Use a named AWS profile already configured on this machine. Leave the profile blank for the default credential chain. The profile needs only the read permissions for your flow; there is no secret for PAM to store.",
  },
};

type Action = { kind: "save-test" } | { kind: "enable"; enabled: boolean } | { kind: "clear" };

function ConnectorRow({
  connector,
  blocked,
  targeted,
}: {
  connector: ConnectorSummary;
  blocked: boolean;
  targeted: boolean;
}) {
  const queryClient = useQueryClient();
  const card = useRef<HTMLDivElement>(null);
  const locked = useRef(false);
  const [baseUrl, setBaseUrl] = useState(connector.base_url ?? "");
  const [username, setUsername] = useState(connector.username ?? "");
  const [secret, setSecret] = useState("");
  const [dirty, setDirty] = useState(false);
  const [failure, setFailure] = useState<BridgeFailure | null>(null);
  const [verdict, setVerdict] = useState(connector.last_test);
  const profile = connector.auth === "aws_profile";
  const guidance = GUIDANCE[connector.id];

  useEffect(() => {
    if (targeted) {
      card.current?.focus();
      card.current?.scrollIntoView?.({ block: "center" });
    }
  }, [targeted]);

  const save = useMutation({
    // Only the action name is kept in React Query's mutation cache. A secret
    // is sent directly to configure, then cleared as soon as storage succeeds.
    mutationFn: async (action: Action) => {
      setFailure(null);
      await queryClient.cancelQueries({ queryKey: ["connectors"] });
      const next = await connectorsConfigure(
        connector.id,
        action.kind === "enable"
          ? { enabled: action.enabled }
          : action.kind === "clear"
            ? { credential: { clear: true } }
            : {
                ...(connector.needs_base_url ? { base_url: baseUrl.trim() || null } : {}),
                ...(connector.username_label ? { username: username.trim() || null } : {}),
                ...(!profile && secret ? { credential: { set: secret } } : {}),
              },
      );
      if (action.kind !== "enable") {
        setSecret("");
        setDirty(false);
        setVerdict(undefined);
      }
      queryClient.setQueryData<{ connectors: ConnectorSummary[] }>(
        ["connectors"],
        (previous) =>
          previous
            ? {
                connectors: previous.connectors.map((row) => (row.id === next.id ? next : row)),
              }
            : previous,
      );
      if (action.kind === "save-test") setVerdict(await connectorsTest(connector.id));
    },
    onError: (error) => setFailure(toBridgeFailure(error)),
    onSettled: async () => {
      try {
        await queryClient.invalidateQueries({ queryKey: ["connectors"] });
      } finally {
        locked.current = false;
      }
    },
  });
  // A refetch may replace the persisted verdict while mutation callbacks
  // still hold the lock. Reconcile again when the entire save settles.
  useEffect(() => {
    if (!dirty && !save.isPending) {
      setBaseUrl(connector.base_url ?? "");
      setUsername(connector.username ?? "");
      setVerdict(connector.last_test);
    }
  }, [connector, dirty, save.isPending]);
  const busy = blocked || save.isPending;
  function act(action: Action) {
    const current = queryClient.getQueryState(["connectors"]);
    if (
      locked.current ||
      busy ||
      current?.status !== "success" ||
      current.fetchStatus !== "idle"
    )
      return;
    locked.current = true;
    if (action.kind !== "enable") setVerdict(undefined);
    save.mutate(action);
  }
  function edit(update: () => void) {
    if (locked.current || busy) return;
    update();
    setDirty(true);
    setVerdict(undefined);
    setFailure(null);
  }
  const denied = failure?.cause === CAUSE_STORE_DENIED;
  const unavailable =
    !profile && (!connector.store_available || failure?.cause === "store_unavailable");
  const needsUrl = connector.needs_base_url && !baseUrl.trim();
  const needsCredentials =
    !profile &&
    ((!connector.credential_present && !secret) ||
      (connector.auth === "basic_user_secret" && !username.trim()));
  const state = blocked
    ? "Readiness unavailable"
    : unavailable
      ? "Store unavailable"
      : denied
        ? "Store access denied"
        : needsUrl
          ? "Needs URL"
          : needsCredentials || failure?.cause === "credential_missing"
            ? "Needs credentials"
            : verdict?.status === "failed" || failure
              ? "Test failed"
              : dirty || !verdict
                ? "Untested"
                : connector.enabled
                  ? "Ready"
                  : "Test passed";
  const authRejected =
    verdict?.status === "failed" && verdict.detail === "the stored credential was rejected";

  return (
    <div
      ref={card}
      id={`connector-${connector.id}`}
      tabIndex={-1}
      aria-label={`connector ${connector.name}`}
      className="connector-card space-y-3 rounded-card border border-line bg-surface-raised p-4"
    >
      <div className="flex flex-wrap items-center gap-2">
        <input
          type="checkbox"
          aria-label={`enable ${connector.name}`}
          checked={connector.enabled}
          disabled={busy}
          onChange={(event) => act({ kind: "enable", enabled: event.target.checked })}
          className="size-3.5 cursor-pointer accent-accent-strong"
        />
        <span className="font-sans text-sm font-medium text-ink">{connector.name}</span>
        {!connector.enabled && <Badge>Disabled</Badge>}
        <Badge
          tone={state === "Ready" ? "success" : state === "Test failed" ? "danger" : "neutral"}
        >
          {state}
        </Badge>
        {connector.credential_present && <Badge tone="success">credential set</Badge>}
      </div>
      <p className="font-sans text-sm text-ink-muted">
        {guidance?.help ?? "Use a credential with only the read access needed by your flow."}
      </p>
      {unavailable && (
        <p className="font-data text-xs text-warning">{STORE_UNAVAILABLE_COPY}</p>
      )}
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        {connector.needs_base_url && (
          <label className="space-y-1">
            <span className="block font-data text-xs text-ink-faint">base URL</span>
            <input
              aria-label={`${connector.name} base URL`}
              value={baseUrl}
              disabled={busy}
              onChange={(event) => edit(() => setBaseUrl(event.target.value))}
              placeholder={guidance?.url ?? "https://service.example.com"}
              className={fieldClasses}
            />
          </label>
        )}
        {connector.username_label && (
          <label className="space-y-1">
            <span className="block font-data text-xs text-ink-faint">
              {connector.username_label}
            </span>
            <input
              aria-label={`${connector.name} ${connector.username_label}`}
              value={username}
              disabled={busy}
              onChange={(event) => edit(() => setUsername(event.target.value))}
              className={fieldClasses}
            />
          </label>
        )}
      </div>
      {!profile && (
        <label className="block space-y-1">
          <span className="block font-data text-xs text-ink-faint">credential</span>
          <input
            type="password"
            autoComplete="new-password"
            aria-label={`${connector.name} credential`}
            value={secret}
            disabled={busy}
            onChange={(event) => edit(() => setSecret(event.target.value))}
            placeholder={
              connector.credential_present ? "stored · type to replace" : "paste it here"
            }
            className={fieldClasses}
          />
        </label>
      )}
      <div className="flex flex-wrap items-center gap-2">
        <Button
          size="sm"
          disabled={busy || needsUrl || needsCredentials}
          onClick={() => act({ kind: "save-test" })}
        >
          {save.isPending && (
            <LoaderCircle aria-hidden="true" className="size-3.5 animate-spin" />
          )}
          Save and test
        </Button>
        {!profile && (
          <ConfirmButton
            label="Clear"
            confirmLabel="clear it?"
            busy={busy}
            disabled={!connector.credential_present}
            onConfirm={() => act({ kind: "clear" })}
          />
        )}
        {verdict && !dirty && (
          <span className="font-data text-xs text-ink-muted">
            {verdict.detail}{" "}
            <span title={exactTime(verdict.ts)}>{relativeTime(verdict.ts)}</span>
          </span>
        )}
      </div>
      <p className="font-sans text-sm text-ink-muted">
        Save and test checks these edits without enabling flow access. Enable this connector
        explicitly when you want flows to use it.
      </p>
      {authRejected && (
        <p className="font-sans text-sm text-danger">
          Authentication was rejected by the service. Replace the token or check the account;
          the credential store was reached.
        </p>
      )}
      {failure && <FailureNote failure={failure} label={connector.id} />}
    </div>
  );
}

export function SettingsConnectorsSection({ targetId }: { targetId?: string } = {}) {
  const connectors = useQuery({ queryKey: ["connectors"], queryFn: connectorsList });
  const failure = connectors.isError ? toBridgeFailure(connectors.error) : null;
  const rows = connectors.data?.connectors ?? [];
  return (
    <div className="settings-connectors">
      {failure && <FailureNote failure={failure} label="connectors" />}
      {!failure && connectors.isPending && (
        <p className="font-data text-xs text-ink-faint">asking the keychain…</p>
      )}
      <div className="settings-grid connector-grid">
        {rows.map((connector) => (
          <ConnectorRow
            key={connector.id}
            connector={connector}
            blocked={!connectors.isSuccess || connectors.isFetching}
            targeted={connector.id === targetId}
          />
        ))}
      </div>
      {!failure && !connectors.isPending && rows.length === 0 && (
        <Panel ground="raised" className="p-4 text-sm text-ink-muted">
          No connectors available.
        </Panel>
      )}
    </div>
  );
}
