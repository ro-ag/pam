import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { LoaderCircle } from "lucide-react";
import { useState } from "react";
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
  type CredentialPatch,
} from "../lib/ipc";
import { exactTime, relativeTime } from "../lib/time";

/**
 * Settings → Connectors: where a human hands pam a credential and points
 * it at a service.
 *
 * This screen is the only door. No agent, CLI, or MCP call builds one of
 * these envelopes — an agent that could configure a connector could grant
 * itself reach it does not have. What an agent *can* do is run a flow
 * step against a connector a human already enabled.
 *
 * Three states a credential can be in are three different sentences, and
 * pam-old taught us to keep them apart: "no credential stored" (the store
 * answered, and it holds nothing), "the store is unavailable" (nobody
 * asked pam anything; the keychain would not talk), and "access denied"
 * (the store answered, and said no). Collapsing them into one "failed"
 * is how an afternoon disappears.
 *
 * A typed secret is never echoed back. It travels once, over the unix
 * socket, into the OS keychain — the field is cleared the moment Set
 * succeeds, and nothing reads it out again.
 */

/** The refusal cause the OS credential store raises when it says no. */
export const CAUSE_STORE_DENIED = "store_denied";

/** The one line the GUI says about a mute credential store. */
export const STORE_UNAVAILABLE_COPY =
  "the OS credential store is unavailable; see the daemon log";

const fieldClasses =
  "h-8 w-full rounded-control field-control border border-control-line bg-inset px-2.5 font-data text-xs text-ink placeholder:text-ink-faint";

/** AWS authenticates by named profile: there is no secret to store. */
function usesProfile(connector: ConnectorSummary): boolean {
  return connector.auth === "aws_profile";
}

function ConnectorRow({ connector }: { connector: ConnectorSummary }) {
  const queryClient = useQueryClient();
  const [baseUrl, setBaseUrl] = useState(connector.base_url ?? "");
  const [username, setUsername] = useState(connector.username ?? "");
  const [secret, setSecret] = useState("");
  const [failure, setFailure] = useState<BridgeFailure | null>(null);
  const [verdict, setVerdict] = useState<ConnectorSummary["last_test"]>(connector.last_test);

  const settle = () => void queryClient.invalidateQueries({ queryKey: ["connectors"] });

  const configure = useMutation({
    mutationFn: (patch: {
      enabled?: boolean;
      base_url?: string | null;
      username?: string | null;
      credential?: CredentialPatch;
    }) => connectorsConfigure(connector.id, patch),
    onMutate: () => setFailure(null),
    onError: (error) => setFailure(toBridgeFailure(error)),
    onSettled: settle,
  });

  const test = useMutation({
    mutationFn: () => connectorsTest(connector.id),
    onMutate: () => setFailure(null),
    onSuccess: (result) => setVerdict(result),
    onError: (error) => setFailure(toBridgeFailure(error)),
    onSettled: settle,
  });

  const profile = usesProfile(connector);
  const denied = failure?.cause === CAUSE_STORE_DENIED;

  return (
    <div
      aria-label={`connector ${connector.name}`}
      className="space-y-3 border-t border-line pt-4 first:border-t-0 first:pt-0"
    >
      <div className="flex flex-wrap items-center gap-2">
        <input
          type="checkbox"
          aria-label={`enable ${connector.name}`}
          checked={connector.enabled}
          disabled={configure.isPending}
          onChange={(event) => configure.mutate({ enabled: event.target.checked })}
          className="size-3.5 cursor-pointer accent-accent-strong"
        />
        <span className="font-sans text-sm font-medium text-ink">{connector.name}</span>
        <span className="font-data text-xs text-ink-faint">{connector.id}</span>
        <span className="flex-1" />
        {connector.credential_present && <Badge tone="success">credential set</Badge>}
        {!connector.store_available && <Badge tone="warning">store unavailable</Badge>}
        {denied && <Badge tone="danger">access denied</Badge>}
      </div>

      {!connector.store_available && (
        <p className="font-data text-xs text-warning">{STORE_UNAVAILABLE_COPY}</p>
      )}

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        {connector.needs_base_url && (
          <label className="space-y-1">
            <span className="block font-data text-xs text-ink-faint">base URL</span>
            <input
              aria-label={`${connector.name} base URL`}
              value={baseUrl}
              onChange={(event) => setBaseUrl(event.target.value)}
              placeholder="https://…"
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
              onChange={(event) => setUsername(event.target.value)}
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
            aria-label={`${connector.name} credential`}
            value={secret}
            onChange={(event) => setSecret(event.target.value)}
            placeholder={
              connector.credential_present ? "stored · type to replace" : "paste it here"
            }
            className={fieldClasses}
          />
        </label>
      )}

      {profile && (
        <p className="font-sans text-sm text-ink-muted">
          This one signs with a named AWS profile from the machine&rsquo;s own credentials —
          there is no secret for me to keep.
        </p>
      )}

      <div className="flex flex-wrap items-center gap-2">
        <Button
          size="sm"
          variant="ghost"
          disabled={configure.isPending}
          onClick={() =>
            configure.mutate({
              ...(connector.needs_base_url ? { base_url: baseUrl.trim() || null } : {}),
              ...(connector.username_label ? { username: username.trim() || null } : {}),
            })
          }
        >
          Save
        </Button>
        {!profile && (
          <>
            <Button
              size="sm"
              disabled={configure.isPending || secret.length === 0}
              onClick={() =>
                configure.mutate(
                  { credential: { set: secret } },
                  // The secret leaves the browser the moment it is
                  // accepted; nothing echoes it back into the field.
                  { onSuccess: () => setSecret("") },
                )
              }
            >
              Set
            </Button>
            <ConfirmButton
              label="Clear"
              confirmLabel="clear it?"
              busy={configure.isPending}
              disabled={!connector.credential_present}
              onConfirm={() => configure.mutate({ credential: { clear: true } })}
            />
          </>
        )}
        <Button
          size="sm"
          variant="ghost"
          disabled={test.isPending}
          onClick={() => test.mutate()}
        >
          {test.isPending && (
            <LoaderCircle aria-hidden="true" className="size-3.5 animate-spin" />
          )}
          Test
        </Button>
        {verdict && (
          <span className="flex flex-wrap items-center gap-2">
            <Badge tone={verdict.status === "passed" ? "success" : "danger"}>
              {verdict.status}
            </Badge>
            <span className="font-data text-xs text-ink-muted">{verdict.detail}</span>
            <span className="font-data text-xs text-ink-faint" title={exactTime(verdict.ts)}>
              {relativeTime(verdict.ts)}
            </span>
          </span>
        )}
      </div>

      {failure && <FailureNote failure={failure} label={connector.id} />}
    </div>
  );
}

export function SettingsConnectorsSection() {
  const connectors = useQuery({ queryKey: ["connectors"], queryFn: connectorsList });
  const failure = connectors.isError ? toBridgeFailure(connectors.error) : null;
  const rows = connectors.data?.connectors ?? [];

  return (
    <Panel ground="raised" className="space-y-4 p-5">
      {failure && <FailureNote failure={failure} label="connectors" />}
      {!failure && connectors.isPending && (
        <p className="font-data text-xs text-ink-faint">asking the keychain…</p>
      )}
      {rows.map((connector) => (
        <ConnectorRow key={connector.id} connector={connector} />
      ))}
    </Panel>
  );
}
