import { TextField, SelectField } from "../components/ui/Fields";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate, useRouterState } from "@tanstack/react-router";
import { Check, Copy, LoaderCircle, RefreshCw } from "lucide-react";
import { useId, useRef, useState, type ReactNode } from "react";
import { LayoutGroup, motion } from "motion/react";
import { Badge } from "../components/ui/Badge";
import { Button } from "../components/ui/Button";
import { ConfirmButton } from "../components/ui/ConfirmButton";
import { TypedConfirm } from "../components/ui/TypedConfirm";
import { FailureNote } from "../components/ui/FailureNote";
import { fieldClasses, fieldLabelClasses } from "../components/ui/field";
import { Panel } from "../components/ui/Panel";
import { SafeText } from "../components/ui/SafeText";
import { Section } from "../components/ui/Section";
import {
  DAEMON_STATUS_KEY,
  statusRefetchInterval,
  useStartDaemon,
} from "../components/shell/useDaemonStatus";
import { formatBytes } from "../lib/bytes";
import { cn } from "../lib/cn";
import { backoffRefetchInterval } from "../lib/polling";
import {
  CONFIRM_GRANT,
  CONFIRM_RELAXED,
  HARNESS_PROFILES,
  boundaryStatus,
  containmentStatus,
  daemonStatus,
  daemonStart,
  daemonStop,
  harnessProfileFor,
  grantsAdd,
  grantsList,
  grantsRevoke,
  profileGet,
  profileSet,
  readDaemonLog,
  retentionGet,
  retentionPrune,
  retentionSet,
  serviceInstall,
  serviceStatus,
  serviceUninstall,
  toBridgeFailure,
  versionMismatchNote,
  type BoundaryStatus,
  type BridgeFailure,
  type DaemonStopReply,
  type EffectiveEntry,
  type HarnessProfile,
  type GrantRow,
  type Profile,
  type PruneReport,
  type RetentionSettings,
  type ServiceReport,
} from "../lib/ipc";
import { AppearancePanel } from "./AppearancePanel";
import { ManagedField, ManagedNote, isLocked } from "./ManagedField";
import { PolicyPanel, PolicyStatusLine } from "./SettingsPolicy";
import { exactTime, formatDuration, relativeTime } from "../lib/time";
import { SettingsConnectorsSection } from "./SettingsConnectors";
import { SettingsFlowsSection } from "./SettingsFlows";
import { SettingsModelsSection } from "./SettingsModels";
import { SettingsNetworkSection } from "./SettingsNetwork";

/**
 * Settings — hash-addressed desktop tabs. Visited panes retain form drafts;
 * unvisited panes do not read services until opened. Every control here
 * round-trips against the real bridge, and every refusal it earns renders
 * as the daemon worded it, instead of being pre-empted or swallowed.
 *
 * The design-system living proof that used to squat here is gone — the
 * real app is its own proof now. (The odometer concept returns with the
 * Ask Pam task.)
 */

// --- security: profile -----------------------------------------------------

/** One serif sentence per profile, honest to `pam_daemon::policy`. */
export const PROFILE_SENTENCES: Record<Profile, string> = {
  relaxed:
    "Safe capabilities grant themselves on first use; destructive or external operations still ask once per capability.",
  standard:
    "Nothing runs until you grant its capability here, and destructive or external operations ask for your approval every time.",
  strict:
    "Grants stay manual, and every granted operation that changes anything asks for your approval every single time.",
};

const PROFILE_ORDER: readonly Profile[] = ["relaxed", "standard", "strict"];

/** Why a profile cannot be picked under the managed policy, or undefined when it can. */
export function profileBlocker(
  entry: EffectiveEntry | undefined,
  candidate: Profile,
): string | undefined {
  if (isLocked(entry)) return "Managed by your organization";
  const floor = entry?.constraint?.floor;
  if (typeof floor === "string") {
    const lowest = PROFILE_ORDER.indexOf(floor as Profile);
    if (lowest > PROFILE_ORDER.indexOf(candidate)) {
      return `Your organization does not allow a profile below ${floor}`;
    }
  }
  return undefined;
}

function ProfilePanel() {
  const queryClient = useQueryClient();
  const profile = useQuery({ queryKey: ["profile"], queryFn: profileGet });
  const [applies, setApplies] = useState<string | null>(null);
  // Relaxing the profile widens what agents may do: it asks for a typed confirmation first.
  const [confirmingRelaxed, setConfirmingRelaxed] = useState(false);

  const setProfile = useMutation({
    mutationFn: ({ next, confirmation }: { next: Profile; confirmation?: string }) =>
      profileSet(next, confirmation),
    onMutate: async ({ next }: { next: Profile; confirmation?: string }) => {
      await queryClient.cancelQueries({ queryKey: ["profile"] });
      const previous = queryClient.getQueryData<{ profile: Profile }>(["profile"]);
      queryClient.setQueryData(["profile"], { profile: next });
      setApplies(null);
      return { previous };
    },
    onSuccess: (reply) => {
      // The daemon swaps the running gate at once ("now"). A daemon from
      // before that change answers "next_daemon_start": surface its caveat.
      if (reply.applies === "next_daemon_start") {
        setApplies("applies at next daemon start — restart from the Daemon section below");
      }
    },
    onError: (_error, _next, context) => {
      if (context?.previous) queryClient.setQueryData(["profile"], context.previous);
    },
    onSettled: () => void queryClient.invalidateQueries({ queryKey: ["profile"] }),
  });

  const current = profile.data?.profile;
  const entry = profile.data?.effective?.profile;
  const failure = profile.isError
    ? toBridgeFailure(profile.error)
    : setProfile.isError
      ? toBridgeFailure(setProfile.error)
      : null;

  return (
    <Panel ground="raised" className="space-y-4 p-4">
      <p className="font-data text-xs text-ink-faint">Policy profile</p>
      <ManagedNote entry={entry} />
      <div role="radiogroup" aria-label="policy profile" className="space-y-2">
        {PROFILE_ORDER.map((candidate) => {
          const selected = current === candidate;
          const blocker = profileBlocker(entry, candidate);
          return (
            <label
              key={candidate}
              title={blocker}
              className={cn(
                "flex cursor-pointer items-start gap-3 rounded-card border p-3 transition-colors duration-150",
                selected ? "border-accent-strong bg-accent-soft/40" : "border-line",
                (current === undefined || blocker !== undefined) && "cursor-default opacity-50",
              )}
            >
              <input
                type="radio"
                name="policy-profile"
                value={candidate}
                checked={selected}
                disabled={
                  current === undefined || setProfile.isPending || blocker !== undefined
                }
                onChange={() => {
                  if (candidate === "relaxed") setConfirmingRelaxed(true);
                  else {
                    setConfirmingRelaxed(false);
                    setProfile.mutate({ next: candidate });
                  }
                }}
                className="mt-0.5 size-4.5 shrink-0 accent-accent-strong"
              />
              <span className="space-y-0.5">
                <span className="block font-data text-sm font-medium text-ink">
                  {candidate}
                </span>
                <span className="block font-sans text-sm text-ink-muted">
                  {PROFILE_SENTENCES[candidate]}
                </span>
              </span>
            </label>
          );
        })}
      </div>
      {confirmingRelaxed && (
        <TypedConfirm
          phrase={CONFIRM_RELAXED}
          title="Switch to the relaxed profile?"
          confirmLabel="Switch to relaxed"
          busy={setProfile.isPending}
          onCancel={() => setConfirmingRelaxed(false)}
          onConfirm={(typed) => {
            setConfirmingRelaxed(false);
            setProfile.mutate({ next: "relaxed", confirmation: typed });
          }}
        >
          <p>{PROFILE_SENTENCES.relaxed}</p>
        </TypedConfirm>
      )}
      {applies && (
        <p className="rounded-card bg-accent-soft px-3 py-2 font-data text-xs text-accent">
          {applies}
        </p>
      )}
      {failure && <FailureNote failure={failure} label="profile" />}
    </Panel>
  );
}

// --- security: grants ------------------------------------------------------

/**
 * The daemon's grantable capabilities, for the add datalist — the `CAP_*`
 * constants in `pam_daemon`. `status`, `query` and `cancel` are built-ins
 * every caller already has and cannot be granted.
 */
export const KNOWN_CAPABILITIES = [
  "echo",
  "flow.run",
  "flow.inspect",
  "flow.list",
  "flow.show",
  "flow.result",
  "evidence.read",
] as const;

export const GRANT_BLOCKED_NOTE =
  "your organization's policy does not allow this capability; the grant is kept but does not authorize";
export const GRANT_MANUAL_BLOCKED_NOTE =
  "Your organization's policy does not allow adding grants by hand.";

function GrantRowView({
  grant,
  busy,
  onRevoke,
}: {
  grant: GrantRow;
  busy: boolean;
  onRevoke: () => void;
}) {
  const revoked = grant.revoked_ts !== null;
  const blocked = grant.blocked_by_policy === true && !revoked;
  return (
    <tr className="border-t border-line">
      <td className="py-2.5 pr-3 font-data text-sm text-ink">
        {grant.capability}
        {blocked && (
          <span className="mt-1 block max-w-content font-sans text-xs text-warning">
            {GRANT_BLOCKED_NOTE}
          </span>
        )}
      </td>
      <td className="py-2.5 pr-3 font-data text-xs text-ink-muted">
        {grant.scope}
        {grant.binding?.state === "bound" && (
          <span
            className="mt-1 block max-w-content font-data text-xs text-ink-faint"
            title={`effect ${grant.binding.effect_digest} (${grant.binding.effect_class})`}
          >
            <SafeText value={grant.binding.repository ?? "every repository"} /> · step{" "}
            <SafeText value={grant.binding.effect_digest} />
          </span>
        )}
        {grant.binding?.state === "legacy" && (
          <span className="mt-1 block max-w-content font-sans text-xs text-ink-faint">
            unbound; binds to the step on its next run
          </span>
        )}
      </td>
      <td
        className="py-2.5 pr-3 font-data text-xs text-ink-faint"
        title={exactTime(grant.granted_ts)}
      >
        {relativeTime(grant.granted_ts)}
      </td>
      <td className="py-2.5 pr-3">
        {revoked ? (
          <Badge tone="neutral">revoked</Badge>
        ) : blocked ? (
          <Badge tone="warning">blocked by policy</Badge>
        ) : (
          <Badge tone="success">active</Badge>
        )}
      </td>
      <td className="py-2.5 text-right">
        {!revoked && (
          <ConfirmButton
            label="Revoke"
            confirmLabel="revoke?"
            busy={busy}
            onConfirm={onRevoke}
          />
        )}
      </td>
    </tr>
  );
}

function GrantsPanel() {
  const queryClient = useQueryClient();
  const grants = useQuery({ queryKey: ["grants"], queryFn: grantsList });
  const [draft, setDraft] = useState("");
  const [failure, setFailure] = useState<BridgeFailure | null>(null);
  const [revoking, setRevoking] = useState<string | null>(null);

  const settle = () => void queryClient.invalidateQueries({ queryKey: ["grants"] });

  // A grant is global: it asks for a typed confirmation naming the capability first.
  const [confirming, setConfirming] = useState<string | null>(null);

  const add = useMutation({
    mutationFn: ({ capability, confirmation }: { capability: string; confirmation: string }) =>
      grantsAdd(capability, confirmation),
    onMutate: () => setFailure(null),
    onSuccess: () => setDraft(""),
    onError: (error) => setFailure(toBridgeFailure(error)),
    onSettled: settle,
  });

  const revoke = useMutation({
    mutationFn: (capability: string) => grantsRevoke(capability),
    onMutate: (capability: string) => {
      setFailure(null);
      setRevoking(capability);
    },
    onError: (error) => setFailure(toBridgeFailure(error)),
    onSettled: () => {
      setRevoking(null);
      settle();
    },
  });

  const rows = grants.data?.grants ?? [];
  const listFailure = grants.isError ? toBridgeFailure(grants.error) : null;
  const manual = grants.data?.effective?.manual;
  const manualBlocked = isLocked(manual);
  const never = grants.data?.policy?.never ?? [];
  const neverClasses = grants.data?.policy?.never_classes ?? [];

  return (
    <Panel ground="raised" className="space-y-4 p-4">
      <p className="font-data text-xs text-ink-faint">Capability grants</p>

      {(never.length > 0 || neverClasses.length > 0) && (
        <p
          aria-label="capabilities the policy never allows"
          className="select-text font-sans text-sm text-ink-muted"
        >
          Your organization&apos;s policy never allows
          {never.length > 0 && (
            <>
              {" "}
              <SafeText value={never.join(", ")} />
            </>
          )}
          {neverClasses.length > 0 && (
            <>
              {never.length > 0 ? " and the classes " : " the classes "}
              <SafeText value={neverClasses.join(", ")} />
            </>
          )}
          . A grant for one of them is kept but does not authorize.
        </p>
      )}

      {listFailure && <FailureNote failure={listFailure} label="grants" />}

      {!listFailure && rows.length === 0 && !grants.isPending && (
        <p className="font-sans text-sm text-ink-muted">
          No grants yet. Everything an agent asks for beyond read-only will raise a hand until
          you grant its capability here.
        </p>
      )}

      {rows.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full border-collapse">
            <thead>
              <tr className="text-left font-data text-xs text-ink-faint">
                <th className="pb-2 pr-3 font-medium">capability</th>
                <th className="pb-2 pr-3 font-medium">scope</th>
                <th className="pb-2 pr-3 font-medium">granted</th>
                <th className="pb-2 pr-3 font-medium">state</th>
                <th className="pb-2 font-medium" aria-label="actions" />
              </tr>
            </thead>
            <tbody>
              {rows.map((grant) => (
                <GrantRowView
                  key={grant.id}
                  grant={grant}
                  busy={revoking === grant.capability && revoke.isPending}
                  onRevoke={() => revoke.mutate(grant.capability)}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}

      {manualBlocked && (
        <div className="space-y-1 border-t border-line pt-4">
          <ManagedNote entry={manual} />
          <p className="font-sans text-sm text-ink-muted">{GRANT_MANUAL_BLOCKED_NOTE}</p>
        </div>
      )}

      <form
        className="flex flex-wrap items-end gap-2 border-t border-line pt-4"
        onSubmit={(event) => {
          event.preventDefault();
          const capability = draft.trim();
          if (capability && !manualBlocked) setConfirming(capability);
        }}
      >
        <label className="min-w-48 flex-1 space-y-1">
          <span className={fieldLabelClasses}>Capability to grant</span>
          <TextField
            aria-label="capability to grant"
            list="known-capabilities"
            value={draft}
            disabled={manualBlocked}
            onChange={(event) => setDraft(event.target.value)}
            placeholder="e.g. flow.run"
          />
        </label>
        <datalist id="known-capabilities">
          {KNOWN_CAPABILITIES.map((capability) => (
            <option key={capability} value={capability} />
          ))}
        </datalist>
        <Button
          size="sm"
          type="submit"
          disabled={add.isPending || !draft.trim() || manualBlocked}
          title={
            manualBlocked
              ? GRANT_MANUAL_BLOCKED_NOTE
              : !draft.trim()
                ? "Name a capability first"
                : undefined
          }
        >
          {add.isPending && (
            <LoaderCircle aria-hidden="true" className="size-3.5 animate-spin" />
          )}
          Grant
        </Button>
      </form>

      {confirming !== null && (
        <TypedConfirm
          phrase={CONFIRM_GRANT}
          title={`Grant ${confirming} to every repository?`}
          confirmLabel="Grant"
          busy={add.isPending}
          onCancel={() => setConfirming(null)}
          onConfirm={(typed) => {
            const capability = confirming;
            setConfirming(null);
            add.mutate({ capability, confirmation: typed });
          }}
        >
          <p>
            A grant is not scoped to one repository: every agent may then use this capability
            wherever the active profile allows, until you revoke it here.
          </p>
        </TypedConfirm>
      )}

      {failure && <FailureNote failure={failure} label="grants" />}
    </Panel>
  );
}

// --- daemon ----------------------------------------------------------------

/** Reads one status body field defensively — the body is loosely typed. */
function statusField(status: Record<string, unknown> | null | undefined, key: string): string {
  const value = status?.[key];
  if (typeof value === "string") return value;
  if (typeof value === "number") return String(value);
  return "—";
}

/**
 * The last `pam doctor` verdict as one phrase: the verdict, how long ago
 * the daemon received it, who sent it and how. No report reads as not
 * verified — the honest state of a machine nobody checked.
 */
export function boundaryVerdictLine(boundary: BoundaryStatus, nowMs?: number): string {
  const report = boundary.last_report;
  if (report === null) return "not verified — run pam doctor from the agent";
  const age = relativeTime(report.received_ts, nowMs);
  const via = report.relayed ? "relay" : "direct";
  const verdict =
    report.verdict === "established"
      ? "established"
      : report.verdict === "not_established"
        ? "not established"
        : "could not be probed";
  return `${verdict} · ${age} · by ${report.agent} (${via})`;
}

/** The badge tone of a boundary state: only an established boundary reads as success. */
function boundaryTone(boundary: BoundaryStatus): "success" | "warning" | "neutral" {
  switch (boundary.last_report?.verdict) {
    case "established":
      return "success";
    case "not_established":
      return "warning";
    default:
      return "neutral";
  }
}

/** The badge word of a boundary state. */
function boundaryLabel(boundary: BoundaryStatus): string {
  switch (boundary.last_report?.verdict) {
    case "established":
      return "established";
    case "not_established":
      return "not established";
    case "cannot_probe":
      return "not probed";
    default:
      return "not verified";
  }
}

/** A button that copies `text` and says so for two seconds; without a clipboard it just stays. */
function CopyCommandButton({ text, label }: { text: string; label: string }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2_000);
    } catch {
      // No clipboard (webview permission, jsdom): the button just stays.
    }
  };
  return (
    <Button size="sm" variant="ghost" aria-label={label} onClick={() => void copy()}>
      {copied ? (
        <Check size={14} aria-hidden="true" className="text-success" />
      ) : (
        <Copy size={14} aria-hidden="true" />
      )}
      {copied ? "Copied" : "Copy"}
    </Button>
  );
}

/**
 * The "Boundary" rows of the daemon card: the last `pam doctor` report
 * (verdict, age, sender, what it reached), the admin contacts nothing
 * explains, and the command to run from the agent's position with the
 * harness pre-selected from the last report. The daemon's own observations
 * are the only part it can vouch for; the report is a point in time from
 * one position. The beacon never carries this: liveness and the boundary
 * are different questions.
 */
function BoundaryRows({ boundary }: { boundary: BoundaryStatus }) {
  const report = boundary.last_report;
  const [harness, setHarness] = useState<HarnessProfile>(() =>
    harnessProfileFor(report?.agent),
  );
  const command = `pam doctor --profile ${harness}`;
  const contacts = boundary.admin_contacts;
  const lastContact = contacts.last;
  return (
    <div className="space-y-3 border-t border-line pt-4" role="group" aria-label="Boundary">
      <div className="flex items-center justify-between gap-3">
        <p className="font-data text-xs text-ink-faint">Boundary</p>
        <Badge tone={boundaryTone(boundary)}>{boundaryLabel(boundary)}</Badge>
      </div>
      <dl className="grid grid-cols-1 gap-x-6 gap-y-3 sm:grid-cols-2">
        <div className="min-w-0 space-y-0.5">
          <dt className="font-data text-xs text-ink-faint">last report</dt>
          <dd className="font-data text-sm text-ink">{boundaryVerdictLine(boundary)}</dd>
        </div>
        {report && (
          <div className="min-w-0 space-y-0.5">
            <dt className="font-data text-xs text-ink-faint">harness</dt>
            <dd className="font-data text-sm text-ink">
              <SafeText value={report.peer_harness ?? report.agent} />
              {report.peer_pid !== null && (
                <span className="text-ink-muted"> · pid {report.peer_pid}</span>
              )}
            </dd>
          </div>
        )}
        {report && report.failed.length > 0 && (
          <div className="min-w-0 space-y-0.5 sm:col-span-2">
            <dt className="font-data text-xs text-ink-faint">reached (must be denied)</dt>
            <dd className="break-words font-data text-sm text-warning">
              <SafeText value={report.failed.join(" ")} />
            </dd>
          </div>
        )}
        {report && report.unverified.length > 0 && (
          <div className="min-w-0 space-y-0.5 sm:col-span-2">
            <dt className="font-data text-xs text-ink-faint">unverified</dt>
            <dd className="break-words font-data text-sm text-warning">
              <SafeText value={report.unverified.join(" ")} />
            </dd>
          </div>
        )}
        <div className="min-w-0 space-y-0.5 sm:col-span-2">
          <dt className="font-data text-xs text-ink-faint">unexpected admin contacts (24 h)</dt>
          <dd className="font-data text-sm text-ink tabular-nums">
            {contacts.unattributed_24h}
            {lastContact && lastContact.peer_exe !== null && (
              <span className="text-ink-muted">
                {" "}
                · last from <SafeText value={lastContact.peer_exe} />{" "}
                {relativeTime(lastContact.ts)}
              </span>
            )}
            {lastContact && lastContact.peer_exe === null && (
              <span className="text-ink-muted">
                {" "}
                · last {relativeTime(lastContact.ts)}, peer unknown
              </span>
            )}
          </dd>
        </div>
      </dl>
      <div className="flex flex-wrap items-center gap-3">
        <p className="font-data text-xs text-ink-faint">verify from the agent</p>
        <SelectField
          aria-label="harness"
          value={harness}
          onChange={(event) => setHarness(event.target.value as HarnessProfile)}
          className={cn(fieldClasses, "w-auto px-2")}
        >
          {HARNESS_PROFILES.map((name) => (
            <option key={name} value={name}>
              {name}
            </option>
          ))}
        </SelectField>
        <code className="select-text rounded-control bg-inset px-2 py-1 font-data text-xs text-ink">
          {command}
        </code>
        <CopyCommandButton text={command} label="copy doctor command" />
      </div>
      <p className="font-sans text-xs text-ink-muted">
        Run it where the agent runs, with the sandbox applied; the profile it prints is the
        sandbox fragment for that harness. A report changes no authority.
      </p>
    </div>
  );
}

/**
 * The daemon card: live status facts, the boundary rows, stop/restart,
 * and the login-start row — whether the platform's user-scope unit
 * (LaunchAgent, scheduled task) is installed, with Install / Remove.
 */
function DaemonPanel({ active }: { active: boolean }) {
  const queryClient = useQueryClient();
  const status = useQuery({
    queryKey: DAEMON_STATUS_KEY,
    queryFn: daemonStatus,
    enabled: active,
    refetchInterval: active ? statusRefetchInterval : false,
  });
  const [note, setNote] = useState<string | null>(null);
  const [failure, setFailure] = useState<BridgeFailure | null>(null);

  const refreshSoon = () => void queryClient.invalidateQueries({ queryKey: ["daemon"] });

  const stop = useMutation({
    mutationFn: () => daemonStop(),
    onMutate: () => {
      setFailure(null);
      setNote(null);
    },
    onError: (error) => setFailure(toBridgeFailure(error)),
    onSettled: refreshSoon,
  });
  /** Stop, then Start: the bridge keeps a stopped daemon down, so a restart asks for both. */
  const restart = useMutation({
    mutationFn: async () => {
      const stopped = await daemonStop();
      // A daemon still draining holds the instance lock: starting now would only meet it.
      const started = stopped.outcome === "still_draining" ? null : await daemonStart();
      return { stopped, started };
    },
    onMutate: () => {
      setFailure(null);
      setNote(null);
    },
    onSuccess: ({ stopped, started }) => {
      if (started) {
        queryClient.setQueryData(DAEMON_STATUS_KEY, started);
        setNote(
          started.connected
            ? `restarted${stopped.pid === null ? "" : ` · was pid ${stopped.pid}`}`
            : "stopped, but the new daemon is not answering yet · see the daemon log",
        );
      } else {
        setNote(stopNote(stopped));
      }
    },
    onError: (error) => setFailure(toBridgeFailure(error)),
    onSettled: refreshSoon,
  });
  const start = useStartDaemon((reply) =>
    setNote(
      reply.connected
        ? "started"
        : "start requested, but the daemon is not answering yet · see the daemon log",
    ),
  );
  /** The stop op's answer in words. A stopped daemon stays down until Start. */
  const stopNote = (reply: DaemonStopReply): string => {
    switch (reply.outcome) {
      case "stopped":
        return `stopped · pid ${reply.pid ?? "?"} · stays down until you press Start`;
      case "still_draining":
        return `still draining · pid ${reply.pid ?? "?"} · finishing in-flight work · press Start once it has exited`;
      case "not_running":
        return "was not running · stays down until you press Start";
    }
  };

  const service = useQuery({ queryKey: ["daemon", "service"], queryFn: serviceStatus });
  const [serviceNote, setServiceNote] = useState<string | null>(null);
  const [serviceFailure, setServiceFailure] = useState<BridgeFailure | null>(null);
  const applyService = (reply: ServiceReport, fallback: string) => {
    queryClient.setQueryData(["daemon", "service"], reply);
    setServiceNote(reply.note ?? fallback);
  };
  const install = useMutation({
    mutationFn: () => serviceInstall(),
    onMutate: () => {
      setServiceFailure(null);
      setServiceNote(null);
    },
    onSuccess: (reply) => applyService(reply, "installed · the daemon now starts at login"),
    onError: (error) => setServiceFailure(toBridgeFailure(error)),
    onSettled: refreshSoon,
  });
  const remove = useMutation({
    mutationFn: () => serviceUninstall(),
    onMutate: () => {
      setServiceFailure(null);
      setServiceNote(null);
    },
    onSuccess: (reply) =>
      applyService(reply, "removed · the next pam command starts the daemon lazily"),
    onError: (error) => setServiceFailure(toBridgeFailure(error)),
    onSettled: refreshSoon,
  });
  const serviceState = service.data?.state;
  const serviceLabel =
    serviceState === undefined
      ? service.isError
        ? "unknown"
        : "checking…"
      : serviceState.kind === "installed"
        ? `installed, ${serviceState.loaded ? "loaded" : "not loaded"}`
        : serviceState.kind === "not_installed"
          ? "not installed"
          : "unsupported";
  const serviceTone =
    serviceState?.kind === "installed"
      ? serviceState.loaded
        ? "success"
        : "warning"
      : "neutral";
  const serviceDetail =
    serviceState === undefined
      ? service.isError
        ? "the login service could not be read"
        : ""
      : serviceState.kind === "unsupported"
        ? serviceState.reason
        : serviceState.unit;

  const connected = status.data?.connected === true;
  // The human pressed Stop in this window: the bridge no longer starts the daemon behind the
  // poll's back, and this panel says so and offers Start.
  const stoppedByYou = !connected && status.data?.stopped_by_you === true;
  const body = status.data?.status;
  const uptime = body?.["uptime_s"];
  const bridgeDown = status.isError ? toBridgeFailure(status.error) : null;
  // A window that is not the daemon's build is refused at the handshake: say so plainly, and keep
  // Stop available, because stopping (a signal, not a request) is the way out the refusal names.
  const mismatch = bridgeDown ? versionMismatchNote(bridgeDown) : null;

  const facts: Array<[string, string]> = [
    ["version", statusField(body, "daemon_version")],
    ["protocol", statusField(body, "protocol")],
    ["uptime", typeof uptime === "number" ? formatDuration(uptime) : "—"],
    ["active requests", statusField(body, "active_requests")],
  ];
  // Only a daemon that publishes the block gets the rows: an older one
  // shows nothing rather than an invented verdict.
  const boundary = connected ? boundaryStatus(body) : null;
  const containment = connected ? containmentStatus(body) : null;

  return (
    <Panel ground="raised" className="space-y-4 p-4">
      <div className="flex items-center justify-between gap-3">
        <p className="font-data text-xs text-ink-faint">Daemon</p>
        {status.data &&
          (connected ? (
            <Badge tone="success">running</Badge>
          ) : stoppedByYou ? (
            <Badge tone="neutral">stopped by you</Badge>
          ) : (
            <Badge tone="danger">unreachable</Badge>
          ))}
      </div>

      {bridgeDown && <FailureNote failure={mismatch ?? bridgeDown} label="daemon" />}

      {!bridgeDown && (
        <dl className="grid grid-cols-2 gap-x-6 gap-y-3 sm:grid-cols-4">
          {facts.map(([label, value]) => (
            <div key={label} className="space-y-0.5">
              <dt className="font-data text-xs text-ink-faint">{label}</dt>
              <dd className="font-data text-sm text-ink tabular-nums">
                {connected ? value : "unknown"}
              </dd>
            </div>
          ))}
        </dl>
      )}

      {!bridgeDown && boundary && <BoundaryRows boundary={boundary} />}

      {/* Whether this machine can contain command workloads: flow command
          steps and guarded landing need it, and on Windows they refuse. */}
      {!bridgeDown && containment && (
        <div className="flex flex-wrap items-center gap-3 border-t border-line pt-4">
          <div className="min-w-0 flex-1 space-y-0.5">
            <p className="font-data text-xs text-ink-faint">Command steps</p>
            <p className="select-text font-data text-xs text-ink-muted">
              <SafeText
                value={
                  containment.available
                    ? containment.detail
                    : `${containment.detail}; ${containment.affects.join(" and ") || "command workloads"} refuse ${containment.cause ?? "command_containment_unavailable"}`
                }
              />
            </p>
          </div>
          <Badge tone={containment.available ? "success" : "warning"}>
            {containment.available ? "contained" : "unavailable"}
          </Badge>
        </div>
      )}

      {/* Login-start: the unit is a property of this machine's session,
          not of the running daemon, so the row stands whether or not the
          daemon answers — only a dead bridge hides it. */}
      {!bridgeDown && (
        <div className="flex flex-wrap items-center gap-3 border-t border-line pt-4">
          <div className="min-w-0 flex-1 space-y-0.5">
            <p className="font-data text-xs text-ink-faint">Start at login</p>
            <p className="truncate font-data text-xs text-ink-muted" title={serviceDetail}>
              {serviceDetail || "no unit named yet"}
            </p>
          </div>
          <Badge tone={serviceTone}>{serviceLabel}</Badge>
          {serviceState?.kind === "not_installed" && (
            <Button size="sm" disabled={install.isPending} onClick={() => install.mutate()}>
              Install
            </Button>
          )}
          {serviceState?.kind === "installed" && (
            <ConfirmButton
              label="Remove"
              confirmLabel="remove it?"
              busy={remove.isPending}
              onConfirm={() => remove.mutate()}
            />
          )}
        </div>
      )}
      {!bridgeDown && service.data?.stale && (
        <div className="flex flex-wrap items-center gap-3">
          <p className="min-w-0 flex-1 break-all font-data text-xs text-warning">
            {service.data.stale}
          </p>
          <Button
            size="sm"
            variant="secondary"
            disabled={install.isPending}
            onClick={() => install.mutate()}
          >
            Repoint to this binary
          </Button>
        </div>
      )}
      {serviceNote && <p className="font-data text-xs text-ink-muted">{serviceNote}</p>}
      {serviceFailure && <FailureNote failure={serviceFailure} label="start at login" />}

      {!bridgeDown && stoppedByYou && (
        <p className="font-sans text-sm text-ink-muted">
          Stopped by you. It stays stopped until you press Start; nothing in this window starts
          it behind your back.
        </p>
      )}
      {!bridgeDown && status.data && !connected && !stoppedByYou && (
        <p className="font-sans text-sm text-ink-muted">
          The daemon is not answering; the next status poll starts it lazily.
        </p>
      )}

      <div className="flex flex-wrap items-center gap-3 border-t border-line pt-4">
        <ConfirmButton
          label="Stop daemon"
          confirmLabel="stop it?"
          busy={stop.isPending}
          disabled={!connected && !mismatch}
          title={!connected && !mismatch ? "The daemon is not running" : undefined}
          onConfirm={() =>
            stop.mutate(undefined, {
              onSuccess: (reply) => setNote(stopNote(reply)),
            })
          }
        />
        {stoppedByYou && (
          <Button size="sm" disabled={start.isPending} onClick={() => start.mutate()}>
            Start daemon
          </Button>
        )}
        <ConfirmButton
          label="Restart"
          confirmLabel="restart it?"
          variant="secondary"
          busy={restart.isPending}
          disabled={!connected && !mismatch}
          title={!connected && !mismatch ? "The daemon is not running" : undefined}
          onConfirm={() => restart.mutate()}
        />
      </div>
      <p className="font-sans text-xs text-ink-muted">
        Stop keeps the daemon down until you press Start. Restart stops it and starts it again.
      </p>

      {note && <p className="font-data text-xs text-ink-muted">{note}</p>}
      {failure && <FailureNote failure={failure} label="daemon" />}

      {/* The bridge resolves the base dir Rust-side ($PAM_BASE_DIR, else
          ~/.pam) and reports it with every status reply. */}
      <p className="border-t border-line pt-3 font-data text-xs text-ink-faint">
        base dir: {status.data?.base_dir ?? "unknown"} · override with $PAM_BASE_DIR
      </p>
    </Panel>
  );
}

// --- retention -------------------------------------------------------------

/** Evidence windows on offer; `null` is forever. */
export const EVIDENCE_CHOICES: ReadonlyArray<number | null> = [30, 90, 365, null];

/** Audit windows. Nothing shorter than 90 days: the trail is the point. */
export const AUDIT_CHOICES: ReadonlyArray<number | null> = [90, 365, null];

/** The one place a window is spoken: "30 days", "1 year", "forever". */
function windowLabel(days: number | null): string {
  if (days === null) return "forever";
  if (days === 365) return "1 year";
  return `${days} days`;
}

/** A window as a `<select>` value — options need a string, and forever needs a name. */
function windowValue(days: number | null): string {
  return days === null ? "forever" : String(days);
}

/** One prune pass in the data voice: exactly what left, and when. */
function pruneLine(report: PruneReport, nowMs?: number): string {
  return (
    `pruned ${report.evidence_rows} evidence rows (${formatBytes(report.evidence_bytes)}) ` +
    `and ${report.requests} requests · ${relativeTime(report.ts, nowMs)}`
  );
}

/**
 * Settings → Retention: the two age windows, and the button that acts on
 * them right now.
 *
 * Both windows default to forever, so nothing is ever lost until a human
 * chooses to lose it. Evidence may not outlive the audit rows that
 * explain it — the GUI does not pre-filter the choices for that rule, it
 * lets the daemon refuse the order violation and renders the refusal, so
 * the human learns the rule from pam (the same posture as Settings ›
 * Flows). The selects are controlled from the stored settings, which is
 * why a refused change snaps back on its own.
 */
function RetentionPanel() {
  const queryClient = useQueryClient();
  const state = useQuery({ queryKey: ["retention"], queryFn: retentionGet });
  const [failure, setFailure] = useState<BridgeFailure | null>(null);
  const [report, setReport] = useState<PruneReport | null>(null);

  const settle = () => void queryClient.invalidateQueries({ queryKey: ["retention"] });

  const save = useMutation({
    mutationFn: (patch: Partial<RetentionSettings>) => retentionSet(patch),
    onMutate: () => setFailure(null),
    onSuccess: (next) => {
      // A save prunes at once; its run supersedes any manual report shown.
      setReport(null);
      queryClient.setQueryData(["retention"], next);
    },
    onError: (error) => setFailure(toBridgeFailure(error)),
    onSettled: settle,
  });

  const prune = useMutation({
    mutationFn: () => retentionPrune(),
    onMutate: () => setFailure(null),
    onSuccess: (fresh) => {
      setReport(fresh);
      settle();
    },
    onError: (error) => setFailure(toBridgeFailure(error)),
  });

  const listFailure = state.isError ? toBridgeFailure(state.error) : null;
  const lastRun = report ?? state.data?.last_run ?? null;
  const busy = state.isPending || save.isPending;

  const selectClasses = cn(
    fieldClasses,
    "w-auto px-2 disabled:cursor-not-allowed disabled:opacity-70",
  );

  const windowField = (
    caption: string,
    label: string,
    choices: ReadonlyArray<number | null>,
    days: number | null,
    entry: EffectiveEntry | undefined,
    onPick: (next: number | null) => void,
  ) => (
    <ManagedField entry={entry}>
      {(locked) => (
        <label className="block space-y-1">
          <span className={fieldLabelClasses}>{caption}</span>
          <SelectField
            appearance="plain"
            aria-label={label}
            value={windowValue(days)}
            disabled={busy || locked}
            onChange={(event) =>
              onPick(event.target.value === "forever" ? null : Number(event.target.value))
            }
            className={selectClasses}
          >
            {choices.map((choice) => (
              <option key={windowValue(choice)} value={windowValue(choice)}>
                {windowLabel(choice)}
              </option>
            ))}
          </SelectField>
        </label>
      )}
    </ManagedField>
  );

  return (
    <Panel ground="raised" className="space-y-4 p-4">
      <div className="flex items-center justify-between gap-3">
        <p className="font-data text-xs text-ink-faint">Storage pruning</p>
        <Button
          size="sm"
          variant="secondary"
          disabled={prune.isPending}
          onClick={() => prune.mutate()}
        >
          Prune now
        </Button>
      </div>

      {listFailure && <FailureNote failure={listFailure} label="retention" />}

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        {windowField(
          "Keep evidence for",
          "evidence age",
          EVIDENCE_CHOICES,
          state.data?.evidence_days ?? null,
          state.data?.effective?.evidence_days,
          (next) => save.mutate({ evidence_days: next }),
        )}
        {windowField(
          "Keep audit rows for",
          "audit age",
          AUDIT_CHOICES,
          state.data?.audit_days ?? null,
          state.data?.effective?.audit_days,
          (next) => save.mutate({ audit_days: next }),
        )}
      </div>

      <p className="font-data text-xs text-ink-muted">
        {lastRun ? pruneLine(lastRun) : "never pruned yet"}
      </p>

      {failure && <FailureNote failure={failure} label="retention" />}

      <p className="font-sans text-sm text-ink-muted">
        Pruning runs at daemon start, every hour after that, and whenever you change these.
        Evidence goes first; a request&apos;s verdict stays until its audit rows go, then the
        whole record leaves together.
      </p>
    </Panel>
  );
}

// --- logs ------------------------------------------------------------------

/** Line-count choices the viewer offers (clamped again Rust-side). */
export const LOG_LINE_CHOICES = [100, 500, 1000] as const;

/** How often the auto-refresh re-reads the tail. */
const LOG_REFRESH_MS = 5_000;

/** The log tail's auto-refresh cadence; backs off while the read keeps failing. */
const logRefetchInterval = backoffRefetchInterval<unknown>({ baseMs: LOG_REFRESH_MS });

/**
 * Colorizes one log line by its level token — plain string matching on
 * the words tracing prints, nothing cleverer.
 */
export function logTone(line: string): "danger" | "warning" | null {
  if (line.includes("ERROR")) return "danger";
  if (line.includes("WARN")) return "warning";
  return null;
}

function LogsPanel({ active }: { active: boolean }) {
  const [lineCount, setLineCount] = useState<number>(500);
  const [auto, setAuto] = useState(false);
  const [copied, setCopied] = useState(false);

  const log = useQuery({
    queryKey: ["daemon-log", lineCount],
    queryFn: () => readDaemonLog(lineCount),
    enabled: active,
    refetchInterval: active && auto ? logRefetchInterval : false,
  });

  const failure = log.isError ? toBridgeFailure(log.error) : null;
  const lines = log.data?.lines ?? [];

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(lines.join("\n"));
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2_000);
    } catch {
      // No clipboard (webview permission, jsdom): the button just stays.
    }
  };

  return (
    <Panel ground="raised" className="space-y-4 p-4">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        <p className="font-data text-xs text-ink-faint">daemon.log</p>
        <span className="flex-1" />
        <SelectField
          aria-label="lines to show"
          value={lineCount}
          onChange={(event) => setLineCount(Number(event.target.value))}
          className={cn(fieldClasses, "w-auto px-2")}
        >
          {LOG_LINE_CHOICES.map((choice) => (
            <option key={choice} value={choice}>
              {choice} lines
            </option>
          ))}
        </SelectField>
        <label className="flex min-h-8 cursor-pointer items-center gap-1.5 font-sans text-xs text-ink-muted">
          <input
            type="checkbox"
            checked={auto}
            onChange={(event) => setAuto(event.target.checked)}
            className="size-4.5 accent-accent-strong"
          />
          Refresh every 5 s
        </label>
        <Button
          size="sm"
          variant="ghost"
          aria-label="refresh log"
          disabled={log.isFetching}
          onClick={() => void log.refetch()}
        >
          <RefreshCw
            size={14}
            aria-hidden="true"
            className={cn(log.isFetching && "animate-spin")}
          />
          Refresh
        </Button>
        <Button
          size="sm"
          variant="ghost"
          aria-label="copy log lines"
          disabled={lines.length === 0}
          onClick={() => void copy()}
        >
          {copied ? (
            <Check size={14} aria-hidden="true" className="text-success" />
          ) : (
            <Copy size={14} aria-hidden="true" />
          )}
          {copied ? "Copied" : "Copy"}
        </Button>
      </div>

      {failure && <FailureNote failure={failure} label="log" />}

      {!failure && log.data && (
        <>
          <p className="truncate font-data text-xs text-ink-faint" title={log.data.file}>
            {log.data.file}
          </p>
          <ol
            aria-label="daemon log lines"
            className="select-text max-h-96 space-y-0.5 overflow-x-auto overflow-y-auto rounded-card border border-line bg-chrome p-3"
          >
            {lines.length === 0 && (
              <li className="font-data text-xs text-ink-faint">the log file is empty</li>
            )}
            {lines.map((line, index) => {
              const tone = logTone(line);
              return (
                <li
                  key={index}
                  className={cn(
                    "font-data text-xs leading-relaxed whitespace-pre",
                    tone === "danger"
                      ? "text-danger"
                      : tone === "warning"
                        ? "text-warning"
                        : "text-ink-muted",
                  )}
                >
                  {line}
                </li>
              );
            })}
          </ol>
        </>
      )}
    </Panel>
  );
}

// --- the screen ------------------------------------------------------------

/**
 * The categories, each with the eyebrow that says what kind of thing it
 * governs: a local preference lives in this app alone; a daemon setting
 * or policy is administered here and nowhere else — no agent or CLI can
 * change it. That one sentence sits in the header instead of a badge on
 * every pane.
 */
const SETTINGS_CATEGORIES = [
  {
    id: "appearance",
    label: "Appearance",
    eyebrow: "Local preference",
    blurb: "Palette, color mode, glass and background motion.",
  },
  {
    id: "security",
    label: "Security",
    eyebrow: "Daemon policy",
    blurb: "Policy profiles and capability grants.",
  },
  {
    id: "models",
    label: "Models",
    eyebrow: "Daemon setting",
    blurb: "Default models, agent assistance and local storage.",
  },
  {
    id: "flows",
    label: "Flows",
    eyebrow: "Daemon policy",
    blurb:
      "What a flow step may reach: allowed programs, search paths, build output and caches, approved repositories and connector scopes, and the landing policy.",
  },
  {
    id: "connectors",
    label: "Connectors",
    eyebrow: "Daemon setting",
    blurb: "Service connections and credentials, stored in this machine's keychain.",
  },
  {
    id: "network",
    label: "Network",
    eyebrow: "Daemon setting",
    blurb:
      "How PAM reaches connector services and download hosts. Nothing is read from environment variables.",
  },
  {
    id: "daemon",
    label: "Daemon",
    eyebrow: "Daemon control",
    blurb: "Connection, login service and daemon controls.",
  },
  {
    id: "retention",
    label: "Retention",
    eyebrow: "Daemon setting",
    blurb: "How long requests and their evidence stay on disk.",
  },
  {
    id: "logs",
    label: "Logs",
    eyebrow: "Local diagnostics",
    blurb: "The daemon's own log, readable even when the daemon is down.",
  },
] as const;

type SettingsCategory = (typeof SETTINGS_CATEGORIES)[number];

/** Keep drafts and pane scroll positions, but don't mount unvisited services. */
function SettingsPane({
  category,
  active,
  children,
}: {
  category: SettingsCategory;
  active: boolean;
  children: ReactNode;
}) {
  const [visited, setVisited] = useState(active);
  if (active && !visited) setVisited(true);
  return (
    <div
      id={category.id}
      role="tabpanel"
      aria-labelledby={`settings-tab-${category.id}`}
      hidden={!active}
      tabIndex={active ? 0 : -1}
      className="settings-pane"
    >
      {visited && (
        <Section eyebrow={category.eyebrow} title={category.label} blurb={category.blurb}>
          {children}
        </Section>
      )}
    </div>
  );
}

export function SettingsScreen() {
  const motionGroup = useId();
  const hash = useRouterState({ select: (state) => state.location.hash });
  const navigate = useNavigate();
  const tabs = useRef<(HTMLButtonElement | null)[]>([]);
  const selected =
    SETTINGS_CATEGORIES.find((category) => category.id === hash.replace(/^#/, "").split("/")[0])
      ?.id ?? "appearance";

  const select = (id: SettingsCategory["id"]) => {
    void navigate({ to: "/settings", hash: id, resetScroll: false, hashScrollIntoView: false });
  };

  const content: Record<SettingsCategory["id"], ReactNode> = {
    appearance: <AppearancePanel />,
    security: (
      <div className="settings-grid settings-security">
        <PolicyPanel />
        <ProfilePanel />
        <GrantsPanel />
      </div>
    ),
    models: <SettingsModelsSection />,
    flows: <SettingsFlowsSection />,
    connectors: <SettingsConnectorsSection targetId={hash.replace(/^#/, "").split("/")[1]} />,
    network: <SettingsNetworkSection />,
    daemon: <DaemonPanel active={selected === "daemon"} />,
    retention: <RetentionPanel />,
    logs: <LogsPanel active={selected === "logs"} />,
  };

  return (
    <div className="settings-workspace">
      <header className="settings-header">
        <div>
          <h1 className="font-sans text-title font-semibold text-ink">Settings</h1>
          <p className="text-sm text-ink-muted">Your machine. Your defaults.</p>
          <PolicyStatusLine onOpen={() => select("security")} />
        </div>
      </header>
      <LayoutGroup id={motionGroup}>
        <motion.div
          layoutScroll
          role="tablist"
          aria-label="Settings categories"
          className="settings-tabs"
        >
          {SETTINGS_CATEGORIES.map((category, index) => (
            <button
              key={category.id}
              ref={(element) => {
                tabs.current[index] = element;
              }}
              type="button"
              role="tab"
              id={`settings-tab-${category.id}`}
              aria-selected={selected === category.id}
              aria-controls={category.id}
              tabIndex={selected === category.id ? 0 : -1}
              onClick={() => select(category.id)}
              onKeyDown={(event) => {
                const last = SETTINGS_CATEGORIES.length - 1;
                const next =
                  event.key === "ArrowRight"
                    ? (index + 1) % (last + 1)
                    : event.key === "ArrowLeft"
                      ? (index + last) % (last + 1)
                      : event.key === "Home"
                        ? 0
                        : event.key === "End"
                          ? last
                          : null;
                if (next === null) return;
                event.preventDefault();
                tabs.current[next]?.focus();
                select(SETTINGS_CATEGORIES[next].id);
              }}
              className="settings-tab"
            >
              {category.label}
              {selected === category.id && (
                <motion.span
                  aria-hidden="true"
                  className="settings-tab-indicator"
                  layoutId="settings-tab-indicator"
                  initial={false}
                  transition={{ type: "tween", duration: 0.2, ease: [0.2, 0, 0, 1] }}
                />
              )}
            </button>
          ))}
        </motion.div>
      </LayoutGroup>
      <div className="settings-panes">
        {SETTINGS_CATEGORIES.map((category) => (
          <SettingsPane key={category.id} category={category} active={selected === category.id}>
            {content[category.id]}
          </SettingsPane>
        ))}
      </div>
    </div>
  );
}
