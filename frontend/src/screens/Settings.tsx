import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate, useRouterState } from "@tanstack/react-router";
import { Check, Copy, LoaderCircle, Moon, RefreshCw, Sun } from "lucide-react";
import { useId, useRef, useState, useSyncExternalStore, type ReactNode } from "react";
import { LayoutGroup, motion } from "motion/react";
import { Badge } from "../components/ui/Badge";
import { Button } from "../components/ui/Button";
import { ConfirmButton } from "../components/ui/ConfirmButton";
import { FailureNote } from "../components/ui/FailureNote";
import { Panel } from "../components/ui/Panel";
import { Section } from "../components/ui/Section";
import { formatBytes } from "../lib/bytes";
import { cn } from "../lib/cn";
import {
  daemonStatus,
  daemonStop,
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
  type BridgeFailure,
  type GrantRow,
  type Profile,
  type PruneReport,
  type RetentionSettings,
  type ServiceReport,
} from "../lib/ipc";
import {
  applyTheme,
  applyMaterial,
  applyBackgroundMotion,
  applyBackgroundSpeed,
  applyBackgroundIntensity,
  modeIds,
  subscribeTheme,
  themes,
  themeSnapshot,
  type ModeId,
} from "../lib/theme";
import { exactTime, formatDuration, relativeTime } from "../lib/time";
import { SettingsConnectorsSection } from "./SettingsConnectors";
import { SettingsFlowsSection } from "./SettingsFlows";
import { SettingsModelsSection } from "./SettingsModels";

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

// --- appearance ------------------------------------------------------------

/**
 * v0 modes are explicit light/dark only — no third "system" option. The
 * cheap version already half-exists: until the human ever touches a mode
 * control, `initTheme()` follows the OS preference at launch. A live
 * system-follow (store null, watch `prefers-color-scheme`) is deferred
 * until someone misses it; two honest buttons beat three subtle states.
 */
function AppearancePanel() {
  const { theme, mode, material, backgroundMotion, backgroundSpeed, backgroundIntensity } =
    useSyncExternalStore(subscribeTheme, themeSnapshot);

  return (
    <Panel ground="raised" className="appearance-panel space-y-4 p-4">
      <div className="appearance-grid grid gap-3">
        {themes.flatMap((family) =>
          modeIds.map((appearance) => {
            const active = family.id === theme && appearance === mode;
            return (
              <button
                key={`${family.id}-${appearance}`}
                type="button"
                aria-label={`${family.label} ${family.appearances[appearance]}`}
                aria-pressed={active}
                onClick={() => applyTheme(family.id, appearance)}
                className={cn(
                  "rounded-card border p-1.5 text-left transition-colors duration-100",
                  active ? "border-focus" : "border-line hover:border-ink-faint",
                )}
              >
                <span
                  data-theme={family.id}
                  data-mode={appearance}
                  className="theme-preview block space-y-2 rounded-card bg-chrome p-3"
                >
                  <span className="flex items-center justify-between gap-2">
                    <span className="font-sans text-sm font-semibold">
                      {family.appearances[appearance]}
                    </span>
                    {active && <Check aria-hidden="true" className="size-4 text-accent" />}
                    <span className="ml-auto font-data text-xs text-ink-muted">
                      {appearance}
                    </span>
                  </span>
                  <span className="theme-swatches" aria-hidden="true">
                    <span />
                    <span />
                    <span />
                    <span />
                    <span />
                  </span>
                  <span
                    className="command-surface block space-y-2 rounded-overlay p-3"
                    aria-hidden="true"
                  >
                    <span className="flex flex-wrap items-center gap-2">
                      <span className="font-sans text-sm font-medium">Liquid glass</span>
                      <span className="warm-marker size-2 rounded-pill" />
                    </span>
                    <span className="block font-sans text-xs text-ink-muted">
                      {family.id === "vina"
                        ? "Pacific sunset · rose reflections"
                        : "Glacier light · autumn copper"}
                    </span>
                    <span className="action-control inline-flex h-8 items-center rounded-control border border-control-line px-3 font-sans text-xs text-on-accent">
                      Primary action
                    </span>
                  </span>
                  <span className="block font-sans text-sm font-medium">{family.label}</span>
                </span>
              </button>
            );
          }),
        )}
      </div>

      <div className="appearance-controls flex flex-wrap items-center gap-3 border-t border-line pt-3">
        <span className="font-data text-xs text-ink-faint">mode</span>
        {modeIds.map((candidate: ModeId) => (
          <Button
            key={candidate}
            size="sm"
            variant={mode === candidate ? "primary" : "ghost"}
            aria-pressed={mode === candidate}
            onClick={() => applyTheme(theme, candidate)}
          >
            {candidate === "light" ? (
              <Sun size={14} aria-hidden="true" />
            ) : (
              <Moon size={14} aria-hidden="true" />
            )}
            {candidate}
          </Button>
        ))}
        <span className="ml-auto font-data text-xs text-ink-faint">
          applies instantly · remembered
        </span>
      </div>
      <div className="flex flex-wrap items-center gap-x-6 gap-y-2 border-t border-line pt-3">
        <label className="flex items-center gap-2 font-sans text-sm text-ink">
          <input
            type="checkbox"
            checked={material === "opaque"}
            onChange={(event) => applyMaterial(event.target.checked ? "opaque" : "glass")}
            aria-describedby="material-help"
            className="size-4 accent-accent-strong"
          />
          Reduce transparency
        </label>
        <p id="material-help" className="font-sans text-sm text-ink-muted">
          Use solid surfaces without texture or blur. Your choice applies throughout PAM.
        </p>
      </div>
      <div className="space-y-2 border-t border-line pt-3">
        <div
          role="group"
          aria-label="Background motion"
          aria-describedby="background-motion-help"
          className="flex flex-wrap items-center gap-2"
        >
          <label className="mr-auto flex items-center gap-2 font-sans text-sm text-ink">
            <input
              type="checkbox"
              checked={backgroundMotion !== "off"}
              onChange={(event) => applyBackgroundMotion(event.target.checked ? "slow" : "off")}
              className="size-4 accent-accent-strong"
            />
            Animate background
          </label>
          <output
            htmlFor="background-speed"
            className="font-data text-xs tabular-nums text-ink-muted"
          >
            {backgroundSpeed.toFixed(1)}× · {Math.round(240 / backgroundSpeed)}s loop
          </output>
          <div className="flex basis-full items-center gap-3">
            <span className="font-data text-xs text-ink-faint">Slower</span>
            <input
              id="background-speed"
              type="range"
              min="0.5"
              max="12"
              step="0.1"
              value={backgroundSpeed}
              disabled={backgroundMotion === "off"}
              aria-label="Background animation speed"
              aria-valuetext={`${backgroundSpeed.toFixed(1)} times speed, ${Math.round(240 / backgroundSpeed)} seconds per loop`}
              aria-describedby="background-motion-help"
              onChange={(event) => applyBackgroundSpeed(Number(event.target.value))}
              className="h-6 min-w-0 flex-1 cursor-pointer accent-accent-strong disabled:cursor-not-allowed disabled:opacity-40"
            />
            <span className="font-data text-xs text-ink-faint">Faster</span>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
          <label htmlFor="background-intensity" className="mr-auto font-sans text-sm text-ink">
            Movement intensity
          </label>
          <output
            htmlFor="background-intensity"
            className="font-data text-xs tabular-nums text-ink-muted"
          >
            {backgroundIntensity}%
          </output>
          <div className="flex basis-full items-center gap-3">
            <span className="font-data text-xs text-ink-faint">Still</span>
            <input
              id="background-intensity"
              type="range"
              min="0"
              max="100"
              step="1"
              value={backgroundIntensity}
              disabled={backgroundMotion === "off"}
              aria-valuetext={`${backgroundIntensity} percent movement`}
              aria-describedby="background-intensity-help"
              onChange={(event) => applyBackgroundIntensity(Number(event.target.value))}
              className="h-6 min-w-0 flex-1 cursor-pointer accent-accent-strong disabled:cursor-not-allowed disabled:opacity-40"
            />
            <span className="font-data text-xs text-ink-faint">Immersive</span>
          </div>
        </div>
        <p id="background-intensity-help" className="font-sans text-sm text-ink-muted">
          Controls how far the texture travels, zooms and turns—not how fast.
        </p>
        <p id="background-motion-help" className="font-sans text-sm text-ink-muted">
          {material === "opaque"
            ? "Hidden while transparency is reduced. Your speed is remembered."
            : backgroundMotion === "off"
              ? "The background stays still."
              : "Drift inward, turn, then take a different path home. Drag toward Faster to preview."}{" "}
          Respects system motion and transparency preferences.
        </p>
      </div>
    </Panel>
  );
}

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

function ProfilePanel() {
  const queryClient = useQueryClient();
  const profile = useQuery({ queryKey: ["profile"], queryFn: profileGet });
  const [applies, setApplies] = useState<string | null>(null);

  const setProfile = useMutation({
    mutationFn: (next: Profile) => profileSet(next),
    onMutate: async (next: Profile) => {
      await queryClient.cancelQueries({ queryKey: ["profile"] });
      const previous = queryClient.getQueryData<{ profile: Profile }>(["profile"]);
      queryClient.setQueryData(["profile"], { profile: next });
      setApplies(null);
      return { previous };
    },
    onSuccess: (reply) => {
      // Surface the daemon's own caveat: the running gate keeps its
      // profile; the change binds at the next daemon start.
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
  const failure = profile.isError
    ? toBridgeFailure(profile.error)
    : setProfile.isError
      ? toBridgeFailure(setProfile.error)
      : null;

  return (
    <Panel ground="raised" className="space-y-4 p-4">
      <p className="font-data text-xs text-ink-faint">policy profile</p>
      <div role="radiogroup" aria-label="policy profile" className="space-y-2">
        {PROFILE_ORDER.map((candidate) => {
          const selected = current === candidate;
          return (
            <label
              key={candidate}
              className={cn(
                "flex cursor-pointer items-start gap-3 rounded-card border p-3 transition-colors duration-150",
                selected ? "border-accent-strong bg-accent-soft/40" : "border-line",
                current === undefined && "cursor-default opacity-50",
              )}
            >
              <input
                type="radio"
                name="policy-profile"
                value={candidate}
                checked={selected}
                disabled={current === undefined || setProfile.isPending}
                onChange={() => setProfile.mutate(candidate)}
                className="mt-1 size-3.5 accent-accent-strong"
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

/** The daemon's registered non-admin capabilities, for the add datalist. */
export const KNOWN_CAPABILITIES = ["status", "echo", "query", "cancel"] as const;

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
  return (
    <tr className="border-t border-line">
      <td className="py-2.5 pr-3 font-data text-sm text-ink">{grant.capability}</td>
      <td className="py-2.5 pr-3 font-data text-xs text-ink-muted">{grant.scope}</td>
      <td
        className="py-2.5 pr-3 font-data text-xs text-ink-faint"
        title={exactTime(grant.granted_ts)}
      >
        {relativeTime(grant.granted_ts)}
      </td>
      <td className="py-2.5 pr-3">
        {revoked ? <Badge tone="neutral">revoked</Badge> : <Badge tone="success">active</Badge>}
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

  const add = useMutation({
    mutationFn: (capability: string) => grantsAdd(capability),
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

  return (
    <Panel ground="raised" className="space-y-4 p-4">
      <p className="font-data text-xs text-ink-faint">capability grants</p>

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

      <form
        className="flex flex-wrap items-center gap-2 border-t border-line pt-4"
        onSubmit={(event) => {
          event.preventDefault();
          const capability = draft.trim();
          if (capability) add.mutate(capability);
        }}
      >
        <input
          aria-label="capability to grant"
          list="known-capabilities"
          value={draft}
          onChange={(event) => setDraft(event.target.value)}
          placeholder="capability, e.g. echo"
          className="h-8 min-w-48 flex-1 rounded-control field-control border border-control-line bg-inset px-2.5 font-data text-xs text-ink placeholder:text-ink-faint"
        />
        <datalist id="known-capabilities">
          {KNOWN_CAPABILITIES.map((capability) => (
            <option key={capability} value={capability} />
          ))}
        </datalist>
        <Button size="sm" type="submit" disabled={add.isPending || !draft.trim()}>
          {add.isPending && (
            <LoaderCircle aria-hidden="true" className="size-3.5 animate-spin" />
          )}
          Grant
        </Button>
      </form>

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
 * The daemon card: live status facts, stop/restart, and the login-start
 * row — whether the platform's user-scope unit (LaunchAgent, systemd
 * user unit, scheduled task) is installed, with Install / Remove.
 */
function DaemonPanel({ active }: { active: boolean }) {
  const queryClient = useQueryClient();
  const status = useQuery({
    queryKey: ["daemon", "status"],
    queryFn: daemonStatus,
    enabled: active,
    refetchInterval: active ? 5_000 : false,
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
  });
  const serviceState = service.data?.state;
  const serviceLabel =
    serviceState === undefined
      ? "—"
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
      ? ""
      : serviceState.kind === "unsupported"
        ? serviceState.reason
        : serviceState.unit;

  const connected = status.data?.connected === true;
  const body = status.data?.status;
  const uptime = body?.["uptime_s"];
  const bridgeDown = status.isError ? toBridgeFailure(status.error) : null;

  const facts: Array<[string, string]> = [
    ["version", statusField(body, "daemon_version")],
    ["protocol", statusField(body, "protocol")],
    ["uptime", typeof uptime === "number" ? formatDuration(uptime) : "—"],
    ["active requests", statusField(body, "active_requests")],
  ];

  return (
    <Panel ground="raised" className="space-y-4 p-4">
      <div className="flex items-center justify-between gap-3">
        <p className="font-data text-xs text-ink-faint">daemon</p>
        {status.data &&
          (connected ? (
            <Badge tone="success">running</Badge>
          ) : (
            <Badge tone="danger">unreachable</Badge>
          ))}
      </div>

      {bridgeDown && <FailureNote failure={bridgeDown} label="daemon" />}

      {!bridgeDown && (
        <dl className="grid grid-cols-2 gap-x-6 gap-y-3 sm:grid-cols-4">
          {facts.map(([label, value]) => (
            <div key={label} className="space-y-0.5">
              <dt className="font-data text-xs text-ink-faint">{label}</dt>
              <dd className="font-data text-sm text-ink tabular-nums">
                {connected ? value : "—"}
              </dd>
            </div>
          ))}
        </dl>
      )}

      {/* Login-start: the unit is a property of this machine's session,
          not of the running daemon, so the row stands whether or not the
          daemon answers — only a dead bridge hides it. */}
      {!bridgeDown && (
        <div className="flex flex-wrap items-center gap-3 border-t border-line pt-4">
          <div className="min-w-0 flex-1 space-y-0.5">
            <p className="font-data text-xs text-ink-faint">start at login</p>
            <p className="truncate font-data text-xs text-ink-muted" title={serviceDetail}>
              {serviceDetail || "—"}
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
      {serviceNote && <p className="font-data text-xs text-ink-muted">{serviceNote}</p>}
      {serviceFailure && <FailureNote failure={serviceFailure} label="start at login" />}

      {!bridgeDown && status.data && !connected && (
        <p className="font-sans text-sm text-ink-muted">
          The daemon is not answering; the next status poll starts it lazily.
        </p>
      )}

      <div className="flex flex-wrap items-center gap-3 border-t border-line pt-4">
        <ConfirmButton
          label="Stop daemon"
          confirmLabel="stop it?"
          busy={stop.isPending}
          disabled={!connected}
          onConfirm={() =>
            stop.mutate(undefined, {
              onSuccess: (reply) =>
                setNote(
                  reply.outcome === "stopped"
                    ? `stopped · pid ${reply.pid ?? "?"} · stays down until something asks for it`
                    : reply.outcome === "still_draining"
                      ? `still draining · pid ${reply.pid ?? "?"} · finishing in-flight work`
                      : "was not running",
                ),
            })
          }
        />
        {/* Honest label: there is no start op — stopping and then polling
            status IS the restart, because status ensures (lazily starts)
            the daemon. */}
        <Button
          size="sm"
          variant="ghost"
          disabled={stop.isPending}
          onClick={() =>
            stop.mutate(undefined, {
              onSuccess: () => {
                setNote("stopped · the next status poll is starting it again");
                refreshSoon();
              },
            })
          }
        >
          Restart (stop + lazy start)
        </Button>
      </div>

      {note && <p className="font-data text-xs text-ink-muted">{note}</p>}
      {failure && <FailureNote failure={failure} label="daemon" />}

      {/* The bridge resolves the base dir Rust-side ($PAM_BASE_DIR, else
          ~/.pam); no IPC op reports it back yet, so this line documents
          the rule rather than pretending to read the live value. */}
      <p className="border-t border-line pt-3 font-data text-xs text-ink-faint">
        base dir: ~/.pam · override with $PAM_BASE_DIR
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
export function windowLabel(days: number | null): string {
  if (days === null) return "forever";
  if (days === 365) return "1 year";
  return `${days} days`;
}

/** A window as a `<select>` value — options need a string, and forever needs a name. */
function windowValue(days: number | null): string {
  return days === null ? "forever" : String(days);
}

/** One prune pass in the data voice: when it ran, and exactly what left. */
export function pruneLine(report: PruneReport, nowMs?: number): string {
  return (
    `last pruned ${relativeTime(report.ts, nowMs)} · ` +
    `${report.evidence_rows} evidence rows (${formatBytes(report.evidence_bytes)}) · ` +
    `${report.requests} requests`
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

  const selectClasses =
    "h-8 rounded-control field-control border border-control-line bg-inset px-2 font-data text-xs text-ink disabled:cursor-not-allowed disabled:opacity-50";

  const windowField = (
    caption: string,
    label: string,
    choices: ReadonlyArray<number | null>,
    days: number | null,
    onPick: (next: number | null) => void,
  ) => (
    <label className="space-y-1">
      <span className="block font-data text-xs text-ink-faint">{caption}</span>
      <select
        aria-label={label}
        value={windowValue(days)}
        disabled={busy}
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
      </select>
    </label>
  );

  return (
    <Panel ground="raised" className="space-y-4 p-4">
      <div className="flex items-center justify-between gap-3">
        <p className="font-data text-xs text-ink-faint">storage pruning</p>
        <Button
          size="sm"
          variant="ghost"
          disabled={prune.isPending}
          onClick={() => prune.mutate()}
        >
          Prune now
        </Button>
      </div>

      {listFailure && <FailureNote failure={listFailure} label="retention" />}

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        {windowField(
          "keep evidence for",
          "evidence age",
          EVIDENCE_CHOICES,
          state.data?.evidence_days ?? null,
          (next) => save.mutate({ evidence_days: next }),
        )}
        {windowField(
          "keep audit rows for",
          "audit age",
          AUDIT_CHOICES,
          state.data?.audit_days ?? null,
          (next) => save.mutate({ audit_days: next }),
        )}
      </div>

      <p className="font-data text-xs text-ink-muted">
        {lastRun ? pruneLine(lastRun) : "never pruned yet"}
      </p>

      {failure && <FailureNote failure={failure} label="retention" />}

      <p className="font-sans text-sm text-ink-muted">
        I prune when I start, every hour after that, and whenever you change these. Evidence
        goes first; a request&apos;s verdict stays until its audit rows go, then the whole
        record leaves together.
      </p>
    </Panel>
  );
}

// --- logs ------------------------------------------------------------------

/** Line-count choices the viewer offers (clamped again Rust-side). */
export const LOG_LINE_CHOICES = [100, 500, 1000] as const;

/** How often the auto-refresh re-reads the tail. */
export const LOG_REFRESH_MS = 5_000;

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
    refetchInterval: active && auto ? LOG_REFRESH_MS : false,
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
        <select
          aria-label="lines to show"
          value={lineCount}
          onChange={(event) => setLineCount(Number(event.target.value))}
          className="h-8 rounded-control field-control border border-control-line bg-inset px-2 font-data text-xs text-ink"
        >
          {LOG_LINE_CHOICES.map((choice) => (
            <option key={choice} value={choice}>
              {choice} lines
            </option>
          ))}
        </select>
        <label className="flex cursor-pointer items-center gap-1.5 font-data text-xs text-ink-muted">
          <input
            type="checkbox"
            checked={auto}
            onChange={(event) => setAuto(event.target.checked)}
            className="size-3.5 accent-accent-strong"
          />
          auto 5s
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
            className="max-h-96 space-y-0.5 overflow-x-auto overflow-y-auto rounded-card border border-line bg-chrome p-3"
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

const SETTINGS_CATEGORIES = [
  {
    id: "appearance",
    label: "Appearance",
    blurb: "Four Costa appearances. Soft light, clear working surfaces.",
  },
  {
    id: "security",
    label: "Security",
    blurb: "Policy profiles and capability grants. Only you can change these.",
    admin: true,
  },
  {
    id: "models",
    label: "Models",
    blurb: "Default models, agent assistance and local storage.",
  },
  {
    id: "flows",
    label: "Flows",
    blurb: "Allowed programs and search paths for flow steps.",
    admin: true,
  },
  {
    id: "connectors",
    label: "Connectors",
    blurb: "Service connections and credentials, managed locally.",
    admin: true,
  },
  { id: "daemon", label: "Daemon", blurb: "Connection, login service and daemon controls." },
  {
    id: "retention",
    label: "Retention",
    blurb: "How long requests and their evidence stay on disk.",
  },
  {
    id: "logs",
    label: "Logs",
    blurb: "Local diagnostics, available even when the daemon is down.",
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
        <Section
          eyebrow={category.id}
          title={category.label}
          blurb={category.blurb}
          eyebrowExtra={"admin" in category && <Badge tone="accent">GUI-only</Badge>}
        >
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
    SETTINGS_CATEGORIES.find((category) => category.id === hash.replace(/^#/, ""))?.id ??
    "appearance";

  const select = (id: SettingsCategory["id"]) => {
    void navigate({ to: "/settings", hash: id, resetScroll: false, hashScrollIntoView: false });
  };

  const content: Record<SettingsCategory["id"], ReactNode> = {
    appearance: <AppearancePanel />,
    security: (
      <div className="settings-grid settings-security">
        <ProfilePanel />
        <GrantsPanel />
      </div>
    ),
    models: <SettingsModelsSection />,
    flows: <SettingsFlowsSection />,
    connectors: <SettingsConnectorsSection />,
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
        </div>
        <span className="settings-context font-data text-xs text-ink-muted">
          LOCAL PREFERENCES
        </span>
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
