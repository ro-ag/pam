import { invoke, isTauri } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

/**
 * Typed wrappers around the Rust IPC bridge (`crates/pam_gui/src/bridge.rs`
 * and `events.rs`). Every failure — daemon refusal, transport trouble, or
 * the bridge itself saying no — arrives as one shape, `BridgeFailure`
 * ({ cause, detail, recovery }, mirroring the daemon's Refusal), so the UI
 * renders any failure the same way.
 *
 * Outside the app shell (plain-browser Vite dev, jsdom) there is no Tauri
 * bridge; every call rejects with `BridgeUnavailable` — the same failure
 * shape, cause `bridge_unavailable` — which keeps browser-based visual dev
 * working without special-casing.
 */

/** The one failure shape every bridge call rejects with. */
export interface BridgeFailure {
  cause: string;
  detail: string;
  recovery: string;
}

/** Rejection used when no Tauri bridge exists (plain browser, jsdom). */
export class BridgeUnavailable extends Error implements BridgeFailure {
  readonly cause = "bridge_unavailable";
  readonly detail = "running outside the app shell; no Tauri bridge exists";
  readonly recovery = "Open the desktop app (`cargo run -p pam -- gui`) to talk to the daemon.";

  constructor() {
    super("running outside the app shell; no Tauri bridge exists");
    this.name = "BridgeUnavailable";
  }
}

/** Narrows an unknown rejection into the uniform failure shape. */
export function toBridgeFailure(err: unknown): BridgeFailure {
  if (
    typeof err === "object" &&
    err !== null &&
    "cause" in err &&
    "detail" in err &&
    "recovery" in err
  ) {
    const shaped = err as Record<"cause" | "detail" | "recovery", unknown>;
    if (
      typeof shaped.cause === "string" &&
      typeof shaped.detail === "string" &&
      typeof shaped.recovery === "string"
    ) {
      return { cause: shaped.cause, detail: shaped.detail, recovery: shaped.recovery };
    }
  }
  return {
    cause: "unknown_failure",
    detail: String(err),
    recovery: "Retry; report this if it persists.",
  };
}

/** The cause of a refusal to a window whose build is not the running daemon's. */
export const CLIENT_VERSION_MISMATCH = "client_version_mismatch";

/**
 * Rewrites a `client_version_mismatch` refusal into the plain notice Settings › Daemon shows, or
 * returns `null` for any other failure. The daemon's detail names its version and the path it is
 * running from ("… does not match daemon version 0.5.0 running from /path/pam; that binary has
 * not changed on disk …"); both are lifted into the sentence, and the daemon's own recovery line
 * is kept as is. A detail that does not parse still gets the notice, without the facts.
 */
export function versionMismatchNote(failure: BridgeFailure): BridgeFailure | null {
  if (failure.cause !== CLIENT_VERSION_MISMATCH) return null;
  const facts = /daemon version (\S+) running from (.+?); /.exec(failure.detail);
  // The note renders as a sentence and adds its own full stop.
  const where = facts ? `; the daemon is version ${facts[1]}, running from ${facts[2]}` : "";
  return {
    cause: failure.cause,
    detail: `This window is not the build the running daemon was started from${where}`,
    recovery: failure.recovery,
  };
}

/**
 * Longest an ordinary bridge call may take before the webview stops waiting. The Rust side
 * bounds every admin request at 30 s, so this only fires for a call that is truly stuck. The
 * Rust call itself cannot be aborted: a poller must therefore never start a second one while
 * the first is in flight (react-query's dedupe, and `useEventRefresh`, guarantee that).
 */
export const BRIDGE_TIMEOUT_MS = 45_000;

/** The status poll's own bound: the bridge gives up on the daemon after 15 s. */
export const STATUS_TIMEOUT_MS = 20_000;

/** Daemon stop (10 s drain wait) and login-unit changes (stop wait plus manager commands). */
const STOP_TIMEOUT_MS = 30_000;
const SERVICE_TIMEOUT_MS = 60_000;

/** The three admin ops that run for minutes by design (model run, compaction, engine install). */
const LONG_ADMIN_OPS: readonly string[] = [
  "admin.models.try",
  "admin.log.compress",
  "admin.models.engine.install",
  "admin.models.engine.import",
];
const LONG_TIMEOUT_MS = 150_000;

/** Rejects with the uniform failure shape when `promise` outlives `ms`. */
function withTimeout<T>(promise: Promise<T>, ms: number, command: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const expired = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => {
      reject({
        cause: "reply_timeout",
        detail: `${command} did not answer within ${Math.round(ms / 1000)} s`,
        recovery: "Retry; the daemon may be busy or restarting.",
      } satisfies BridgeFailure);
    }, ms);
  });
  return Promise.race([promise, expired]).finally(() => clearTimeout(timer));
}

/** Invoke guarded by bridge detection and a client-side timeout, shared by every wrapper. */
function bridged<T>(
  command: string,
  args?: Record<string, unknown>,
  timeoutMs: number = BRIDGE_TIMEOUT_MS,
): Promise<T> {
  if (!isTauri()) return Promise.reject(new BridgeUnavailable());
  return withTimeout(invoke<T>(command, args), timeoutMs, command);
}

// --- managed policy ----------------------------------------------------------

/**
 * The managed policy file's state (`pam_daemon::managed_policy`): `none` (no file), `active`,
 * `degraded` (some leaves rejected, the rest applied), `last_good` (the file cannot be read or
 * trusted and the last good copy governs) or `frozen` (nothing usable: widening changes pause).
 */
export type PolicyState = "none" | "active" | "degraded" | "last_good" | "frozen";

/** One setting the file names: how it stands. */
export interface PolicyKeyRow {
  key: string;
  tier: string;
  mode: string[];
  state: "applied" | "held" | "rejected";
  code?: string;
  detail?: string;
}

/** One problem found while reading the file. */
export interface PolicyDiagnostic {
  code: string;
  key: string;
  detail: string;
}

/** The trust verdict on the file's origin. */
export interface PolicyTrust {
  verdict: "trusted" | "untrusted" | "busy" | "absent";
  code: string | null;
  recovery: string | null;
  owner?: string | null;
  writable_by_user?: boolean | null;
  symlink?: boolean | null;
  parents?: "ok" | "failed" | "unknown";
}

/** `admin.policy.get` and `admin.policy.reload` answer this body. Timestamps are unix seconds. */
export interface PolicyBody {
  state: PolicyState;
  reason_code: string | null;
  reason_detail: string | null;
  origin: { path: string | null; platform: string; trust: PolicyTrust };
  /** 64 hex digits; the screen shows a prefix. */
  digest: string | null;
  file_digest: string | null;
  revision: string | null;
  organization: string | null;
  contact: string | null;
  loaded_ts: number | null;
  checked_ts: number | null;
  last_good: { digest: string; loaded_ts: number } | null;
  rejected_leaves: number;
  keys: PolicyKeyRow[];
  diagnostics: PolicyDiagnostic[];
  compliance: { login_unit: { required: boolean; present: boolean | null } };
}

export function policyGet(): Promise<PolicyBody> {
  return adminCall("admin.policy.get");
}

/** Re-reads the policy file now; no confirmation, because it cannot loosen what the file says. */
export function policyReload(): Promise<PolicyBody> {
  return adminCall("admin.policy.reload");
}

// --- daemon status ---------------------------------------------------------

/** What the `status` capability reports (loosely typed on purpose). */
export type StatusBody = Record<string, unknown>;

/** Whether PAM can reach the platform credential store, and the way out. */
export interface KeyringHealth {
  state: "reachable" | "denied" | "unavailable";
  cause: string | null;
  recovery: string | null;
}

/**
 * The `keyring` block of a daemon status body, when the daemon publishes
 * one. An older daemon has none, and the caller shows nothing rather than
 * inventing a verdict.
 */
export function keyringHealth(status: StatusBody | null | undefined): KeyringHealth | null {
  const block = status?.keyring;
  if (typeof block !== "object" || block === null) return null;
  const health = block as Record<string, unknown>;
  const state = health.state;
  if (state !== "reachable" && state !== "denied" && state !== "unavailable") return null;
  return {
    state,
    cause: typeof health.cause === "string" ? health.cause : null,
    recovery: typeof health.recovery === "string" ? health.recovery : null,
  };
}

// --- boundary (pam doctor) --------------------------------------------------

/**
 * The harness names `pam doctor --profile` takes, in the order the CLI
 * documents them (`pam::doctor::profiles::Harness::ALL`; a test in the
 * `pam` crate pins this line to it, because the window cannot ask the
 * binary).
 */
export const HARNESS_PROFILES = [
  "claude-code",
  "codex",
  "gemini-cli",
  "copilot-cli",
  "sandbox-exec",
] as const;

export type HarnessProfile = (typeof HARNESS_PROFILES)[number];

/**
 * The profile a report's agent runs under (`claude` → `claude-code`, as
 * `pam::doctor::profiles::Harness::parse` maps it); `sandbox-exec`, the
 * harness-less fallback, for anything else — including no report at all.
 */
export function harnessProfileFor(agent: string | null | undefined): HarnessProfile {
  switch ((agent ?? "").toLowerCase()) {
    case "claude":
    case "claude-code":
      return "claude-code";
    case "codex":
      return "codex";
    case "gemini":
    case "gemini-cli":
      return "gemini-cli";
    case "copilot":
    case "github-copilot":
    case "copilot-cli":
      return "copilot-cli";
    default:
      return "sandbox-exec";
  }
}

/**
 * A `pam doctor` verdict. The daemon records only the first two (a
 * `cannot_probe` document never arrives over the public socket), but the
 * type keeps the third so a block that carries it is still read.
 */
export type BoundaryVerdict = "established" | "not_established" | "cannot_probe";

/** The last `pam doctor` report the daemon accepted (`status.boundary.last_report`). */
export interface BoundaryLastReport {
  verdict: BoundaryVerdict;
  /** The client's clock when it probed. */
  ts: number;
  /** The daemon's clock when it recorded the report. */
  received_ts: number;
  /** Seconds since `received_ts`, as of the poll. */
  age_s: number;
  /** The caller's self-reported agent (`claude`, `codex`, …). */
  agent: string;
  repo: string | null;
  relayed: boolean;
  /** The daemon's own kernel-peer facts; null on Windows and through the relay. */
  peer_pid: number | null;
  peer_exe: string | null;
  peer_harness: string | null;
  /** Must-deny probes that were allowed. */
  failed: string[];
  /** Must-deny probes whose answer was unknown. */
  unverified: string[];
  request_id: string | null;
}

/** One observed contact on the admin plane, or one public request from an unknown harness. */
export interface BoundaryContact {
  ts: number;
  kind: string | null;
  peer_pid: number | null;
  peer_exe: string | null;
  peer_harness: string | null;
  /** The `doctor.report` request that explains the contact, when one did. */
  attributed: string | null;
}

/**
 * The `boundary` block of a daemon status body: the last report and the
 * daemon's own observations of its admin plane. See
 * `docs/specs/2026-10-02-boundary-self-check.md`.
 */
export interface BoundaryStatus {
  /** `kernel_pid` where the public plane has a kernel peer (macOS), `none` elsewhere. */
  peer_identity: "kernel_pid" | "none";
  last_report: BoundaryLastReport | null;
  reports: { retained: number; established: number; not_established: number };
  admin_contacts: {
    /** Unexpected contacts no report explains: the headline. */
    unattributed: number;
    unattributed_24h: number;
    total: number;
    expected_total: number;
    last: BoundaryContact | null;
    last_expected: BoundaryContact | null;
  };
  public_unknown_harness: { total: number; last: BoundaryContact | null };
  /** The daemon's one-line form. */
  summary: string;
}

function numberOr(value: unknown, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

function stringOrNull(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

function numberOrNull(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function stringList(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

function record(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null ? (value as Record<string, unknown>) : null;
}

function boundaryContact(value: unknown): BoundaryContact | null {
  const row = record(value);
  if (row === null) return null;
  return {
    ts: numberOr(row.ts, 0),
    kind: stringOrNull(row.kind),
    peer_pid: numberOrNull(row.peer_pid),
    peer_exe: stringOrNull(row.peer_exe),
    peer_harness: stringOrNull(row.peer_harness),
    attributed: stringOrNull(row.attributed),
  };
}

function boundaryLastReport(value: unknown): BoundaryLastReport | null {
  const row = record(value);
  if (row === null) return null;
  const verdict = row.verdict;
  if (verdict !== "established" && verdict !== "not_established" && verdict !== "cannot_probe") {
    return null;
  }
  return {
    verdict,
    ts: numberOr(row.ts, 0),
    received_ts: numberOr(row.received_ts, numberOr(row.ts, 0)),
    age_s: numberOr(row.age_s, 0),
    agent: typeof row.agent === "string" ? row.agent : "unknown",
    repo: stringOrNull(row.repo),
    relayed: row.relayed === true,
    peer_pid: numberOrNull(row.peer_pid),
    peer_exe: stringOrNull(row.peer_exe),
    peer_harness: stringOrNull(row.peer_harness),
    failed: stringList(row.failed),
    unverified: stringList(row.unverified),
    request_id: stringOrNull(row.request_id),
  };
}

/**
 * The `boundary` block of a daemon status body, when the daemon publishes
 * one. An older daemon has none, and the caller shows nothing rather than
 * inventing a verdict. Counts the block omits read as zero; a `last_report`
 * without a known verdict reads as none.
 */
export function boundaryStatus(status: StatusBody | null | undefined): BoundaryStatus | null {
  const block = record(status?.boundary);
  if (block === null) return null;
  const reports = record(block.reports) ?? {};
  const admin = record(block.admin_contacts) ?? {};
  const unknown = record(block.public_unknown_harness) ?? {};
  const lastReport = boundaryLastReport(block.last_report);
  return {
    peer_identity: block.peer_identity === "kernel_pid" ? "kernel_pid" : "none",
    last_report: lastReport,
    reports: {
      retained: numberOr(reports.retained, 0),
      established: numberOr(reports.established, 0),
      not_established: numberOr(reports.not_established, 0),
    },
    admin_contacts: {
      unattributed: numberOr(admin.unattributed, 0),
      unattributed_24h: numberOr(admin.unattributed_24h, 0),
      total: numberOr(admin.total, 0),
      expected_total: numberOr(admin.expected_total, 0),
      last: boundaryContact(admin.last),
      last_expected: boundaryContact(admin.last_expected),
    },
    public_unknown_harness: {
      total: numberOr(unknown.total, 0),
      last: boundaryContact(unknown.last),
    },
    summary:
      typeof block.summary === "string"
        ? block.summary
        : lastReport === null
          ? "never checked — run pam doctor from the agent"
          : lastReport.verdict,
  };
}

export interface DaemonStatusReply {
  connected: boolean;
  status: StatusBody | null;
  /** The base directory the bridge resolved (`$PAM_BASE_DIR` or `~/.pam`); absent on an older bridge. */
  base_dir?: string;
}

/** Daemon health; ensures (lazily starts) the daemon as a side effect. */
export function daemonStatus(): Promise<DaemonStatusReply> {
  return bridged<DaemonStatusReply>("daemon_status", undefined, STATUS_TIMEOUT_MS);
}

export interface DaemonStopReply {
  outcome: "not_running" | "stopped" | "still_draining";
  pid: number | null;
}

/** Stops the daemon; the next status poll lazily restarts it. */
export function daemonStop(): Promise<DaemonStopReply> {
  return bridged<DaemonStopReply>("daemon_stop", undefined, STOP_TIMEOUT_MS);
}

// --- login-start service ---------------------------------------------------

/** Where the platform's login-start unit stands (`pam_client::service`). */
export type ServiceState =
  | { kind: "installed"; unit: string; loaded: boolean }
  | { kind: "not_installed"; unit: string }
  | { kind: "unsupported"; reason: string };

/** What `pam service …` and the three service commands answer. */
export interface ServiceReport {
  platform: string;
  /** The binary this process is (what an install would pin). */
  exe: string;
  /** The executable the installed unit runs, read back from the unit; null when unknown. */
  pinned_exe?: string | null;
  /** Why the pinned executable is stale (missing, or not this binary); null when it is current. */
  stale?: string | null;
  state: ServiceState;
  note: string | null;
}

/** Whether the login-start unit exists and is loaded. */
export function serviceStatus(): Promise<ServiceReport> {
  return bridged<ServiceReport>("service_status", undefined, SERVICE_TIMEOUT_MS);
}

/** Registers the unit and starts the managed daemon (a loose one is stopped first). */
export function serviceInstall(): Promise<ServiceReport> {
  return bridged<ServiceReport>("service_install", undefined, SERVICE_TIMEOUT_MS);
}

/** Unregisters and removes the unit; the daemon keeps running. */
export function serviceUninstall(): Promise<ServiceReport> {
  return bridged<ServiceReport>("service_uninstall", undefined, SERVICE_TIMEOUT_MS);
}

// --- admin operations ------------------------------------------------------

/** The admin ops the bridge whitelists (`pam_daemon::admin` op names). */
export type AdminOp =
  | "admin.profile.get"
  | "admin.profile.set"
  | "admin.grants.list"
  | "admin.grants.add"
  | "admin.grants.revoke"
  | "admin.approvals.pending"
  | "admin.approvals.resolve"
  | "admin.activity.list"
  | "admin.callers.list"
  | "admin.audit.request"
  | "admin.requests.cancel"
  | "admin.models.list"
  | "admin.models.catalog"
  | "admin.models.download"
  | "admin.models.download.cancel"
  | "admin.models.download.discard"
  | "admin.models.delete"
  | "admin.models.verify"
  | "admin.models.load"
  | "admin.models.unload"
  | "admin.models.status"
  | "admin.models.defaults.set"
  | "admin.models.settings.set"
  | "admin.models.engine.status"
  | "admin.models.engine.install"
  | "admin.models.engine.import"
  | "admin.models.engine.remove"
  | "admin.models.import"
  | "admin.models.try"
  | "admin.curator.list"
  | "admin.curator.set"
  | "admin.curator.test"
  | "admin.log.compress"
  | "admin.evidence.list"
  | "admin.evidence.get"
  | "admin.evidence.stats"
  | "admin.flows.list"
  | "admin.flows.get"
  | "admin.flows.save"
  | "admin.flows.delete"
  | "admin.flows.run"
  | "admin.flows.normalize"
  | "admin.flows.inspect"
  | "admin.flows.settings.get"
  | "admin.flows.settings.set"
  | "admin.flows.landing.get"
  | "admin.flows.landing.set"
  | "admin.connectors.list"
  | "admin.connectors.configure"
  | "admin.connectors.test"
  | "admin.connectors.keyring"
  | "admin.connectors.sonar_mappings.get"
  | "admin.connectors.sonar_mappings.set"
  | "admin.network.get"
  | "admin.network.set"
  | "admin.network.test"
  | "admin.retention.get"
  | "admin.retention.set"
  | "admin.retention.prune"
  | "admin.policy.get"
  | "admin.policy.reload";

/**
 * One generic admin call; prefer the typed wrappers below. `confirmation` is the phrase the
 * human typed for an op that expands what agents may do: the bridge checks it in Rust
 * (`required_confirmation`) and refuses with `confirmation_required` without it.
 */
export function adminCall<T>(
  op: AdminOp,
  args: Record<string, unknown> = {},
  confirmation?: string,
): Promise<T> {
  const timeout = LONG_ADMIN_OPS.includes(op) ? LONG_TIMEOUT_MS : BRIDGE_TIMEOUT_MS;
  return bridged<T>("admin_call", { op, args, confirmation }, timeout);
}

/**
 * The phrases the bridge demands for authority-expanding ops (`pam_gui::bridge`): switching to
 * the relaxed profile, and any global grant — added directly or by approving with "remember".
 */
export const CONFIRM_RELAXED = "relaxed";
export const CONFIRM_GRANT = "grant";
/** Setting or changing the network proxy, its password or the CA bundle (`CONFIRM_NETWORK`). */
export const CONFIRM_NETWORK = "network";

export type Profile = "relaxed" | "standard" | "strict";

/**
 * One field of an `effective` block (`pam_daemon::managed_policy::EffectiveEntry`): where the
 * value in force came from, and whether the human can edit it at all. `source: "policy"` with
 * `locked: false` is a policy default or a clamp; `source: "default"` means no policy is in play.
 * `mode`, `constraint` and `reason` appear only when a managed policy names the key; `value` only
 * on the ops that echo the effective value.
 */
export interface EffectiveEntry {
  source: "policy" | "user" | "default";
  locked: boolean;
  mode?: "locked" | "default" | "floor" | "min" | "max" | "allow" | "forbid";
  constraint?: Record<string, unknown>;
  reason?: string;
  state?: "applied" | "held" | "rejected";
  clamped?: boolean;
  value?: unknown;
}

/** An `effective` block: one entry per field the op reports. */
export type EffectiveBlock<K extends string> = Partial<Record<K, EffectiveEntry>>;

/** One grant row; timestamps are unix seconds (`pam_store` integers). */
export interface GrantRow {
  id: number;
  capability: string;
  scope: string;
  granted_ts: number;
  revoked_ts: number | null;
  /** The managed policy's `never` rules cover it: kept, but it does not authorize. */
  blocked_by_policy?: boolean;
  /**
   * What a flow step's grant is bound to; `legacy` is an unbound grant its next run binds.
   * Null for any other capability.
   */
  binding?: GrantBinding | null;
}

/** A flow step grant's binding: the step as it was when granted, in one repository (or all). */
export type GrantBinding =
  | { state: "legacy" }
  | {
      state: "bound";
      flow: string;
      step: string;
      /** The canonical repository; null for every repository. */
      repository: string | null;
      /** The first 12 characters of the step's effect digest. */
      effect_digest: string;
      effect_class: string;
      bound_ts: number | null;
    };

/** What remembering a flow step's approval records, and what changed since an earlier grant. */
export interface RememberScope {
  flow: string;
  step: string;
  repository: string | null;
  effect_digest: string;
  effect_class: string;
  /** Why an earlier grant of this step no longer covers it; null when there was none. */
  changed: string | null;
}

/** What the managed policy says about grants; each is null unless that key is in force. */
export interface GrantsPolicy {
  manual: "allow" | "deny" | null;
  remember: "allow" | "deny" | null;
  never: string[] | null;
  never_classes: string[] | null;
}

export interface GrantsListReply {
  grants: GrantRow[];
  policy?: GrantsPolicy;
  effective?: EffectiveBlock<"manual" | "remember" | "never" | "never_classes">;
}

/** One unresolved raised hand; `requested_ts` is unix seconds. */
export interface PendingApproval {
  request_id: string;
  capability: string;
  repo: string;
  agent: string;
  requested_ts: number;
  /** The request's recorded args as submitted; null when none were recorded. */
  args: unknown;
  /** The repository the request acts on, when the daemon can resolve it. */
  repository: string | null;
  /** The gated flow step's declared effect; null for a plain request. */
  effect: FlowEffect | null;
  /**
   * What the gated step will actually execute once its inputs are substituted, when the daemon
   * snapshots it into the approval (absent or null on a daemon that does not). The card renders
   * it verbatim; without it the card shows only the request as submitted.
   */
  resolved?: ResolvedStep | null;
  /** What Remember records for a gated flow step: this step as it is now, in this repository. */
  remember?: RememberScope | null;
}

/** The resolved program, arguments, directory and environment names of a gated flow step. */
export interface ResolvedStep {
  program: string;
  /** Every argument after the program, one element each. */
  argv: string[];
  cwd?: string | null;
  /** The names (never the values) of the environment variables the step sets. */
  env_keys?: string[];
  /**
   * The digest of the flow the step belongs to, as it was when the approval was raised. Sent back
   * on approve so a flow edited since the card was shown is refused instead of approved. The
   * daemon may name it `digest` or `flow_digest`; either is accepted.
   */
  digest?: string | null;
  flow_digest?: string | null;
}

/** The flow digest a pending approval's snapshot carries, when it carries one. */
export function snapshotDigest(approval: PendingApproval): string | null {
  const resolved = approval.resolved;
  return resolved?.digest || resolved?.flow_digest || null;
}

/** `pam_store::RequestState`, exactly — the store knows no other states. */
export type RequestStateName =
  "queued" | "running" | "waiting_approval" | "done" | "refused" | "failed";

/** The five truth verdicts a finished request can report. */
export type OutcomeName = "solved" | "changed" | "verified" | "unresolved" | "blocked";

/** One `admin.activity.list` request row; timestamps are unix seconds. */
export interface ActivityRow {
  /** Absent on a daemon from before refusals were listed; always `"request"` otherwise. */
  kind?: "request";
  id: string;
  capability: string;
  repo: string;
  agent: string;
  /** The request's args, parsed back to JSON by the daemon. */
  args: unknown;
  state: RequestStateName;
  outcome: string | null;
  created_ts: number;
  updated_ts: number;
}

/**
 * A refusal the daemon decided before a request row existed (capacity, rate, a malformed or
 * oversized frame, a refused hello, an expired deadline at admission, the connection cap, the
 * drain). `admin.activity.list` returns these, interleaved by time, only when asked
 * (`include_refusals`). Timestamps are unix seconds: `created_ts` is the first attempt and
 * `updated_ts` the latest of the `count` identical attempts the row stands for.
 *
 * Every `agent`, `repo`, `capability` and `request_id` is what the client *claimed*, bounded and
 * attribution only; the `peer_*` fields are the daemon's own view of the connection (null where the
 * platform reports none, and `peer_exe` null when the daemon could not resolve it). All of it is
 * text a client chose: render it through `SafeText`.
 */
export interface RefusalEntry {
  kind: "refusal";
  /** `refusal_<n>`; never a request id. */
  id: string;
  cause: string;
  detail: string;
  count: number;
  capability: string | null;
  repo: string | null;
  agent: string | null;
  /** The request id the client supplied; no such request exists. */
  request_id: string | null;
  created_ts: number;
  updated_ts: number;
  ingress: "public" | "admin";
  peer_uid: number | null;
  peer_pid: number | null;
  peer_exe: string | null;
}

/** One entry of an `admin.activity.list` that asked for refusals. */
export type ActivityEntry = ActivityRow | RefusalEntry;

/** True for a refusal decided before admission. */
export function isRefusal(entry: ActivityEntry): entry is RefusalEntry {
  return entry.kind === "refusal";
}

/** One observed agent+repo pair; timestamps are unix seconds. */
export interface CallerRow {
  agent: string;
  repo: string;
  first_seen: number;
  last_seen: number;
}

export interface ProfileGetReply {
  profile: Profile;
  effective?: EffectiveBlock<"profile">;
}

export function profileGet(): Promise<ProfileGetReply> {
  return adminCall("admin.profile.get");
}

export function profileSet(
  profile: Profile,
  confirmation?: string,
): Promise<{
  profile: Profile;
  applies: "now" | "next_daemon_start";
  effective?: EffectiveBlock<"profile">;
}> {
  return adminCall("admin.profile.set", { profile }, confirmation);
}

export function grantsList(): Promise<GrantsListReply> {
  return adminCall("admin.grants.list");
}

export function grantsAdd(
  capability: string,
  confirmation?: string,
): Promise<{ capability: string; granted: true }> {
  return adminCall("admin.grants.add", { capability }, confirmation);
}

export function grantsRevoke(
  capability: string,
): Promise<{ capability: string; revoked: true }> {
  return adminCall("admin.grants.revoke", { capability });
}

export function approvalsPending(): Promise<{ pending: PendingApproval[] }> {
  return adminCall("admin.approvals.pending");
}

export function approvalsResolve(
  requestId: string,
  resolution: "approved" | "denied",
  options: {
    remember?: boolean;
    note?: string;
    confirmation?: string;
    /** The flow digest the card showed; the daemon refuses `flow_changed` when it differs. */
    expectedDigest?: string;
  } = {},
): Promise<{ request_id: string; resolution: string; remember: boolean }> {
  const { confirmation, expectedDigest, ...rest } = options;
  return adminCall(
    "admin.approvals.resolve",
    {
      request_id: requestId,
      resolution,
      ...rest,
      ...(expectedDigest ? { expected_digest: expectedDigest } : {}),
    },
    confirmation,
  );
}

/**
 * The tide, narrowed. `capability` is what the Flows screen's run
 * history uses to ask for `flow.run` rows only, instead of pulling the
 * whole tide and sieving it client-side.
 */
export function activityList(
  filters: ActivityFilters & { include_refusals: true },
): Promise<{ requests: ActivityEntry[] }>;
export function activityList(
  filters?: ActivityFilters & { include_refusals?: false },
): Promise<{ requests: ActivityRow[] }>;
export function activityList(
  filters: ActivityFilters & { include_refusals?: boolean } = {},
): Promise<{ requests: ActivityEntry[] }> {
  return adminCall("admin.activity.list", filters);
}

/** The filters every `admin.activity.list` call may carry. */
export type ActivityFilters = {
  limit?: number;
  repo?: string;
  agent?: string;
  state?: RequestStateName;
  capability?: string;
  /** Drop the GUI's own `admin.*` and `status` polling from the list. */
  hide_probes?: boolean;
};

export function callersList(): Promise<{ callers: CallerRow[] }> {
  return adminCall("admin.callers.list");
}

/**
 * One audit row. `detail` is the daemon's own JSON when the row carried
 * JSON (a refusal's `{ cause, detail, recovery }`), the raw string when
 * it did not, and `null` when the row has none.
 */
export interface AuditRow {
  id: number;
  action: string;
  decision: string;
  actor: string;
  detail: unknown;
  ts: number;
}

/**
 * The audit trail of one request, oldest first. An id the daemon does
 * not know — pruned or mistyped — answers `rows: []` rather than
 * refusing.
 */
export function auditRequest(
  requestId: string,
): Promise<{ request_id: string; rows: AuditRow[] }> {
  return adminCall("admin.audit.request", { request_id: requestId });
}

// --- models ----------------------------------------------------------------

/**
 * The model surface (`pam_daemon::admin_models`). Every shape below is
 * the daemon's own serialization — `pam_model::registry::ModelEntry`,
 * `catalog::Preset` plus the two host flags the daemon adds,
 * `runtime::RuntimeState` (internally tagged on `state`), and the
 * `model_job` rows. Administration is GUI-only by design: no agent, CLI,
 * or MCP call reaches any of these ops.
 */

/** Engine class: `engine` once the digest is verified, `test_only` until then. */
export type ModelClass = "engine" | "test_only";

/**
 * The compiled-in admission evidence a verified digest matched on this
 * platform (`pam_model::qualification::Qualification`). Only a qualified
 * entry serves a job; verified alone still means Try only.
 */
export interface Qualification {
  artifact: string;
  sha256: string;
  engine_tag: string;
  targets: string[];
  contract: string;
  case_set_sha256: string;
  /** Repository path of the evidence record. */
  record: string;
  host: string;
  accuracy: number;
  false_passes: number;
  warm_p95_ms: number;
  decided: string;
}

/** What the bounded GGUF header parser could read out of a file. */
export interface GgufInfo {
  architecture: string;
  name: string | null;
  quant_label: string;
  parameter_count: number;
  context_length: number | null;
  expert_count: number | null;
  tensor_count: number;
  version: number;
}

/** A digest run's verdict, kept in a sidecar next to the weights. */
export interface VerifiedRecord {
  sha256: string;
  size_bytes: number;
  verified_ts: number;
  /** True/false against a catalog preset; null when no preset matches. */
  matches_catalog: boolean | null;
}

/** One set of weights in the models directory. */
export interface ModelEntry {
  id: string;
  vendor: string;
  file_name: string;
  path: string;
  size_bytes: number;
  info: GgufInfo | null;
  /** Why the header would not parse, when `info` is null. */
  info_error: string | null;
  class: ModelClass;
  verified: VerifiedRecord | null;
  /** Null for an unverified file, or a verified one nobody has measured here. */
  qualification: Qualification | null;
  catalog_id: string | null;
}

/** A catalog entry, flagged for this host. */
export interface CatalogPreset {
  id: string;
  label: string;
  vendor: string;
  file_name: string;
  url: string;
  size_bytes: number;
  sha256: string;
  license_id: string;
  license_url: string;
  quant: string;
  params_label: string;
  min_host_ram_bytes: number;
  /** False when this machine has too little RAM; such cards are hidden. */
  fits_host: boolean;
  installed: boolean;
  /**
   * Bytes of this model already on disk from a transfer that never
   * finished, or null when there is no partial. A registry scan cannot
   * see these — the part file is a dotfile — so the catalog reports them.
   */
  partial_bytes: number | null;
  /**
   * What a download of this preset would actually fetch, worked out by the daemon with the
   * function the downloader uses: the host shown is the host requested. Absent on a daemon that
   * predates network settings; the screen then falls back to the catalog `url`.
   */
  fetch?: PresetFetch;
}

/** Where a catalog download comes from, resolved against the network settings. */
export interface PresetFetch {
  url: string;
  host: string;
  /** `mirror` when the configured models mirror replaced the catalog host. */
  source: "upstream" | "mirror";
}

/** Where the runtime is; `state` is the discriminant the daemon tags on. */
export type RuntimeState =
  | { state: "idle" }
  | { state: "loading"; phase: string; id: string }
  | {
      state: "loaded";
      id: string;
      quant: string;
      architecture: string;
      context_length: number;
      weight_bytes: number;
      device: string;
      loaded_at: number;
      last_used_at: number;
      last_tokens_per_sec: number | null;
    };

/** One `model_job` row: a download or a digest run. */
export interface ModelJob {
  id: string;
  kind: "download" | "verify" | "import";
  model_id: string;
  source: string | null;
  state: "running" | "done" | "failed" | "cancelled";
  bytes_done: number;
  bytes_total: number | null;
  detail: string | null;
  created_ts: number;
  updated_ts: number;
}

/**
 * Why the pinned llama.cpp engine is not simply "installed": every non-null
 * cause names a specific, honest reason (`pam_model::engine`).
 */
export type EngineCause =
  | "not_installed"
  | "manifest_invalid"
  | "stale_release"
  | "server_missing"
  | "unsupported_target"
  | null;

/** What survived a completed install: the release identity and the digest. */
export interface EngineManifest {
  tag: string;
  build: number;
  target: string;
  asset: string;
  sha256: string;
  bytes: number;
  version_line: string | null;
  installed_at_ms: number;
  /** Absent in a manifest written by an older build: shown as "source not recorded". */
  source?: EngineSource | null;
}

/** Where the installed archive came from (`pam_model::engine::EngineSource`). */
export type EngineSource =
  | { kind: "download"; host: string }
  | { kind: "mirror"; host: string; url?: string }
  | { kind: "import"; path: string; imported_at_ms?: number };

/**
 * The pinned llama.cpp engine's install state (`admin.models.engine.status`
 * and `.install`). Read-only status, or an install the human asked for —
 * nothing installs on navigation or on a poll.
 */
export interface EngineStatus {
  expected_tag: string;
  expected_build: number;
  target: string | null;
  installed: boolean;
  server_path: string | null;
  manifest: EngineManifest | null;
  cause: EngineCause;
  /**
   * What Install would do, computed by the daemon so the card cannot disagree with the request.
   * All absent on a daemon that predates engine delivery, and null for an unsupported platform;
   * the card then says less, never more.
   */
  expected_asset?: string | null;
  expected_size?: number | null;
  /** The compiled-in SHA-256 the archive is held to. */
  expected_sha256?: string | null;
  /** The exact address Install would fetch: upstream, or the mirror's when one is configured. */
  download_url?: string | null;
  download_host?: string | null;
  mirror_in_use?: boolean;
  mirror_host?: string | null;
  upstream_host?: string;
  /** What Remove deletes, and what to delete by hand. */
  engine_dir?: string;
  /** The unpacked release inside `engine_dir`. */
  install_dir?: string;
  /** Where the installed engine came from; null when not installed or not recorded. */
  source?: EngineSource | null;
  /** A model is loaded on the engine right now. */
  loaded?: boolean;
  /** `engine_dir` has content and nothing is loaded. */
  removable?: boolean;
  /** Present only when the stored network settings cannot be read. */
  network_issue?: BridgeFailure;
  /** What `models.engine_source` allows right now; absent on a daemon without the policy layer. */
  source_policy?: EngineSourcePolicy;
}

/** The `source_policy` block of the engine status. */
export interface EngineSourcePolicy {
  engine_source: "download" | "mirror_only" | "import_only";
  install_allowed: boolean;
  install_blocked: "import_only" | "mirror_missing" | null;
  import_allowed: boolean;
  effective?: EffectiveEntry;
}

/** Read-only: never installs anything. */
export function engineStatus(): Promise<EngineStatus> {
  return adminCall("admin.models.engine.status");
}

/**
 * Installs the pinned engine — downloads and verifies it (up to ~2
 * minutes). Only ever called from an explicit human click, never a poll.
 */
export function engineInstall(): Promise<EngineStatus> {
  return adminCall("admin.models.engine.install", { confirm: true });
}

/**
 * Installs the pinned engine from a file already on this computer: the release archive, or a
 * folder that holds it by its exact name. No network is used; the daemon copies the file, checks
 * the copy against the SHA-256 built into PAM, and leaves the original untouched.
 */
export function engineImport(path: string): Promise<EngineStatus> {
  return adminCall("admin.models.engine.import", { path, confirm: true });
}

/** What `admin.models.engine.remove` answers. */
export interface EngineRemoveReply {
  removed: boolean;
  engine_dir: string;
  entries_removed: number;
  status: EngineStatus;
}

/**
 * Removes everything under the engine directory (not the model files). Only ever called from an
 * explicit two-tap confirmation; the daemon refuses with `engine_busy` while a model is loaded.
 */
export function engineRemove(): Promise<EngineRemoveReply> {
  return adminCall("admin.models.engine.remove", { confirm: true });
}

/** The model the engine currently holds, as `admin.models.status` reports it. */
export interface EngineLoadedModel {
  id: string;
  path: string;
  context_length: number;
  build_info: string;
  loaded_at_ms: number;
  pid: number;
}

/** The engine summary folded into `admin.models.status`. */
export interface ModelsEngineSummary {
  installed: boolean;
  expected_tag: string;
  cause: EngineCause;
  loaded: EngineLoadedModel | null;
}

/**
 * The first rung of configured → installed → verified → qualified → engine →
 * ready that fails, or `ready` (`pam_daemon::model_readiness::Stage`).
 */
export type ReadinessStage =
  "unconfigured" | "missing" | "unverified" | "unqualified" | "engine_missing" | "ready";

/**
 * The summary disclosure of one tier (`pam_daemon::model_service::SummaryDisclosure`): the
 * fingerprint of the prompt the summary is written under, and that no qualification record was
 * measured under it. A disclosure, never a gate.
 */
export interface SummaryContract {
  task: string;
  fingerprint: string | null;
  measured: boolean;
  note: string;
}

/** One tier's verdict, computed by the daemon with the job's own refusal cause. */
export interface TierReadiness {
  tier: "light" | "heavy";
  /** The id set on this tier itself, before any fallback. */
  configured: string | null;
  /** The id the tier resolves to after `heavy` → `light` fallback. */
  model_id: string | null;
  fallback: boolean;
  stage: ReadinessStage;
  /** Whether the engine holds `model_id` right now — transient, independent of `stage`. */
  resident: boolean;
  qualification: Qualification | null;
  /**
   * What the qualification covers, in one sentence: the capability bench, not the summary
   * prompt. Present exactly when `qualification` is; absent on an older daemon.
   */
  note?: string | null;
  /** What PAM discloses about the summary this tier's model writes; absent on an older daemon. */
  summary_contract?: SummaryContract;
  /** Present exactly when `stage` is not `ready`. */
  blocker: { cause: string; detail: string; recovery: string } | null;
}

/** Everything the Models screen polls, in one read. */
export interface ModelsStatus {
  runtime: { state: RuntimeState; busy: boolean };
  jobs: ModelJob[];
  defaults: { light: string | null; heavy: string | null };
  idle_unload_min: number;
  models_dir: string;
  host_ram_bytes: number;
  effective?: EffectiveBlock<"models_dir" | "idle_unload_min">;
  /** Absent on an older daemon that predates the engine — never invented. */
  engine?: ModelsEngineSummary;
  /** Absent on an older daemon that predates readiness — never invented. */
  readiness?: { light: TierReadiness; heavy: TierReadiness };
}

/** What one generation produced, and what it cost. */
export interface GenerateResult {
  model: {
    id: string;
    architecture: string;
    quant: string;
    device: string;
    weight_bytes: number;
  };
  requested_model_id: string;
  diagnostic_only: true;
  qualification: "not_assessed";
  text: string;
  prompt_tokens: number;
  completion_tokens: number;
  prompt_ms: number;
  decode_ms: number;
  tokens_per_sec: number;
}

/** The closed set of vendor agent CLIs PAM knows how to invoke. */
export type AgentId = "claude" | "codex" | "copilot" | "gemini";

/** One agent CLI found on the daemon's PATH. */
export interface AgentCli {
  id: AgentId;
  path: string;
  /** First line of `<cli> --version`, or null when it would not say. */
  version: string | null;
}

export function modelsList(): Promise<{ models: ModelEntry[]; models_dir: string }> {
  return adminCall("admin.models.list");
}

export function modelsCatalog(): Promise<{
  presets: CatalogPreset[];
  host_ram_bytes: number;
  /** Present only when the stored network settings cannot be read; `fetch` then shows upstream. */
  network_issue?: BridgeFailure;
  effective?: EffectiveBlock<"allowed_sources">;
}> {
  return adminCall("admin.models.catalog");
}

/** From a catalog preset, or from a pasted URL (then it stays unverified). */
export function modelsDownload(
  source: { preset_id: string } | { url: string; vendor: string },
): Promise<{ job_id: string }> {
  return adminCall("admin.models.download", { ...source });
}

export function modelsDownloadCancel(
  jobId: string,
): Promise<{ job_id: string; cancelled: true }> {
  return adminCall("admin.models.download.cancel", { job_id: jobId });
}

/**
 * Throws away a partial download so the next one starts from zero. Takes
 * the same argument as the download it undoes; refused while a transfer
 * of that file is running.
 */
export function modelsDownloadDiscard(
  source: { preset_id: string } | { url: string; vendor: string },
): Promise<{ model_id: string; discarded_bytes: number }> {
  return adminCall("admin.models.download.discard", { ...source });
}

/** What `admin.models.import` answers: the job that copies, and what will be trusted. */
export interface ModelImportReply {
  job_id: string;
  model_id: string;
  dest: string;
  source: string;
  size_bytes: number;
  /** Set when the file's size matched a catalog model, which it is then checked against. */
  catalog: { preset_id: string; label: string; sha256: string; size_bytes: number } | null;
  expected_sha256: string | null;
  verified_on_completion: boolean;
  /** The daemon's plain sentence on what will be checked and what is left to Verify. */
  note: string;
}

/**
 * Copies a weights file from a path on this computer into the models directory, hashing as it
 * copies. A file whose size matches a catalog model is checked against that model's digest; any
 * other `.gguf` lands as an unverified, test-only model unless `expected_sha256` is given and
 * equal. Answers with the job that does the copy; progress and cancel are the download's.
 */
export function modelsImport(source: {
  path: string;
  vendor?: string;
  expected_sha256?: string;
}): Promise<ModelImportReply> {
  return adminCall("admin.models.import", { ...source, confirm: true });
}

export function modelsDelete(modelId: string): Promise<{ deleted: true }> {
  return adminCall("admin.models.delete", { model_id: modelId });
}

export function modelsVerify(modelId: string): Promise<{ job_id: string }> {
  return adminCall("admin.models.verify", { model_id: modelId });
}

export function modelsLoad(modelId: string): Promise<{ state: RuntimeState }> {
  return adminCall("admin.models.load", { model_id: modelId });
}

export function modelsUnload(): Promise<{ state: RuntimeState }> {
  return adminCall("admin.models.unload");
}

export function modelsStatus(): Promise<ModelsStatus> {
  return adminCall("admin.models.status");
}

/** `null` clears the tier back to the deterministic path. */
export function modelsDefaultsSet(
  tier: "light" | "heavy",
  modelId: string | null,
): Promise<{ tier: string; model_id: string | null }> {
  return adminCall("admin.models.defaults.set", { tier, model_id: modelId });
}

export function modelsSettingsSet(patch: {
  models_dir?: string;
  idle_unload_min?: number;
}): Promise<{
  models_dir: string;
  idle_unload_min: number;
  effective?: EffectiveBlock<"models_dir" | "idle_unload_min">;
}> {
  return adminCall("admin.models.settings.set", { ...patch });
}

/**
 * One diagnostic generation on the explicitly named loaded model — allowed
 * on `test_only` weights, because proving the wiring is its purpose. The
 * bridge gives this op a 120 s deadline; every other admin op gets 30 s.
 */
export function modelsTry(
  modelId: string,
  prompt: string,
  maxTokens?: number,
  timeoutMs?: number,
): Promise<GenerateResult> {
  return adminCall("admin.models.try", {
    model_id: modelId,
    prompt,
    ...(maxTokens === undefined ? {} : { max_tokens: maxTokens }),
    ...(timeoutMs === undefined ? {} : { timeout_ms: timeoutMs }),
  });
}

export function curatorList(): Promise<{
  detected: AgentCli[];
  selected: AgentId | null;
  effective?: EffectiveBlock<"curator">;
}> {
  return adminCall("admin.curator.list");
}

export function curatorSet(agent: AgentId | null): Promise<{ selected: AgentId | null }> {
  return adminCall("admin.curator.set", { agent });
}

export function curatorTest(): Promise<{ reply: string; ms: number }> {
  return adminCall("admin.curator.test");
}

// --- log compression and evidence ------------------------------------------

/**
 * The log surface (`pam_daemon::admin_logs`). Compression is
 * daemon-internal — flows and connector diagnoses call `LogService`
 * directly — so these four ops exist for one reason: to give a human the
 * observatory. Drive a log through the pipeline by hand, read every
 * evidence row it left, and watch the odometer move. Every shape below is
 * the daemon's own serialization (`pam_daemon::log_service`).
 */

/** A handle to one evidence row and how big its stored blob is. */
export interface EvidenceRef {
  id: string;
  bytes: number;
}

/** What one compaction saved, in bytes, records and estimated tokens. */
export interface CompressStats {
  source_bytes: number;
  compact_bytes: number;
  source_records: number;
  retained_records: number;
  tokens_source_est: number;
  tokens_compact_est: number;
  tokens_avoided_est: number;
}

/** The model that wrote a summary, and what the generation cost. */
export interface ModelUse {
  id: string;
  /** The qualification record that admitted the model; null only for a test-seeded default. */
  qualification: {
    artifact: string;
    contract: string;
    record: string;
    engine_tag: string;
  } | null;
  tier: string;
  prompt_tokens: number;
  completion_tokens: number;
  tokens_per_sec: number;
}

/** Everything one compression produced. */
export interface CompressReport {
  semantic?: EvidenceRef | null;
  semantic_text?: string | null;
  compression_skipped?: { cause: string; detail: string } | null;
  source: EvidenceRef;
  compact: EvidenceRef;
  /** Null when no model answered; `model_skipped` then says why. */
  summary: EvidenceRef | null;
  compact_text: string;
  summary_text: string | null;
  stats: CompressStats;
  model: ModelUse | null;
  /** Why there is no summary — never a failure, always an explanation. */
  model_skipped: { cause: string; detail: string } | null;
}

/** One evidence row's identity and figures; the blob stays home. */
export interface EvidenceMeta {
  id: string;
  request_id: string;
  /** `log.source`, `log.compact`, `log.summary`, … */
  kind: string;
  /** Length of the stored blob, always — never the rendered text's. */
  bytes: number;
  sha256: string;
  /** The row's `meta_json`, parsed by the daemon (null when it has none). */
  meta: Record<string, unknown> | null;
  ts: number;
}

/**
 * One evidence row, readable. `text` is the first `max_bytes` of what a
 * reader wants (for `log.compact` the rendered text, not the stored
 * JSON), `text_bytes` is the full length of that same text, and
 * `truncated` says the two differ.
 */
export interface EvidenceContent extends EvidenceMeta {
  text: string;
  text_bytes: number;
  truncated: boolean;
}

/** The tokens-avoided odometer's figures over a window. */
export interface EvidenceStats {
  since_ts: number;
  compressions: number;
  source_bytes: number;
  compact_bytes: number;
  tokens_avoided_est: number;
}

/**
 * Compresses one log the daemon can read. `path` must be absolute — the
 * daemon's working directory is not a thing a human can reason about.
 * The bridge gives this op a 120 s deadline.
 */
export function logCompress(args: {
  path: string;
  exit_status?: number;
  model?: boolean;
}): Promise<CompressReport> {
  return adminCall("admin.log.compress", { ...args });
}

/** Every evidence row of one request; no rows is an empty list, not an error. */
export function evidenceList(requestId: string): Promise<{ evidence: EvidenceMeta[] }> {
  return adminCall("admin.evidence.list", { request_id: requestId });
}

/** One evidence row, bounded; the daemon defaults to 256 KB. */
export function evidenceGet(id: string, maxBytes?: number): Promise<EvidenceContent> {
  return adminCall("admin.evidence.get", {
    id,
    ...(maxBytes === undefined ? {} : { max_bytes: maxBytes }),
  });
}

/** The odometer's figures; the daemon defaults to the last seven days. */
export function evidenceStats(sinceTs?: number): Promise<EvidenceStats> {
  return adminCall("admin.evidence.stats", {
    ...(sinceTs === undefined ? {} : { since_ts: sinceTs }),
  });
}

// --- flows -----------------------------------------------------------------

/**
 * The flow surface (`pam_daemon::admin_flows`). Editing a flow is a
 * human act — a flow file IS the list of commands pam will run — so
 * these ops exist only here. *Running* one is not privileged:
 * `flowsRun` makes the daemon build a genuine `flow.run` envelope and
 * push it through its own pipeline, so the GUI follows the returned
 * ticket's events exactly like any other subscriber.
 */

/** One declared input of a flow, as the run card renders its field. */
export interface FlowInput {
  name: string;
  description: string;
  default?: string;
}

/** One flow in the library column: builtins and library files merged. */
export interface FlowListEntry {
  id: string;
  name: string;
  description: string;
  /** `builtin` ships with pam; `library` is a file under ~/.pam/flows. */
  source: "builtin" | "library";
  /** The library file's path; builtins have none until one shadows them. */
  path?: string;
  /** False when the YAML would not parse; `error` then says why. */
  valid: boolean;
  error?: string;
  digest: string;
  steps: number;
  inputs: FlowInput[];
}

// The resolved flow (`pam_flow::Flow` as serde emits it): every default
// filled in, durations as strings, an action that is exactly one thing.
// This is what the canvas draws and edits.

export type FlowWhen =
  "needs_succeeded" | "always" | { succeeded: string } | { failed: string };
export type FlowEffect = "read_only" | "stateful";
export type FlowRole = "observe" | "verify" | "change";
export type FlowOutput = "compact" | "summarize" | "discard";
export type FlowApproval = "none" | "required";
export type FlowConnectorId =
  "github" | "jenkins" | "sonarqube" | "jira" | "confluence" | "sharepoint";

/** Every connector, in `ConnectorId::ALL` order (the order the GUI lists them). */
export const FLOW_CONNECTORS: readonly FlowConnectorId[] = [
  "github",
  "jenkins",
  "sonarqube",
  "jira",
  "confluence",
  "sharepoint",
];

/** A connector call argument: YAML scalars only, string or integer. */
export type FlowArgValue = string | number;

export type LandingOperation =
  "freeze" | "validate" | "push" | "ensure_pr" | "verify_pr" | "merge" | "verify_main" | "sync";

export type FlowAction =
  | { kind: "landing"; operation: LandingOperation }
  | { kind: "command"; argv: string[] }
  | {
      kind: "connector";
      connector: FlowConnectorId;
      call: string;
      with: Record<string, FlowArgValue>;
    };

/** Existing bounded polling policy; edited as part of the flow, not an access grant. */
export interface FlowWatch {
  max_polls: number;
  interval: string;
  max_interval: string;
}

export interface FlowStep {
  id: string;
  action: FlowAction;
  /** A duration string (`5m`, `500ms`), as `pam_flow` formats it. */
  timeout: string;
  effect: FlowEffect;
  role: FlowRole;
  output: FlowOutput;
  /** Fail when a command emits any stdout or stderr bytes. */
  expect_empty_output?: boolean;
  expect_status?: string;
  needs: string[];
  when: FlowWhen;
  retry: { attempts: number; backoff: string };
  watch?: FlowWatch | null;
  approval: FlowApproval;
  env: Record<string, string>;
  /** A human note for the canvas; absent when the step has none. */
  note?: string;
}

export interface FlowSpecInput {
  description: string;
  default: string | null;
}

export interface FlowCorrelation {
  repository: string;
  commit: string;
  pull_request?: FlowArgValue;
  pull_request_head?: string;
}

export interface FlowSpec {
  id: string;
  name: string;
  description: string;
  inputs: Record<string, FlowSpecInput>;
  correlation?: FlowCorrelation | null;
  steps: FlowStep[];
}

/** One step in the file's own shape: `run` or `connector`/`call`/`with`. */
export interface RawFlowStep {
  id: string;
  run?: string[];
  landing?: LandingOperation;
  connector?: FlowConnectorId;
  call?: string;
  with?: Record<string, FlowArgValue>;
  timeout?: string;
  effect?: FlowEffect;
  role?: FlowRole;
  output?: FlowOutput;
  expect_empty_output?: boolean;
  expect_status?: string;
  needs?: string[];
  when?: FlowWhen;
  retry?: { attempts: number; backoff?: string };
  watch?: Partial<FlowWatch>;
  approval?: FlowApproval;
  env?: Record<string, string>;
  note?: string;
}

/** The file's own shape, what `admin.flows.normalize { flow }` takes. */
export interface RawFlow {
  schema: 1;
  id: string;
  name: string;
  description?: string;
  inputs?: Record<string, { description?: string; default?: string | null }>;
  correlation?: FlowCorrelation;
  steps: RawFlowStep[];
}

/** What `admin.flows.normalize` answers: canonical text + resolved flow, or the first error. */
export type FlowNormalizeReply =
  | { valid: true; yaml: string; flow: FlowSpec; digest: string }
  | { valid: false; error: { path: string; message: string } };

/** One read-only connector call and the arguments it takes. */
export interface FlowCallSpec {
  name: string;
  args: { name: string; required: boolean }[];
}

/**
 * The connector call table, mirrored verbatim from
 * `pam_flow::validate::connector_calls` for the inspector's call picker.
 * The daemon stays the validator; this only shapes the picker.
 */
export const FLOW_CONNECTOR_CALLS: Record<FlowConnectorId, FlowCallSpec[]> = {
  github: [
    {
      name: "runs",
      args: [
        { name: "repo", required: true },
        { name: "status", required: false },
        { name: "limit", required: false },
      ],
    },
    {
      name: "run",
      args: [
        { name: "repo", required: true },
        { name: "run_id", required: true },
      ],
    },
    {
      name: "job_log",
      args: [
        { name: "repo", required: true },
        { name: "job_id", required: true },
      ],
    },
  ],
  jenkins: [
    { name: "jobs", args: [{ name: "limit", required: false }] },
    {
      name: "builds",
      args: [
        { name: "job", required: true },
        { name: "limit", required: false },
      ],
    },
    {
      name: "console",
      args: [
        { name: "job", required: true },
        { name: "build", required: true },
      ],
    },
    {
      name: "investigate",
      args: [
        { name: "job", required: true },
        { name: "build", required: true },
      ],
    },
  ],
  sonarqube: [
    { name: "quality_gate", args: [{ name: "project", required: true }] },
    {
      name: "issues",
      args: [
        { name: "project", required: true },
        { name: "limit", required: false },
      ],
    },
  ],
  jira: [
    {
      name: "search",
      args: [
        { name: "jql", required: true },
        { name: "limit", required: false },
      ],
    },
    { name: "issue", args: [{ name: "key", required: true }] },
  ],
  confluence: [
    {
      name: "search",
      args: [
        { name: "cql", required: true },
        { name: "limit", required: false },
      ],
    },
    { name: "page", args: [{ name: "id", required: true }] },
  ],
  sharepoint: [
    {
      name: "documents",
      args: [
        { name: "site", required: true },
        { name: "query", required: true },
        { name: "limit", required: false },
      ],
    },
    {
      name: "lists",
      args: [
        { name: "site", required: true },
        { name: "limit", required: false },
      ],
    },
  ],
};

/** One flow with its text: what the YAML tab edits. */
export interface FlowDetail extends FlowListEntry {
  yaml: string;
  /** The canonical rendering the digest is taken over. */
  normalized_yaml: string;
  /** The parsed shape, or null when the file is invalid. */
  flow?: FlowSpec | null;
}

export interface FlowConnectorScope {
  connector: FlowConnectorId;
  base_url: string;
  access: "targets" | "connector_wide";
  targets: string[];
}

export interface FlowScopePolicy {
  version: 1;
  repositories: { root: string; connectors: FlowConnectorScope[] }[];
}

/** Settings › Flows; missing scope policy is interpreted as empty deny. */
export interface FlowSettings {
  allowed_programs: string[];
  extra_path: string[];
  /** Private directory build outputs go under; `null` until a human names one. */
  artifacts_root?: string | null;
  /** Toolchain caches a step may read but never write. */
  read_cache_roots?: string[];
  scope_policy?: FlowScopePolicy;
  /** What every consumer reads under the managed policy, per field. */
  effective?: EffectiveBlock<
    "allowed_programs" | "extra_path" | "artifacts_root" | "read_cache_roots" | "scope_policy"
  >;
  /** Stored scope entries the managed policy forbids: kept, reported, never used. */
  scope_policy_dropped?: PolicyDrop[];
}

/** One stored entry the managed policy stops using, and why. */
export interface PolicyDrop {
  root: string;
  connector?: string | null;
  key?: string;
  reason: string;
}

/** How one step of a run ended (`pam_daemon::flow_exec::StepStatus`). */
export type FlowStepStatus = "succeeded" | "failed" | "skipped" | "blocked" | "cancelled";

/** One step of a finished run, as the step table reads it. */
export interface FlowStepReport {
  id: string;
  kind: "command" | "connector" | "landing";
  status: FlowStepStatus;
  attempts: number;
  duration_ms: number;
  exit_status?: number;
  evidence: string[];
  summary?: string;
  error?: BridgeFailure;
}

/** The `flow.result` evidence body: one run's whole verdict. */
export interface FlowResult {
  flow: { id: string; name: string; source: string; digest: string };
  repo: string;
  inputs: Record<string, string>;
  outcome: OutcomeName;
  summary: string;
  steps: FlowStepReport[];
  /** Every state-changing step that ran; absent when none did. */
  effects?: FlowEffectRecord[];
}

/** One state change a run made, or may have made (`pam_daemon::flow_exec::EffectRecord`). */
export interface FlowEffectRecord {
  step: string;
  kind: "command" | "connector" | "landing";
  /** `possibly_applied`: the step started and then failed, so how much it changed is unknown. */
  state: "applied" | "possibly_applied";
  /** The landing operation (`push`, `merge`, ...) when the step is a landing step. */
  landing?: string;
}

export function flowsList(): Promise<{ flows: FlowListEntry[] }> {
  return adminCall("admin.flows.list");
}

export function flowsGet(id: string): Promise<FlowDetail> {
  return adminCall("admin.flows.get", { id });
}

/**
 * Validates and writes one library file. The daemon is the only
 * validator — an invalid flow comes back as a refusal naming the YAML
 * path, which is why the editor has no separate Validate button.
 */
export function flowsSave(
  id: string,
  yaml: string,
  options: { create_only?: boolean; allow_builtin_override?: boolean } = {},
): Promise<FlowListEntry & GrantRevocation> {
  return adminCall("admin.flows.save", { id, yaml, ...options });
}

/** Removes one library file; deleting a shadow reveals its builtin. */
export function flowsDelete(
  id: string,
): Promise<{ id: string; revealed_builtin: boolean } & GrantRevocation> {
  return adminCall("admin.flows.delete", { id });
}

/**
 * What a save or delete did to remembered approvals: a step whose definition changed loses its
 * "always allow", so it asks again. Absent fields mean nothing was revoked (or an older daemon).
 */
export interface GrantRevocation {
  /** The `flow.step:<flow>/<step>` capabilities whose remembered approval was removed. */
  grants_revoked?: string[];
  reapproval_required?: boolean;
}

/**
 * How many steps lost their remembered approval, or null when none did. A daemon that says
 * `reapproval_required` without listing them counts as one so the human is still told.
 */
export function revokedStepCount(reply: GrantRevocation | null | undefined): number | null {
  const listed = reply?.grants_revoked?.length ?? 0;
  if (listed > 0) return listed;
  return reply?.reapproval_required === true ? 1 : null;
}

/**
 * Round-trips a flow through the daemon's validator without saving it:
 * YAML text or the raw file shape in, canonical YAML + resolved flow out,
 * or the first validation error with its path. GUI-only, never grantable.
 */
export function flowsNormalize(
  input: { yaml: string } | { flow: RawFlow },
): Promise<FlowNormalizeReply> {
  return adminCall("admin.flows.normalize", { ...input });
}

/**
 * Starts a run and answers with the ticket its events arrive under. `expectedDigest` pins the run
 * to the flow the human was looking at (`flow.digest` of the list entry or inspection): the daemon
 * refuses `flow_changed` instead of running a flow edited since. Sent only when given.
 */
export function flowsRun(
  id: string,
  repo: string,
  inputs: Record<string, string> = {},
  expectedDigest?: string,
): Promise<{ ticket: string; position: number }> {
  return adminCall("admin.flows.run", {
    id,
    repo,
    inputs,
    ...(expectedDigest ? { expected_digest: expectedDigest } : {}),
  });
}

/** One declared input as `admin.flows.inspect` reports it. */
export interface FlowInspectInput {
  name: string;
  type: string;
  required: boolean;
}

/**
 * One reason a run cannot go straight to admission. `step`, `detail`,
 * `input` and `capability` are present only when that blocker names one;
 * a run card reads whichever are there to point at a fix.
 */
export interface FlowInspectBlocker {
  cause: string;
  recovery?: string;
  step?: string;
  detail?: string;
  input?: string;
  capability?: string;
}

/** Whether a run of this flow, as inspected, would be admitted or stopped. */
export type FlowReadiness = "admission_required" | "blocked";

/**
 * The `flow.inspect` body (`admin.flows.inspect { id, repo, inputs? }`):
 * a dry run of admission without starting one. Read loosely — the daemon
 * may add fields this type does not name, and callers should tolerate
 * that rather than break on them.
 */
export interface FlowInspection {
  schema_version: number;
  flow: { id: string; digest: string };
  inputs: FlowInspectInput[];
  steps: unknown[];
  correlation: unknown;
  readiness: FlowReadiness;
  blockers: FlowInspectBlocker[];
  live: unknown;
  model: { required: boolean; qualification: unknown };
  run_admission: unknown;
}

/** A dry run of admission: what would block this flow, without starting it. */
export function flowsInspect(
  id: string,
  repo: string,
  inputs: Record<string, string> = {},
): Promise<FlowInspection> {
  return adminCall("admin.flows.inspect", { id, repo, inputs });
}

export function flowsSettingsGet(): Promise<FlowSettings> {
  return adminCall("admin.flows.settings.get");
}

/** Replaces the named lists; an omitted key is left exactly as it is. */
export function flowsSettingsSet(patch: Partial<FlowSettings>): Promise<FlowSettings> {
  return adminCall("admin.flows.settings.set", { ...patch });
}

// --- retention -------------------------------------------------------------

/**
 * The retention surface (`pam_daemon::admin_retention`). Deciding how
 * long the audit trail lives is the most human act the daemon has, so
 * these are GUI-only by construction — no agent, CLI, or MCP call can
 * shorten its own record.
 *
 * `null` in either window means *forever*: nothing of that kind is ever
 * pruned. It is the shipped default, so an upgrade loses nothing until a
 * human picks a window here.
 */

/** The two age windows, in whole days; `null` is forever. */
export interface RetentionSettings {
  evidence_days: number | null;
  audit_days: number | null;
}

/** What one prune pass removed, as the daemon last recorded it. */
export interface PruneReport {
  /** Unix seconds the pass finished. */
  ts: number;
  evidence_rows: number;
  evidence_bytes: number;
  requests: number;
  audit_rows: number;
}

/** The settings plus the last pass — what `get` and `set` both answer. */
export interface RetentionState extends RetentionSettings {
  last_run: PruneReport | null;
  effective?: EffectiveBlock<"evidence_days" | "audit_days">;
}

export function retentionGet(): Promise<RetentionState> {
  return adminCall("admin.retention.get");
}

/**
 * Saves one or both windows and prunes at once, answering the stored
 * settings and that fresh run. An omitted key is left exactly as it is;
 * an explicit `null` sets that window back to forever. Evidence may not
 * outlive audit rows — the daemon refuses that order violation rather
 * than the GUI pre-filtering the choices.
 */
export function retentionSet(patch: Partial<RetentionSettings>): Promise<RetentionState> {
  return adminCall("admin.retention.set", { ...patch });
}

/** Runs one prune pass now, on the stored windows, and reports it. */
export function retentionPrune(): Promise<PruneReport> {
  return adminCall("admin.retention.prune");
}

// --- connectors ------------------------------------------------------------

/**
 * The connector surface (`pam_daemon::admin_connectors`). Handing pam a
 * credential and pointing it at a service is a human act too, so this is
 * GUI-only by construction. The secret travels once, over the same unix
 * socket, straight into the OS keychain — it is never echoed back, never
 * audited, and never read out again.
 */

/** How pam authenticates a connector. */
export type ConnectorAuth = "bearer" | "basic_user_secret" | "token_as_user";

/** One connector row in Settings › Connectors. */
export interface ConnectorSummary {
  id: string;
  name: string;
  auth: ConnectorAuth;
  /** What this connector's `username` means, when it means anything. */
  username_label?: string;
  needs_base_url: boolean;
  enabled: boolean;
  base_url?: string;
  username?: string;
  /** Whether a secret is stored — false also when the store was mute. */
  credential_present: boolean;
  /** Whether the OS credential store answered at all. */
  store_available: boolean;
  last_test?: { status: "passed" | "failed"; detail: string; ts: number };
  /** Whether the managed policy disables it or narrows its service host. */
  effective?: EffectiveBlock<"enabled" | "base_url">;
}

/** What a configure asks of the stored credential. */
export type CredentialPatch = { set: string } | { clear: true };

export function connectorsList(): Promise<{ connectors: ConnectorSummary[] }> {
  return adminCall("admin.connectors.list");
}

/**
 * Saves one connector's configuration. An omitted key leaves the stored
 * value alone; an explicit `null` clears it.
 */
export function connectorsConfigure(
  id: string,
  patch: {
    enabled?: boolean;
    base_url?: string | null;
    username?: string | null;
    credential?: CredentialPatch;
  },
): Promise<ConnectorSummary> {
  return adminCall("admin.connectors.configure", { id, ...patch });
}

/**
 * Proves one connector's credential still works. A failing test is an
 * answer, not a refusal; only a connector that could not be *tried*
 * refuses. The bridge gives this op 15 s.
 */
export function connectorsTest(
  id: string,
): Promise<{ status: "passed" | "failed"; detail: string; ts: number }> {
  return adminCall("admin.connectors.test", { id });
}

/**
 * Whether PAM can reach the platform credential store. Never refuses —
 * "the keychain said no" is the answer, not an error. `fresh` bypasses
 * the daemon's cached reading, which is what a Re-check asks for.
 */
export function connectorsKeyring(fresh = false): Promise<KeyringHealth> {
  return adminCall("admin.connectors.keyring", { fresh });
}

// --- network ---------------------------------------------------------------

/**
 * The network settings surface (`pam_daemon::admin_network`, spec
 * docs/specs/2026-10-02-enterprise-network-and-engine-delivery.md). The proxy password is
 * write-only: it goes to the keychain through `credential: { set }` and no reply ever carries it,
 * only `credential.present`.
 */

export type ProxyAuth = "none" | "basic" | "anyauth";

export interface NetworkProxy {
  url: string;
  auth: ProxyAuth;
  username?: string | null;
}

/** The private, digest-checked copy PAM made of an imported CA bundle. */
export interface NetworkCaBundle {
  /** Absent on a platform that does not take a bundle file (Windows). */
  sha256?: string;
  certificates?: number;
  /** False on Windows: the OS certificate store is the supported way to trust a CA. */
  supported?: boolean;
  /** Why the bundle is unsupported here, in the daemon's words. */
  reason?: string;
  /** Where it was imported from; display only. */
  source_path?: string;
  imported_ts?: number;
  /** True when the source file's digest no longer equals the import (display only). */
  source_changed?: boolean;
}

export interface NetworkSettings {
  proxy: NetworkProxy | null;
  no_proxy: string[];
  ca_bundle: NetworkCaBundle | null;
  engine_mirror: string | null;
  models_mirror: string | null;
  credential: { present: boolean; store_available: boolean };
  /** Managed-policy only; absent or empty when no policy sets it. */
  mirror_allowed_hosts?: string[] | null;
}

/** Where a field's effective value comes from, and whether policy owns it. */
export type NetworkEffective = EffectiveEntry;

export interface NetworkGetReply {
  settings: NetworkSettings;
  effective?: Partial<
    Record<
      "proxy" | "credential" | "no_proxy" | "ca_bundle" | "engine_mirror" | "models_mirror",
      NetworkEffective
    >
  >;
  curl?: {
    version: string;
    backend: string;
    supports_proxy: boolean;
    supports_cidr_no_proxy: boolean;
  };
  /** Names (never values) of proxy and CA variables in the daemon's own environment. */
  ignored_env?: string[];
  /** Present when the managed policy closes the network: nothing leaves the machine. */
  closed_by_policy?: { key: string; code: string; detail: string; recovery: string };
}

/**
 * A patch: an absent key keeps the stored value, `null` clears it, a value sets it. The daemon
 * validates the whole patch before applying any of it.
 */
export interface NetworkPatch {
  proxy?: { url: string; auth: ProxyAuth; username: string | null } | null;
  credential?: { set: string } | { clear: true };
  no_proxy?: string[];
  ca_bundle?: { path: string } | null;
  engine_mirror?: string | null;
  models_mirror?: string | null;
}

export type NetworkRoute = "direct" | "bypass" | "proxy";

/** One probed target; a failed probe is an answer (`ok: false`), not a refusal. */
export interface NetworkTestResult {
  target: string;
  host: string;
  route: NetworkRoute;
  /**
   * The stage the probe reached or failed at. `connect` is the first connection itself, the one
   * word that is not about a proxy; a daemon that still sends `proxy` for a route with no proxy
   * is read as `connect` by the screen.
   */
  stage: "connect" | "proxy" | "tunnel" | "tls" | "http";
  ok: boolean;
  http_status: number | null;
  cause?: string | null;
  detail?: string | null;
  recovery?: string | null;
}

export function networkGet(): Promise<NetworkGetReply> {
  return adminCall("admin.network.get");
}

/**
 * Saves a patch. A proxy URL, password or CA bundle that is set or changed needs the typed
 * phrase (`CONFIRM_NETWORK`); the bridge checks it in Rust before the op reaches the daemon.
 */
/** A save can carry a `warning` (macOS: a bundle replaces system trust); nothing else is read. */
export function networkSet(
  patch: NetworkPatch,
  confirmation?: string,
): Promise<{ warning?: string } | null> {
  return adminCall("admin.network.set", { ...patch }, confirmation);
}

/**
 * Probes a configured target with the saved settings: no credentials, no free-form URL. The
 * bridge gives this op 25 s.
 */
export function networkTest(target?: string): Promise<{ results: NetworkTestResult[] }> {
  return adminCall("admin.network.test", target === undefined ? {} : { target });
}

// --- daemon log ------------------------------------------------------------

/** What `read_daemon_log` answers: the file read, and its tail. */
export interface DaemonLogTail {
  /** Full path of the newest daemon log file. */
  file: string;
  /** The last lines of that file, oldest first. */
  lines: string[];
}

/**
 * Tail of the newest daemon log file, read from disk by the GUI process
 * itself (never a daemon op — the log's whole point is diagnosing a
 * daemon that is down). `lines` is clamped to 50..=1000 Rust-side.
 */
export function readDaemonLog(lines: number): Promise<DaemonLogTail> {
  return bridged<DaemonLogTail>("read_daemon_log", { lines });
}

// --- event stream ----------------------------------------------------------

/**
 * A daemon lifecycle event, tagged like the Rust `Event` enum, or the pump's own `resync`
 * marker: "events may have been missed, refetch your lists once". `resync` is sent after every
 * (re)connect of the stream and when the daemon's counter `n` skips; it is not a daemon event
 * and carries an empty ticket.
 */
export type PamEvent =
  | { kind: "queued" }
  | { kind: "started" }
  | { kind: "progress"; pct?: number; note: string }
  | { kind: "approval_pending" }
  | { kind: "done" }
  | { kind: "refused" }
  | { kind: "resync" };

/**
 * What arrives on the `pam://event` channel: `{ ticket, event }` plus what the daemon knows
 * about the ticket. The stream is the private admin socket's, so progress notes are the real
 * ones. The members after `event` are absent when the daemon holds no admission record for the
 * ticket and on a `resync`.
 */
export interface PamEventPayload {
  ticket: string;
  event: PamEvent;
  /** The daemon-wide event counter; a skip means events were missed. */
  n?: number;
  capability?: string;
  /** The caller's repository as admitted. */
  repo?: string;
  /** The caller's self-reported agent label: attribution, not authority. */
  agent?: string;
  /** Which plane admitted the ticket. */
  ingress?: "public" | "admin";
}

/** The Tauri event channel the Rust bridge forwards daemon events on. */
export const EVENT_CHANNEL = "pam://event";

/**
 * Subscribes `handler` to every daemon event. The first call also asks
 * the Rust side to start its (singleton, reconnecting) all-events stream on the
 * private admin socket. Resolves to an unlisten function.
 */
export async function subscribeEvents(
  handler: (payload: PamEventPayload) => void,
): Promise<UnlistenFn> {
  if (!isTauri()) return Promise.reject(new BridgeUnavailable());
  const unlisten = await listen<PamEventPayload>(EVENT_CHANNEL, (event) => {
    handler(event.payload);
  });
  try {
    await invoke<boolean>("events_subscribe");
  } catch (err) {
    unlisten();
    throw err;
  }
  return unlisten;
}

export interface SonarRepositoryMapping {
  server: string;
  project: string;
  repository: string;
}
export interface SonarRepositoryMappings {
  revision: string;
  mappings: SonarRepositoryMapping[];
}
export function sonarMappingsGet(): Promise<SonarRepositoryMappings> {
  return adminCall("admin.connectors.sonar_mappings.get");
}
export function sonarMappingsSet(
  snapshot: SonarRepositoryMappings,
): Promise<SonarRepositoryMappings> {
  return adminCall("admin.connectors.sonar_mappings.set", {
    expected_revision: snapshot.revision,
    mappings: snapshot.mappings,
  });
}
