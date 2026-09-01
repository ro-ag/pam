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

/** Invoke guarded by bridge detection, shared by every wrapper. */
function bridged<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  if (!isTauri()) return Promise.reject(new BridgeUnavailable());
  return invoke<T>(command, args);
}

// --- daemon status ---------------------------------------------------------

/** What the `status` capability reports (loosely typed on purpose). */
export type StatusBody = Record<string, unknown>;

export interface DaemonStatusReply {
  connected: boolean;
  status: StatusBody | null;
}

/** Daemon health; ensures (lazily starts) the daemon as a side effect. */
export function daemonStatus(): Promise<DaemonStatusReply> {
  return bridged<DaemonStatusReply>("daemon_status");
}

export interface DaemonStopReply {
  outcome: "not_running" | "stopped" | "still_draining";
  pid: number | null;
}

/** Stops the daemon; the next status poll lazily restarts it. */
export function daemonStop(): Promise<DaemonStopReply> {
  return bridged<DaemonStopReply>("daemon_stop");
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
  | "admin.callers.list";

/** One generic admin call; prefer the typed wrappers below. */
export function adminCall<T>(op: AdminOp, args: Record<string, unknown> = {}): Promise<T> {
  return bridged<T>("admin_call", { op, args });
}

export type Profile = "relaxed" | "standard" | "strict";

export interface GrantRow {
  id: number;
  capability: string;
  scope: string;
  granted_ts: string;
  revoked_ts: string | null;
}

/** One unresolved raised hand; `requested_ts` is unix seconds. */
export interface PendingApproval {
  request_id: string;
  capability: string;
  repo: string;
  agent: string;
  requested_ts: number;
}

/** `pam_store::RequestState`, exactly — the store knows no other states. */
export type RequestStateName =
  "queued" | "running" | "waiting_approval" | "done" | "refused" | "failed";

/** The five truth verdicts a finished request can report. */
export type OutcomeName = "solved" | "changed" | "verified" | "unresolved" | "blocked";

/** One `admin.activity.list` row; timestamps are unix seconds. */
export interface ActivityRow {
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

/** One observed agent+repo pair; timestamps are unix seconds. */
export interface CallerRow {
  agent: string;
  repo: string;
  first_seen: number;
  last_seen: number;
}

export function profileGet(): Promise<{ profile: Profile }> {
  return adminCall("admin.profile.get");
}

export function profileSet(
  profile: Profile,
): Promise<{ profile: Profile; applies: "next_daemon_start" }> {
  return adminCall("admin.profile.set", { profile });
}

export function grantsList(): Promise<{ grants: GrantRow[] }> {
  return adminCall("admin.grants.list");
}

export function grantsAdd(capability: string): Promise<{ capability: string; granted: true }> {
  return adminCall("admin.grants.add", { capability });
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
  options: { remember?: boolean; note?: string } = {},
): Promise<{ request_id: string; resolution: string; remember: boolean }> {
  return adminCall("admin.approvals.resolve", {
    request_id: requestId,
    resolution,
    ...options,
  });
}

export function activityList(
  filters: { limit?: number; repo?: string; agent?: string; state?: RequestStateName } = {},
): Promise<{ requests: ActivityRow[] }> {
  return adminCall("admin.activity.list", filters);
}

export function callersList(): Promise<{ callers: CallerRow[] }> {
  return adminCall("admin.callers.list");
}

// --- ordinary capabilities -------------------------------------------------

/** The daemon's tagged response for a non-admin capability request. */
export type CapabilityResponse =
  | {
      kind: "result";
      id: string;
      outcome: string;
      body: Record<string, unknown>;
      evidence: string[];
    }
  | { kind: "ticket"; id: string; ticket: string; position: number };

/** Thin wrapper for future views; `admin.*` is refused structurally. */
export function requestCapability(
  capability: string,
  args: Record<string, unknown> = {},
  wait = true,
): Promise<CapabilityResponse> {
  return bridged<CapabilityResponse>("request_capability", { capability, args, wait });
}

// --- event stream ----------------------------------------------------------

/** A daemon lifecycle event, tagged like the Rust `Event` enum. */
export type PamEvent =
  | { kind: "queued" }
  | { kind: "started" }
  | { kind: "progress"; pct?: number; note: string }
  | { kind: "approval_pending" }
  | { kind: "done" }
  | { kind: "refused" };

/** What arrives on the `pam://event` channel: `{ ticket, event }`. */
export interface PamEventPayload {
  ticket: string;
  event: PamEvent;
}

/** The Tauri event channel the Rust bridge forwards daemon events on. */
export const EVENT_CHANNEL = "pam://event";

/**
 * Subscribes `handler` to every daemon event. The first call also asks
 * the Rust side to start its (singleton, reconnecting) events.sock
 * subscriber. Resolves to an unlisten function.
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
