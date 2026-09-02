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
  | "admin.callers.list"
  | "admin.models.list"
  | "admin.models.catalog"
  | "admin.models.download"
  | "admin.models.download.cancel"
  | "admin.models.delete"
  | "admin.models.verify"
  | "admin.models.load"
  | "admin.models.unload"
  | "admin.models.status"
  | "admin.models.defaults.set"
  | "admin.models.settings.set"
  | "admin.models.try"
  | "admin.curator.list"
  | "admin.curator.set"
  | "admin.curator.test"
  | "admin.log.compress"
  | "admin.evidence.list"
  | "admin.evidence.get"
  | "admin.evidence.stats";

/** One generic admin call; prefer the typed wrappers below. */
export function adminCall<T>(op: AdminOp, args: Record<string, unknown> = {}): Promise<T> {
  return bridged<T>("admin_call", { op, args });
}

export type Profile = "relaxed" | "standard" | "strict";

/** One grant row; timestamps are unix seconds (`pam_store` integers). */
export interface GrantRow {
  id: number;
  capability: string;
  scope: string;
  granted_ts: number;
  revoked_ts: number | null;
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

// --- models ----------------------------------------------------------------

/**
 * The model surface (`pam_daemon::admin_models`). Every shape below is
 * the daemon's own serialization — `pam_model::registry::ModelEntry`,
 * `catalog::Preset` plus the two host flags the daemon adds,
 * `runtime::RuntimeState` (internally tagged on `state`), and the
 * `model_job` rows. Administration is GUI-only by design: no agent, CLI,
 * or MCP call reaches any of these ops.
 */

/** Engine class, decided by size against the 18 GB floor. */
export type ModelClass = "engine" | "test_only";

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
  kind: "download" | "verify";
  model_id: string;
  source: string | null;
  state: "running" | "done" | "failed" | "cancelled";
  bytes_done: number;
  bytes_total: number | null;
  detail: string | null;
  created_ts: number;
  updated_ts: number;
}

/** Everything the Models screen polls, in one read. */
export interface ModelsStatus {
  runtime: { state: RuntimeState; busy: boolean };
  jobs: ModelJob[];
  defaults: { light: string | null; heavy: string | null };
  idle_unload_min: number;
  models_dir: string;
  host_ram_bytes: number;
}

/** What one generation produced, and what it cost. */
export interface GenerateResult {
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
  floor_bytes: number;
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
}): Promise<{ models_dir: string; idle_unload_min: number }> {
  return adminCall("admin.models.settings.set", { ...patch });
}

/**
 * One diagnostic generation on whatever is loaded — deliberately allowed
 * on `test_only` weights, because proving the wiring is its purpose. The
 * bridge gives this op a 120 s deadline; every other admin op gets 30 s.
 */
export function modelsTry(prompt: string, maxTokens?: number): Promise<GenerateResult> {
  return adminCall("admin.models.try", {
    prompt,
    ...(maxTokens === undefined ? {} : { max_tokens: maxTokens }),
  });
}

export function curatorList(): Promise<{ detected: AgentCli[]; selected: AgentId | null }> {
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
  tier: string;
  prompt_tokens: number;
  completion_tokens: number;
  tokens_per_sec: number;
}

/** Everything one compression produced. */
export interface CompressReport {
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
