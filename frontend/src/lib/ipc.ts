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

// --- login-start service ---------------------------------------------------

/** Where the platform's login-start unit stands (`pam_client::service`). */
export type ServiceState =
  | { kind: "installed"; unit: string; loaded: boolean }
  | { kind: "not_installed"; unit: string }
  | { kind: "unsupported"; reason: string };

/** What `pam service …` and the three service commands answer. */
export interface ServiceReport {
  platform: string;
  exe: string;
  state: ServiceState;
  note: string | null;
}

/** Whether the login-start unit exists and is loaded. */
export function serviceStatus(): Promise<ServiceReport> {
  return bridged<ServiceReport>("service_status");
}

/** Registers the unit and starts the managed daemon (a loose one is stopped first). */
export function serviceInstall(): Promise<ServiceReport> {
  return bridged<ServiceReport>("service_install");
}

/** Unregisters and removes the unit; the daemon keeps running. */
export function serviceUninstall(): Promise<ServiceReport> {
  return bridged<ServiceReport>("service_uninstall");
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
  | "admin.evidence.stats"
  | "admin.flows.list"
  | "admin.flows.get"
  | "admin.flows.save"
  | "admin.flows.delete"
  | "admin.flows.run"
  | "admin.flows.normalize"
  | "admin.flows.settings.get"
  | "admin.flows.settings.set"
  | "admin.connectors.list"
  | "admin.connectors.configure"
  | "admin.connectors.test"
  | "admin.retention.get"
  | "admin.retention.set"
  | "admin.retention.prune";

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

/**
 * The tide, narrowed. `capability` is what the Flows screen's run
 * history uses to ask for `flow.run` rows only, instead of pulling the
 * whole tide and sieving it client-side.
 */
export function activityList(
  filters: {
    limit?: number;
    repo?: string;
    agent?: string;
    state?: RequestStateName;
    capability?: string;
    /** Drop the GUI's own `admin.*` and `status` polling from the list. */
    hide_probes?: boolean;
  } = {},
): Promise<{ requests: ActivityRow[] }> {
  return adminCall("admin.activity.list", filters);
}

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
  "github" | "jenkins" | "sonarqube" | "jira" | "confluence" | "sharepoint" | "aws";

/** Every connector, in `ConnectorId::ALL` order (the order the GUI lists them). */
export const FLOW_CONNECTORS: readonly FlowConnectorId[] = [
  "github",
  "jenkins",
  "sonarqube",
  "jira",
  "confluence",
  "sharepoint",
  "aws",
];

/** A connector call argument: YAML scalars only, string or integer. */
export type FlowArgValue = string | number;

export type FlowAction =
  | { kind: "command"; argv: string[] }
  | {
      kind: "connector";
      connector: FlowConnectorId;
      call: string;
      with: Record<string, FlowArgValue>;
    };

export interface FlowStep {
  id: string;
  action: FlowAction;
  /** A duration string (`5m`, `500ms`), as `pam_flow` formats it. */
  timeout: string;
  effect: FlowEffect;
  role: FlowRole;
  output: FlowOutput;
  needs: string[];
  when: FlowWhen;
  retry: { attempts: number; backoff: string };
  approval: FlowApproval;
  env: Record<string, string>;
  /** A human note for the canvas; absent when the step has none. */
  note?: string;
}

export interface FlowSpecInput {
  description: string;
  default: string | null;
}

export interface FlowSpec {
  id: string;
  name: string;
  description: string;
  inputs: Record<string, FlowSpecInput>;
  steps: FlowStep[];
}

/** One step in the file's own shape: `run` or `connector`/`call`/`with`. */
export interface RawFlowStep {
  id: string;
  run?: string[];
  connector?: FlowConnectorId;
  call?: string;
  with?: Record<string, FlowArgValue>;
  timeout?: string;
  effect?: FlowEffect;
  role?: FlowRole;
  output?: FlowOutput;
  needs?: string[];
  when?: FlowWhen;
  retry?: { attempts: number; backoff?: string };
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
  aws: [
    { name: "commands", args: [] },
    {
      name: "cli",
      args: [
        { name: "service", required: true },
        { name: "command", required: true },
        { name: "args", required: false },
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

/** The two knobs Settings › Flows edits. */
export interface FlowSettings {
  allowed_programs: string[];
  extra_path: string[];
}

/** How one step of a run ended (`pam_daemon::flow_exec::StepStatus`). */
export type FlowStepStatus = "succeeded" | "failed" | "skipped" | "blocked" | "cancelled";

/** One step of a finished run, as the step table reads it. */
export interface FlowStepReport {
  id: string;
  kind: "command" | "connector";
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
export function flowsSave(id: string, yaml: string): Promise<FlowListEntry> {
  return adminCall("admin.flows.save", { id, yaml });
}

/** Removes one library file; deleting a shadow reveals its builtin. */
export function flowsDelete(id: string): Promise<{ id: string; revealed_builtin: boolean }> {
  return adminCall("admin.flows.delete", { id });
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

/** Starts a run and answers with the ticket its events arrive under. */
export function flowsRun(
  id: string,
  repo: string,
  inputs: Record<string, string> = {},
): Promise<{ ticket: string; position: number }> {
  return adminCall("admin.flows.run", { id, repo, inputs });
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
export type ConnectorAuth = "bearer" | "basic_user_secret" | "token_as_user" | "aws_profile";

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
