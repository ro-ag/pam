use std::{fmt, path::PathBuf, time::Duration};

use clap::{Parser, Subcommand, ValueEnum};
use pam_core::{ApprovalId, ContentDigest, EvidenceHandle, GrantId, IdempotencyKey, RequestId};
use pam_model::ModelKey;
use pam_policy::{CapabilityName, ResourceName};
use pam_skills::{AgentArtifactId, CanonicalEntryId, MaterializationAgent, OriginAgent};

const DEFAULT_WAIT_TIMEOUT: &str = "30s";
const MAX_WAIT_TIMEOUT: Duration = Duration::from_hours(24);
const MAX_MODEL_TIMEOUT: Duration = Duration::from_mins(10);
const DEFAULT_AUDIT_EXPORT_LIMIT: usize = 500;
const MAX_AUDIT_EXPORT_LIMIT: usize = 1_000;

#[derive(Parser)]
#[command(name = "pam", version, about = "Local project continuity companion")]
pub(crate) struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Report daemon health through the local protocol.
    Status {
        /// One-time exact-effect approval receipt, when policy requires it.
        #[arg(long, value_parser = parse_approval_id)]
        approval_id: Option<ApprovalId>,
    },
    /// Print a compact, provenance-backed project handoff.
    Brief {
        /// One-time exact-effect approval receipt, when policy requires it.
        #[arg(long, value_parser = parse_approval_id)]
        approval_id: Option<ApprovalId>,
    },
    /// Replay a request and wait for its durable result.
    Wait {
        /// Durable request to observe.
        #[arg(value_parser = parse_request_id)]
        request_id: RequestId,
        /// Replay events strictly after this sequence number.
        #[arg(long, default_value_t = 0)]
        after: u64,
        /// Stop observing after this bounded duration (for example, 500ms, 30s, 5m, or 1h).
        #[arg(long, default_value = DEFAULT_WAIT_TIMEOUT, value_parser = parse_wait_timeout)]
        timeout: Duration,
        /// One-time exact-effect approval receipt, when policy requires it.
        #[arg(long, value_parser = parse_approval_id)]
        approval_id: Option<ApprovalId>,
    },
    /// Print a request's durable result without waiting.
    Result {
        /// Durable request to inspect.
        #[arg(value_parser = parse_request_id)]
        request_id: RequestId,
        /// One-time exact-effect approval receipt, when policy requires it.
        #[arg(long, value_parser = parse_approval_id)]
        approval_id: Option<ApprovalId>,
    },
    /// Validate, run, and observe durable project flows.
    Flow {
        #[command(subcommand)]
        command: FlowCommand,
    },
    /// Inspect retained project evidence.
    Evidence {
        #[command(subcommand)]
        command: EvidenceCommand,
    },
    /// Inventory normalized local agent skills, rules, and configuration.
    Skills {
        #[command(subcommand)]
        command: SkillsCommand,
    },
    /// Manage revocable local caller credentials.
    Caller {
        #[command(subcommand)]
        command: CallerCommand,
    },
    /// Register user-owned model metadata and weights.
    Model {
        #[command(subcommand)]
        command: ModelCommand,
    },
    /// Manage project-scoped capability grants.
    Access {
        #[command(subcommand)]
        command: AccessCommand,
    },
    /// Decide exact-effect approval requests.
    Approval {
        #[command(subcommand)]
        command: ApprovalCommand,
    },
    /// Inspect native trust and proxy configuration without exposing endpoints.
    Network {
        #[command(subcommand)]
        command: NetworkCommand,
    },
    /// Export the current project's redacted audit ledger.
    Audit {
        #[command(subcommand)]
        command: AuditCommand,
    },
    /// Apply explicit project evidence-retention controls.
    Retention {
        #[command(subcommand)]
        command: RetentionCommand,
    },
    /// Run the foreground daemon.
    Daemon {
        /// Recover an endpoint left behind by an interrupted daemon.
        #[arg(long)]
        recover: bool,
        /// Load this registered vendor/name into the embedded llama.cpp runtime.
        #[arg(long, value_name = "VENDOR/NAME", value_parser = parse_model_key)]
        model: Option<ModelKey>,
    },
    /// Open the native control-center shell.
    Gui,
}

#[derive(Debug, Subcommand)]
enum EvidenceCommand {
    /// Show evidence metadata and content.
    Show {
        /// Canonical evidence handle to inspect.
        #[arg(value_parser = parse_evidence_handle)]
        handle: EvidenceHandle,
        /// Write only exact evidence bytes to standard output.
        #[arg(long, conflicts_with = "output")]
        raw: bool,
        /// Write exact evidence bytes to this platform-native path.
        #[arg(long, value_name = "PATH")]
        output: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum SkillsCommand {
    /// Audit always-loaded context and persist the versioned report.
    Audit {
        /// Emit the exact persisted versioned JSON report.
        #[arg(long)]
        json: bool,
    },
    /// Rescan and list active normalized artifacts.
    List {
        /// Emit the stable versioned JSON contract.
        #[arg(long)]
        json: bool,
    },
    /// Rescan and show one active artifact by exact stable ID.
    Show {
        #[arg(value_parser = parse_agent_artifact_id)]
        artifact_id: AgentArtifactId,
        /// Emit the stable versioned JSON contract.
        #[arg(long)]
        json: bool,
    },
    /// Manage the canonical skill library and agent materializations.
    Library {
        #[command(subcommand)]
        command: SkillsLibraryCommand,
    },
}

#[derive(Debug, Subcommand)]
enum SkillsLibraryCommand {
    /// List canonical library entries and project-scoped state.
    List {
        #[arg(long)]
        json: bool,
    },
    /// Adopt one exact artifact from a new complete live scan.
    Adopt {
        #[arg(value_parser = parse_canonical_entry_id)]
        entry_id: CanonicalEntryId,
        #[arg(value_parser = parse_agent_artifact_id)]
        artifact_id: AgentArtifactId,
        #[arg(long)]
        json: bool,
    },
    /// Install one exact local or Git artifact into the canonical library.
    Install {
        #[command(subcommand)]
        source: SkillsInstallCommand,
    },
    /// Enable one exact library version for this project and agent.
    Enable {
        #[arg(value_parser = parse_canonical_entry_id)]
        entry_id: CanonicalEntryId,
        #[arg(value_parser = parse_content_digest)]
        version: ContentDigest,
        #[arg(long, value_enum)]
        agent: SkillsAgentArg,
        #[arg(long)]
        json: bool,
    },
    /// Disable one exact version and safely clean up its managed copy.
    Disable {
        #[arg(value_parser = parse_canonical_entry_id)]
        entry_id: CanonicalEntryId,
        #[arg(value_parser = parse_content_digest)]
        version: ContentDigest,
        #[arg(long, value_enum)]
        agent: SkillsAgentArg,
        #[arg(long, value_name = "ABSOLUTE_PATH", value_parser = parse_agent_root)]
        root: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Preview or explicitly apply one library version to an agent root.
    Materialize {
        #[arg(value_parser = parse_canonical_entry_id)]
        entry_id: CanonicalEntryId,
        #[arg(value_parser = parse_content_digest)]
        version: ContentDigest,
        #[arg(long, value_enum)]
        agent: SkillsAgentArg,
        #[arg(long, value_name = "ABSOLUTE_PATH", value_parser = parse_agent_root)]
        root: Option<PathBuf>,
        /// Apply the preview. Without this flag the command performs no writes.
        #[arg(long)]
        apply: bool,
        #[arg(long)]
        json: bool,
    },
    /// Inspect one enabled managed copy for drift.
    Drift {
        #[arg(value_parser = parse_canonical_entry_id)]
        entry_id: CanonicalEntryId,
        #[arg(value_parser = parse_content_digest)]
        version: ContentDigest,
        #[arg(long, value_enum)]
        agent: SkillsAgentArg,
        #[arg(long, value_name = "ABSOLUTE_PATH", value_parser = parse_agent_root)]
        root: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Preview or explicitly apply a drift resynchronization.
    Resync {
        #[arg(value_parser = parse_canonical_entry_id)]
        entry_id: CanonicalEntryId,
        #[arg(value_parser = parse_content_digest)]
        version: ContentDigest,
        #[arg(long, value_enum)]
        agent: SkillsAgentArg,
        #[arg(long, value_name = "ABSOLUTE_PATH", value_parser = parse_agent_root)]
        root: Option<PathBuf>,
        /// Apply the preview. Without this flag the command performs no writes.
        #[arg(long)]
        apply: bool,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum SkillsInstallCommand {
    /// Install an absolute local regular file.
    Local {
        #[arg(value_parser = parse_canonical_entry_id)]
        entry_id: CanonicalEntryId,
        #[arg(value_name = "ABSOLUTE_FILE", value_parser = parse_install_path)]
        source: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Install one repository-relative file from a validated Git URL.
    Git {
        #[arg(value_parser = parse_canonical_entry_id)]
        entry_id: CanonicalEntryId,
        #[arg(value_name = "URL")]
        url: String,
        #[arg(value_name = "REPOSITORY_PATH")]
        artifact_path: String,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum FlowCommand {
    /// Validate and submit a project-local flow definition.
    Run {
        /// Exact flow ID or `<id>.toml` file name from `.pam/flows`.
        selector: String,
        /// Durable run ID; generated when omitted.
        #[arg(long, value_parser = parse_flow_run_id)]
        run_id: Option<RequestId>,
        /// Idempotency key; generated when omitted.
        #[arg(long, value_parser = parse_idempotency_key)]
        idempotency_key: Option<IdempotencyKey>,
        /// Stop observing after this bounded duration.
        #[arg(long, default_value = DEFAULT_WAIT_TIMEOUT, value_parser = parse_wait_timeout)]
        timeout: Duration,
        /// One-time exact-effect approval receipt, when policy requires it.
        #[arg(long, value_parser = parse_approval_id)]
        approval_id: Option<ApprovalId>,
    },
    /// List validated project-local flow definitions.
    List,
    /// Show one normalized project-local flow definition.
    Show { selector: String },
    /// Validate one flow, or every flow when no selector is supplied.
    Validate { selector: Option<String> },
    /// Cancel one durable flow run.
    Cancel {
        #[arg(value_parser = parse_flow_run_id)]
        run_id: RequestId,
        #[arg(long, value_parser = parse_approval_id)]
        approval_id: Option<ApprovalId>,
    },
    /// Replay durable flow events without waiting.
    Logs {
        #[arg(value_parser = parse_flow_run_id)]
        run_id: RequestId,
        #[arg(long, default_value_t = 0, value_parser = parse_flow_after)]
        after: u64,
        #[arg(long, value_parser = parse_approval_id)]
        approval_id: Option<ApprovalId>,
    },
    /// Replay and wait for a durable flow result.
    Wait {
        #[arg(value_parser = parse_flow_run_id)]
        run_id: RequestId,
        #[arg(long, default_value_t = 0, value_parser = parse_flow_after)]
        after: u64,
        #[arg(long, default_value = DEFAULT_WAIT_TIMEOUT, value_parser = parse_wait_timeout)]
        timeout: Duration,
        #[arg(long, value_parser = parse_approval_id)]
        approval_id: Option<ApprovalId>,
    },
    /// Read one durable flow result without waiting.
    Result {
        #[arg(value_parser = parse_flow_run_id)]
        run_id: RequestId,
        #[arg(long, value_parser = parse_approval_id)]
        approval_id: Option<ApprovalId>,
    },
}

#[derive(Debug, Subcommand)]
enum CallerCommand {
    /// Register a caller and save its credential in the native secure store.
    Register {
        /// Local caller surface to register.
        #[arg(long, value_enum, default_value_t = CallerKindArg::Cli)]
        kind: CallerKindArg,
    },
    /// Revoke a caller immediately.
    Revoke {
        /// Local caller surface to revoke.
        #[arg(long, value_enum, default_value_t = CallerKindArg::Cli)]
        kind: CallerKindArg,
    },
}

#[derive(Subcommand)]
enum ModelCommand {
    /// Verify and register an existing user-owned GGUF in place.
    Import {
        /// Stable model identity.
        #[arg(value_name = "VENDOR/NAME", value_parser = parse_model_key)]
        model: ModelKey,
        /// Absolute path to the existing GGUF.
        #[arg(long, value_name = "PATH")]
        path: PathBuf,
        /// Expected model digest in canonical `sha256:<lowercase-hex>` form.
        #[arg(long, value_parser = parse_content_digest)]
        digest: ContentDigest,
        /// Expected model file size in bytes.
        #[arg(long, value_parser = parse_positive_u64)]
        size_bytes: u64,
        /// SPDX-style model license identifier.
        #[arg(long)]
        license_id: String,
        /// Canonical HTTPS URL for the accepted license notice.
        #[arg(long)]
        license_url: String,
        /// Digest of the exact accepted license notice.
        #[arg(long, value_parser = parse_content_digest)]
        license_notice_digest: ContentDigest,
        /// Confirm acceptance of the exact model and license metadata above.
        #[arg(long)]
        accept_license: bool,
        /// One-time exact-effect approval receipt, when policy requires it.
        #[arg(long, value_parser = parse_approval_id)]
        approval_id: Option<ApprovalId>,
    },
    /// Generate text with the daemon's directly embedded llama.cpp runtime.
    Generate {
        /// Registered model identity selected when the daemon started.
        #[arg(value_name = "VENDOR/NAME", value_parser = parse_model_key)]
        model: ModelKey,
        /// User message sent to the embedded model.
        #[arg(value_name = "PROMPT")]
        prompt: String,
        /// Optional system message prepended to the conversation.
        #[arg(long)]
        system: Option<String>,
        /// Maximum generated tokens.
        #[arg(long, default_value_t = 128, value_parser = parse_model_output_tokens)]
        tokens: u32,
        /// Bound the complete request.
        #[arg(long, default_value = "5m", value_parser = parse_model_timeout)]
        timeout: Duration,
        /// One-time exact-effect approval receipt, when policy requires it.
        #[arg(long, value_parser = parse_approval_id)]
        approval_id: Option<ApprovalId>,
    },
}

#[derive(Debug, Subcommand)]
enum AccessCommand {
    /// Add an allow or explicit-deny grant for the current project.
    Grant {
        /// Stable capability name, such as daemon.status or evidence.read.
        #[arg(value_parser = parse_capability_name)]
        capability: CapabilityName,
        /// Exact resource; omit to match any resource.
        #[arg(long, value_parser = parse_resource_name)]
        resource: Option<ResourceName>,
        /// Create an explicit deny instead of an allow.
        #[arg(long)]
        deny: bool,
        /// Require a one-time exact-effect approval before use.
        #[arg(long, conflicts_with = "deny")]
        require_approval: bool,
        /// Optional absolute expiration time in Unix milliseconds.
        #[arg(long)]
        expires_at_unix_ms: Option<u64>,
        /// Local caller surface receiving the grant.
        #[arg(long, value_enum, default_value_t = CallerKindArg::Cli)]
        kind: CallerKindArg,
    },
    /// Revoke an existing grant.
    Revoke {
        #[arg(value_parser = parse_grant_id)]
        grant_id: GrantId,
    },
}

#[derive(Debug, Subcommand)]
enum ApprovalCommand {
    /// Approve a pending exact effect.
    Approve {
        #[arg(value_parser = parse_approval_id)]
        approval_id: ApprovalId,
    },
    /// Deny a pending exact effect.
    Deny {
        #[arg(value_parser = parse_approval_id)]
        approval_id: ApprovalId,
    },
}

#[derive(Debug, Subcommand)]
enum NetworkCommand {
    /// Report sanitized native trust, proxy, and PAC configuration facts.
    Diagnostics {
        /// One-time exact-effect approval receipt, when policy requires it.
        #[arg(long, value_parser = parse_approval_id)]
        approval_id: Option<ApprovalId>,
    },
}

#[derive(Debug, Subcommand)]
enum AuditCommand {
    /// Write bounded, deterministic NDJSON without overwriting an existing file.
    Export {
        /// New output path; existing files are never overwritten.
        #[arg(long, value_name = "PATH")]
        output: PathBuf,
        /// Export events strictly after this global sequence.
        #[arg(long, default_value_t = 0)]
        after: u64,
        /// Reuse the first page's inclusive high-water sequence on later pages.
        #[arg(long)]
        through: Option<u64>,
        /// One-time exact-effect approval receipt, when policy requires it.
        #[arg(long, value_parser = parse_approval_id)]
        approval_id: Option<ApprovalId>,
        /// Maximum events in this export page.
        #[arg(long, default_value_t = DEFAULT_AUDIT_EXPORT_LIMIT, value_parser = parse_audit_limit)]
        limit: usize,
    },
}

#[derive(Debug, Subcommand)]
enum RetentionCommand {
    /// Delete bounded evidence handles for the selected retention class.
    Prune {
        /// Retention class to remove from the current project.
        #[arg(long, value_enum)]
        scope: RetentionScopeArg,
        /// Delete handles created at or before this Unix timestamp in milliseconds.
        #[arg(long)]
        before_unix_ms: u64,
        /// One-time exact-effect approval receipt, when policy requires it.
        #[arg(long, value_parser = parse_approval_id)]
        approval_id: Option<ApprovalId>,
        /// Maximum handles to delete in this invocation.
        #[arg(long, default_value_t = DEFAULT_AUDIT_EXPORT_LIMIT, value_parser = parse_audit_limit)]
        limit: usize,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum CallerKindArg {
    Cli,
    Gui,
    CodingAgent,
    LocalApplication,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum RetentionScopeArg {
    Session,
    Project,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum SkillsAgentArg {
    Claude,
    Codex,
    Cursor,
}

impl SkillsAgentArg {
    #[must_use]
    pub(crate) const fn materialization_agent(self) -> MaterializationAgent {
        match self {
            Self::Claude => MaterializationAgent::Claude,
            Self::Codex => MaterializationAgent::Codex,
            Self::Cursor => MaterializationAgent::Cursor,
        }
    }

    #[must_use]
    pub(crate) const fn origin(self) -> OriginAgent {
        match self {
            Self::Claude => OriginAgent::ClaudeCode,
            Self::Codex => OriginAgent::Codex,
            Self::Cursor => OriginAgent::Cursor,
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) enum SkillsInstallSourceArg {
    Local(PathBuf),
    Git { url: String, artifact_path: String },
}

impl fmt::Debug for SkillsInstallSourceArg {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Local(_) => formatter.write_str("Local(..)"),
            Self::Git { .. } => formatter.write_str("Git(..)"),
        }
    }
}

#[derive(Eq, PartialEq)]
pub(crate) enum Mode {
    Client,
    Status {
        approval_id: Option<ApprovalId>,
    },
    Brief {
        approval_id: Option<ApprovalId>,
    },
    Wait {
        request_id: RequestId,
        after: u64,
        timeout: Duration,
        approval_id: Option<ApprovalId>,
    },
    Result {
        request_id: RequestId,
        approval_id: Option<ApprovalId>,
    },
    FlowRun {
        selector: String,
        run_id: Option<RequestId>,
        idempotency_key: Option<IdempotencyKey>,
        timeout: Duration,
        approval_id: Option<ApprovalId>,
    },
    FlowList,
    FlowShow {
        selector: String,
    },
    FlowValidate {
        selector: Option<String>,
    },
    FlowCancel {
        run_id: RequestId,
        approval_id: Option<ApprovalId>,
    },
    FlowLogs {
        run_id: RequestId,
        after: u64,
        approval_id: Option<ApprovalId>,
    },
    FlowWait {
        run_id: RequestId,
        after: u64,
        timeout: Duration,
        approval_id: Option<ApprovalId>,
    },
    FlowResult {
        run_id: RequestId,
        approval_id: Option<ApprovalId>,
    },
    EvidenceShow {
        handle: EvidenceHandle,
        raw: bool,
        output: Option<PathBuf>,
    },
    SkillsList {
        json: bool,
    },
    SkillsLibraryList {
        json: bool,
    },
    SkillsShow {
        artifact_id: AgentArtifactId,
        json: bool,
    },
    SkillsAudit {
        json: bool,
    },
    SkillsAdopt {
        entry_id: CanonicalEntryId,
        artifact_id: AgentArtifactId,
        json: bool,
    },
    SkillsInstall {
        entry_id: CanonicalEntryId,
        source: SkillsInstallSourceArg,
        json: bool,
    },
    SkillsEnable {
        entry_id: CanonicalEntryId,
        version: ContentDigest,
        agent: SkillsAgentArg,
        json: bool,
    },
    SkillsDisable {
        entry_id: CanonicalEntryId,
        version: ContentDigest,
        agent: SkillsAgentArg,
        root: Option<PathBuf>,
        json: bool,
    },
    SkillsMaterialize {
        entry_id: CanonicalEntryId,
        version: ContentDigest,
        agent: SkillsAgentArg,
        root: Option<PathBuf>,
        apply: bool,
        json: bool,
    },
    SkillsDrift {
        entry_id: CanonicalEntryId,
        version: ContentDigest,
        agent: SkillsAgentArg,
        root: Option<PathBuf>,
        json: bool,
    },
    SkillsResync {
        entry_id: CanonicalEntryId,
        version: ContentDigest,
        agent: SkillsAgentArg,
        root: Option<PathBuf>,
        apply: bool,
        json: bool,
    },
    CallerRegister {
        kind: CallerKindArg,
    },
    CallerRevoke {
        kind: CallerKindArg,
    },
    ModelImport {
        model: ModelKey,
        path: PathBuf,
        digest: ContentDigest,
        size_bytes: u64,
        license_id: String,
        license_url: String,
        license_notice_digest: ContentDigest,
        accept_license: bool,
        approval_id: Option<ApprovalId>,
    },
    ModelGenerate {
        model: ModelKey,
        prompt: String,
        system: Option<String>,
        tokens: u32,
        timeout: Duration,
        approval_id: Option<ApprovalId>,
    },
    AccessGrant {
        capability: CapabilityName,
        resource: Option<ResourceName>,
        deny: bool,
        require_approval: bool,
        expires_at_unix_ms: Option<u64>,
        kind: CallerKindArg,
    },
    AccessRevoke {
        grant_id: GrantId,
    },
    ApprovalApprove {
        approval_id: ApprovalId,
    },
    ApprovalDeny {
        approval_id: ApprovalId,
    },
    NetworkDiagnostics {
        approval_id: Option<ApprovalId>,
    },
    AuditExport {
        output: PathBuf,
        after: u64,
        through: Option<u64>,
        approval_id: Option<ApprovalId>,
        limit: usize,
    },
    RetentionPrune {
        scope: RetentionScopeArg,
        before_unix_ms: u64,
        approval_id: Option<ApprovalId>,
        limit: usize,
    },
    Daemon {
        recover: bool,
        model: Option<ModelKey>,
    },
    Gui,
}

impl fmt::Debug for Cli {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Cli")
            .field("command", &self.command)
            .finish()
    }
}

impl fmt::Debug for Command {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Model { command } => formatter.debug_tuple("Model").field(command).finish(),
            Self::Status { .. } => formatter.write_str("Status"),
            Self::Brief { .. } => formatter.write_str("Brief"),
            Self::Wait { .. } => formatter.write_str("Wait"),
            Self::Result { .. } => formatter.write_str("Result"),
            Self::Flow { .. } => formatter.write_str("Flow"),
            Self::Evidence { .. } => formatter.write_str("Evidence"),
            Self::Skills { .. } => formatter.write_str("Skills"),
            Self::Caller { .. } => formatter.write_str("Caller"),
            Self::Access { .. } => formatter.write_str("Access"),
            Self::Approval { .. } => formatter.write_str("Approval"),
            Self::Network { .. } => formatter.write_str("Network"),
            Self::Audit { .. } => formatter.write_str("Audit"),
            Self::Retention { .. } => formatter.write_str("Retention"),
            Self::Daemon { .. } => formatter.write_str("Daemon"),
            Self::Gui => formatter.write_str("Gui"),
        }
    }
}

impl fmt::Debug for ModelCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Import { .. } => formatter.write_str("Import"),
            Self::Generate {
                model,
                prompt,
                system,
                tokens,
                timeout,
                approval_id,
            } => formatter
                .debug_struct("Generate")
                .field("model", model)
                .field("prompt_bytes", &prompt.len())
                .field("system_bytes", &system.as_ref().map_or(0, String::len))
                .field("tokens", tokens)
                .field("timeout", timeout)
                .field("approval_id", approval_id)
                .finish(),
        }
    }
}

impl fmt::Debug for Mode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ModelGenerate {
                model,
                prompt,
                system,
                tokens,
                timeout,
                approval_id,
            } => formatter
                .debug_struct("ModelGenerate")
                .field("model", model)
                .field("prompt_bytes", &prompt.len())
                .field("system_bytes", &system.as_ref().map_or(0, String::len))
                .field("tokens", tokens)
                .field("timeout", timeout)
                .field("approval_id", approval_id)
                .finish(),
            Self::Client => formatter.write_str("Client"),
            Self::Status { .. } => formatter.write_str("Status"),
            Self::Brief { .. } => formatter.write_str("Brief"),
            Self::Wait { .. } => formatter.write_str("Wait"),
            Self::Result { .. } => formatter.write_str("Result"),
            Self::FlowRun { .. } => formatter.write_str("FlowRun"),
            Self::FlowList => formatter.write_str("FlowList"),
            Self::FlowShow { .. } => formatter.write_str("FlowShow"),
            Self::FlowValidate { .. } => formatter.write_str("FlowValidate"),
            Self::FlowCancel { .. } => formatter.write_str("FlowCancel"),
            Self::FlowLogs { .. } => formatter.write_str("FlowLogs"),
            Self::FlowWait { .. } => formatter.write_str("FlowWait"),
            Self::FlowResult { .. } => formatter.write_str("FlowResult"),
            Self::EvidenceShow { .. } => formatter.write_str("EvidenceShow"),
            Self::SkillsList { .. } => formatter.write_str("SkillsList"),
            Self::SkillsLibraryList { .. } => formatter.write_str("SkillsLibraryList"),
            Self::SkillsShow { .. } => formatter.write_str("SkillsShow"),
            Self::SkillsAudit { .. } => formatter.write_str("SkillsAudit"),
            Self::SkillsAdopt { .. } => formatter.write_str("SkillsAdopt"),
            Self::SkillsInstall { .. } => formatter.write_str("SkillsInstall"),
            Self::SkillsEnable { .. } => formatter.write_str("SkillsEnable"),
            Self::SkillsDisable { .. } => formatter.write_str("SkillsDisable"),
            Self::SkillsMaterialize { .. } => formatter.write_str("SkillsMaterialize"),
            Self::SkillsDrift { .. } => formatter.write_str("SkillsDrift"),
            Self::SkillsResync { .. } => formatter.write_str("SkillsResync"),
            Self::CallerRegister { .. } => formatter.write_str("CallerRegister"),
            Self::CallerRevoke { .. } => formatter.write_str("CallerRevoke"),
            Self::ModelImport { .. } => formatter.write_str("ModelImport"),
            Self::AccessGrant { .. } => formatter.write_str("AccessGrant"),
            Self::AccessRevoke { .. } => formatter.write_str("AccessRevoke"),
            Self::ApprovalApprove { .. } => formatter.write_str("ApprovalApprove"),
            Self::ApprovalDeny { .. } => formatter.write_str("ApprovalDeny"),
            Self::NetworkDiagnostics { .. } => formatter.write_str("NetworkDiagnostics"),
            Self::AuditExport { .. } => formatter.write_str("AuditExport"),
            Self::RetentionPrune { .. } => formatter.write_str("RetentionPrune"),
            Self::Daemon { .. } => formatter.write_str("Daemon"),
            Self::Gui => formatter.write_str("Gui"),
        }
    }
}

impl Cli {
    #[allow(clippy::too_many_lines)]
    pub(crate) fn mode(self) -> Mode {
        match self.command {
            None => Mode::Client,
            Some(Command::Status { approval_id }) => Mode::Status { approval_id },
            Some(Command::Brief { approval_id }) => Mode::Brief { approval_id },
            Some(Command::Wait {
                request_id,
                after,
                timeout,
                approval_id,
            }) => Mode::Wait {
                request_id,
                after,
                timeout,
                approval_id,
            },
            Some(Command::Result {
                request_id,
                approval_id,
            }) => Mode::Result {
                request_id,
                approval_id,
            },
            Some(Command::Flow { command }) => flow_mode(command),
            Some(Command::Evidence { command }) => evidence_mode(command),
            Some(Command::Skills { command }) => skills_mode(command),
            Some(Command::Caller {
                command: CallerCommand::Register { kind },
            }) => Mode::CallerRegister { kind },
            Some(Command::Caller {
                command: CallerCommand::Revoke { kind },
            }) => Mode::CallerRevoke { kind },
            Some(Command::Model {
                command:
                    ModelCommand::Import {
                        model,
                        path,
                        digest,
                        size_bytes,
                        license_id,
                        license_url,
                        license_notice_digest,
                        accept_license,
                        approval_id,
                    },
            }) => Mode::ModelImport {
                model,
                path,
                digest,
                size_bytes,
                license_id,
                license_url,
                license_notice_digest,
                accept_license,
                approval_id,
            },
            Some(Command::Model {
                command:
                    ModelCommand::Generate {
                        model,
                        prompt,
                        system,
                        tokens,
                        timeout,
                        approval_id,
                    },
            }) => Mode::ModelGenerate {
                model,
                prompt,
                system,
                tokens,
                timeout,
                approval_id,
            },
            Some(Command::Access {
                command:
                    AccessCommand::Grant {
                        capability,
                        resource,
                        deny,
                        require_approval,
                        expires_at_unix_ms,
                        kind,
                    },
            }) => Mode::AccessGrant {
                capability,
                resource,
                deny,
                require_approval,
                expires_at_unix_ms,
                kind,
            },
            Some(Command::Access {
                command: AccessCommand::Revoke { grant_id },
            }) => Mode::AccessRevoke { grant_id },
            Some(Command::Approval {
                command: ApprovalCommand::Approve { approval_id },
            }) => Mode::ApprovalApprove { approval_id },
            Some(Command::Approval {
                command: ApprovalCommand::Deny { approval_id },
            }) => Mode::ApprovalDeny { approval_id },
            Some(Command::Network {
                command: NetworkCommand::Diagnostics { approval_id },
            }) => Mode::NetworkDiagnostics { approval_id },
            Some(Command::Audit {
                command:
                    AuditCommand::Export {
                        output,
                        after,
                        through,
                        approval_id,
                        limit,
                    },
            }) => Mode::AuditExport {
                output,
                after,
                through,
                approval_id,
                limit,
            },
            Some(Command::Retention {
                command:
                    RetentionCommand::Prune {
                        scope,
                        before_unix_ms,
                        approval_id,
                        limit,
                    },
            }) => Mode::RetentionPrune {
                scope,
                before_unix_ms,
                approval_id,
                limit,
            },
            Some(Command::Daemon { recover, model }) => Mode::Daemon { recover, model },
            Some(Command::Gui) => Mode::Gui,
        }
    }
}

fn skills_mode(command: SkillsCommand) -> Mode {
    match command {
        SkillsCommand::Audit { json } => Mode::SkillsAudit { json },
        SkillsCommand::List { json } => Mode::SkillsList { json },
        SkillsCommand::Show { artifact_id, json } => Mode::SkillsShow { artifact_id, json },
        SkillsCommand::Library { command } => skills_library_mode(command),
    }
}

fn skills_library_mode(command: SkillsLibraryCommand) -> Mode {
    match command {
        SkillsLibraryCommand::List { json } => Mode::SkillsLibraryList { json },
        SkillsLibraryCommand::Adopt {
            entry_id,
            artifact_id,
            json,
        } => Mode::SkillsAdopt {
            entry_id,
            artifact_id,
            json,
        },
        SkillsLibraryCommand::Install { source } => match source {
            SkillsInstallCommand::Local {
                entry_id,
                source,
                json,
            } => Mode::SkillsInstall {
                entry_id,
                source: SkillsInstallSourceArg::Local(source),
                json,
            },
            SkillsInstallCommand::Git {
                entry_id,
                url,
                artifact_path,
                json,
            } => Mode::SkillsInstall {
                entry_id,
                source: SkillsInstallSourceArg::Git { url, artifact_path },
                json,
            },
        },
        SkillsLibraryCommand::Enable {
            entry_id,
            version,
            agent,
            json,
        } => Mode::SkillsEnable {
            entry_id,
            version,
            agent,
            json,
        },
        SkillsLibraryCommand::Disable {
            entry_id,
            version,
            agent,
            root,
            json,
        } => Mode::SkillsDisable {
            entry_id,
            version,
            agent,
            root,
            json,
        },
        SkillsLibraryCommand::Materialize {
            entry_id,
            version,
            agent,
            root,
            apply,
            json,
        } => Mode::SkillsMaterialize {
            entry_id,
            version,
            agent,
            root,
            apply,
            json,
        },
        SkillsLibraryCommand::Drift {
            entry_id,
            version,
            agent,
            root,
            json,
        } => Mode::SkillsDrift {
            entry_id,
            version,
            agent,
            root,
            json,
        },
        SkillsLibraryCommand::Resync {
            entry_id,
            version,
            agent,
            root,
            apply,
            json,
        } => Mode::SkillsResync {
            entry_id,
            version,
            agent,
            root,
            apply,
            json,
        },
    }
}

fn evidence_mode(command: EvidenceCommand) -> Mode {
    match command {
        EvidenceCommand::Show {
            handle,
            raw,
            output,
        } => Mode::EvidenceShow {
            handle,
            raw,
            output,
        },
    }
}

fn flow_mode(command: FlowCommand) -> Mode {
    match command {
        FlowCommand::Run {
            selector,
            run_id,
            idempotency_key,
            timeout,
            approval_id,
        } => Mode::FlowRun {
            selector,
            run_id,
            idempotency_key,
            timeout,
            approval_id,
        },
        FlowCommand::List => Mode::FlowList,
        FlowCommand::Show { selector } => Mode::FlowShow { selector },
        FlowCommand::Validate { selector } => Mode::FlowValidate { selector },
        FlowCommand::Cancel {
            run_id,
            approval_id,
        } => Mode::FlowCancel {
            run_id,
            approval_id,
        },
        FlowCommand::Logs {
            run_id,
            after,
            approval_id,
        } => Mode::FlowLogs {
            run_id,
            after,
            approval_id,
        },
        FlowCommand::Wait {
            run_id,
            after,
            timeout,
            approval_id,
        } => Mode::FlowWait {
            run_id,
            after,
            timeout,
            approval_id,
        },
        FlowCommand::Result {
            run_id,
            approval_id,
        } => Mode::FlowResult {
            run_id,
            approval_id,
        },
    }
}

fn parse_request_id(value: &str) -> Result<RequestId, String> {
    if value.is_empty()
        || value
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(
            "request ID must be non-empty and contain no whitespace or controls".to_owned(),
        );
    }
    Ok(RequestId::from(value.to_owned()))
}

fn parse_idempotency_key(value: &str) -> Result<IdempotencyKey, String> {
    if value.is_empty()
        || value.len() > 256
        || value.starts_with('-')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        return Err(
            "idempotency key must contain 1 to 256 shell-safe ASCII bytes and not start with '-'"
                .to_owned(),
        );
    }
    Ok(IdempotencyKey::from(value.to_owned()))
}

fn parse_flow_run_id(value: &str) -> Result<RequestId, String> {
    pam_flow::RunId::parse(value)
        .map(|run_id| RequestId::from(run_id.as_str().to_owned()))
        .map_err(|error| error.to_string())
}

fn parse_flow_after(value: &str) -> Result<u64, String> {
    let sequence = value
        .parse::<u64>()
        .map_err(|_| "flow sequence must be an unsigned integer".to_owned())?;
    if sequence > i64::MAX as u64 {
        return Err("flow sequence exceeds the supported range".to_owned());
    }
    Ok(sequence)
}

fn parse_evidence_handle(value: &str) -> Result<EvidenceHandle, String> {
    EvidenceHandle::parse(value.to_owned()).map_err(|error| error.to_string())
}

fn parse_agent_artifact_id(value: &str) -> Result<AgentArtifactId, String> {
    AgentArtifactId::parse(value.to_owned()).map_err(|error| error.to_string())
}

fn parse_canonical_entry_id(value: &str) -> Result<CanonicalEntryId, String> {
    CanonicalEntryId::parse(value.to_owned()).map_err(|error| error.to_string())
}

fn parse_agent_root(value: &str) -> Result<PathBuf, String> {
    parse_bounded_absolute_path(value, "agent root")
}

fn parse_install_path(value: &str) -> Result<PathBuf, String> {
    parse_bounded_absolute_path(value, "local install source")
}

fn parse_bounded_absolute_path(value: &str, label: &str) -> Result<PathBuf, String> {
    const MAX_CLI_PATH_BYTES: usize = 4_096;
    let path = PathBuf::from(value);
    if value.is_empty()
        || value.len() > MAX_CLI_PATH_BYTES
        || value.chars().any(char::is_control)
        || !path.is_absolute()
    {
        return Err(format!("{label} must be an absolute bounded path"));
    }
    Ok(path)
}

fn parse_capability_name(value: &str) -> Result<CapabilityName, String> {
    CapabilityName::parse(value.to_owned()).map_err(|error| error.to_string())
}

fn parse_model_key(value: &str) -> Result<ModelKey, String> {
    let Some((vendor, name)) = value.split_once('/') else {
        return Err("model identity must use vendor/name form".to_owned());
    };
    if name.contains('/') {
        return Err("model identity must contain exactly one slash".to_owned());
    }
    ModelKey::new(vendor, name).map_err(|error| error.to_string())
}

fn parse_content_digest(value: &str) -> Result<ContentDigest, String> {
    ContentDigest::parse(value.to_owned()).map_err(|error| error.to_string())
}

fn parse_positive_u64(value: &str) -> Result<u64, String> {
    let value = value
        .parse::<u64>()
        .map_err(|_| "value must be an unsigned integer".to_owned())?;
    if value == 0 {
        return Err("value must be greater than zero".to_owned());
    }
    Ok(value)
}

fn parse_model_output_tokens(value: &str) -> Result<u32, String> {
    let tokens = value
        .parse::<u32>()
        .map_err(|_| "model output tokens must be a positive integer".to_owned())?;
    if tokens == 0 || tokens > pam_protocol::MAX_MODEL_OUTPUT_TOKENS {
        return Err(format!(
            "model output tokens must be between 1 and {}",
            pam_protocol::MAX_MODEL_OUTPUT_TOKENS
        ));
    }
    Ok(tokens)
}

fn parse_model_timeout(value: &str) -> Result<Duration, String> {
    let timeout = parse_wait_timeout(value)?;
    if timeout.is_zero() || timeout > MAX_MODEL_TIMEOUT {
        return Err("model timeout must be between 1ms and 10m".to_owned());
    }
    Ok(timeout)
}

fn parse_resource_name(value: &str) -> Result<ResourceName, String> {
    ResourceName::parse(value.to_owned()).map_err(|error| error.to_string())
}

fn parse_grant_id(value: &str) -> Result<GrantId, String> {
    parse_simple_id(value, "grant ID").map(GrantId::from)
}

fn parse_approval_id(value: &str) -> Result<ApprovalId, String> {
    parse_simple_id(value, "approval ID").map(ApprovalId::from)
}

fn parse_simple_id(value: &str, label: &str) -> Result<String, String> {
    if value.is_empty()
        || value
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
        || value.len() > 256
    {
        return Err(format!(
            "{label} must contain 1 to 256 bytes with no whitespace or controls"
        ));
    }
    Ok(value.to_owned())
}

fn parse_audit_limit(value: &str) -> Result<usize, String> {
    let limit = value
        .parse::<usize>()
        .map_err(|_| "limit must be a positive integer".to_owned())?;
    if limit == 0 || limit > MAX_AUDIT_EXPORT_LIMIT {
        return Err(format!(
            "limit must be between 1 and {MAX_AUDIT_EXPORT_LIMIT}"
        ));
    }
    Ok(limit)
}

fn parse_wait_timeout(value: &str) -> Result<Duration, String> {
    let (number, unit) = if let Some(number) = value.strip_suffix("ms") {
        (number, TimeoutUnit::Milliseconds)
    } else if let Some(number) = value.strip_suffix('s') {
        (number, TimeoutUnit::Seconds)
    } else if let Some(number) = value.strip_suffix('m') {
        (number, TimeoutUnit::Minutes)
    } else if let Some(number) = value.strip_suffix('h') {
        (number, TimeoutUnit::Hours)
    } else {
        return Err("duration must use one of: ms, s, m, or h".to_owned());
    };
    let amount = number.parse::<u64>().map_err(|_| {
        "duration must be a whole non-negative number followed by a unit".to_owned()
    })?;
    let duration = match unit {
        TimeoutUnit::Milliseconds => Duration::from_millis(amount),
        TimeoutUnit::Seconds => Duration::from_secs(amount),
        TimeoutUnit::Minutes => {
            if amount > u64::MAX / 60 {
                return Err("duration is too large".to_owned());
            }
            Duration::from_mins(amount)
        }
        TimeoutUnit::Hours => {
            if amount > u64::MAX / (60 * 60) {
                return Err("duration is too large".to_owned());
            }
            Duration::from_hours(amount)
        }
    };
    if duration.is_zero() {
        return Err("duration must be greater than zero".to_owned());
    }
    if duration > MAX_WAIT_TIMEOUT {
        return Err("duration must not exceed 24h".to_owned());
    }
    Ok(duration)
}

#[derive(Clone, Copy)]
enum TimeoutUnit {
    Milliseconds,
    Seconds,
    Minutes,
    Hours,
}
