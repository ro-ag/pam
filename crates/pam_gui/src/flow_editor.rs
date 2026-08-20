use std::{
    error::Error,
    fmt,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use cap_fs_ext::{
    DirExt as _, FollowSymlinks, OpenOptionsFollowExt as _, OpenOptionsSyncExt as _,
    ambient_authority,
};
use cap_std::fs::{Dir, OpenOptions};
use pam_flow::{
    ApprovalMode, EffectKind, FlowDefinition, FlowDigest, FlowParseError, MAX_FLOW_DOCUMENT_BYTES,
    RetryPolicy, StepCondition, StepSemanticRole,
};

/// Maximum number of direct entries inspected in `.pam/flows`.
pub const MAX_FLOW_CATALOG_ENTRIES: usize = 256;
/// Maximum total bytes retained from valid flow documents in one catalog.
pub const MAX_FLOW_CATALOG_BYTES: usize = 8 * MAX_FLOW_DOCUMENT_BYTES;
/// Maximum number of normalized lines exposed by a version diff.
pub const MAX_VERSION_DIFF_LINES: usize = 1_024;

const MAX_SELECTOR_BYTES: usize = 256;
const MAX_VALIDATION_MESSAGE_BYTES: usize = 2_048;
const SAVE_TEMP_ATTEMPTS: u64 = 8;
static SAVE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Stable catalog identity for one validated flow version.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlowIdentity {
    file_name: String,
    id: String,
    revision: u64,
    digest: FlowDigest,
}

impl FlowIdentity {
    fn from_definition(definition: &FlowDefinition) -> Result<Self, FlowEditorError> {
        let digest = definition
            .normalized_digest()
            .map_err(|error| invalid_validation(&error))?;
        Ok(Self {
            file_name: format!("{}.toml", definition.id()),
            id: definition.id().to_owned(),
            revision: definition.revision(),
            digest,
        })
    }

    #[must_use]
    pub fn file_name(&self) -> &str {
        &self.file_name
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub const fn digest(&self) -> FlowDigest {
        self.digest
    }
}

/// One direct, validated catalog entry.
#[derive(Clone, Debug)]
pub struct FlowCatalogEntry {
    identity: FlowIdentity,
    source: String,
    normalized: String,
    definition: FlowDefinition,
}

impl FlowCatalogEntry {
    #[must_use]
    pub const fn identity(&self) -> &FlowIdentity {
        &self.identity
    }

    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    #[must_use]
    pub fn normalized_toml(&self) -> &str {
        &self.normalized
    }

    #[must_use]
    pub const fn definition(&self) -> &FlowDefinition {
        &self.definition
    }
}

/// Rust-side state for a project-local flow editor.
pub struct FlowEditorModel {
    project_root: PathBuf,
    project_directory: Arc<Dir>,
    entries: Vec<FlowCatalogEntry>,
}

impl fmt::Debug for FlowEditorModel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FlowEditorModel")
            .field("project_root", &self.project_root)
            .field("entries", &self.entries)
            .finish_non_exhaustive()
    }
}

impl FlowEditorModel {
    /// Opens a project and loads its bounded direct `.pam/flows` catalog.
    ///
    /// Missing catalog directories represent an empty catalog. Existing
    /// directories and definition files must not be symbolic links.
    ///
    /// # Errors
    ///
    /// Returns a bounded catalog/path/definition error without following a
    /// catalog symlink.
    pub fn open(project_root: impl AsRef<Path>) -> Result<Self, FlowEditorError> {
        Self::open_with_hooks(project_root.as_ref(), |_, _| {}, |_, _| {})
    }

    fn open_with_hooks<F, G>(
        project_root: &Path,
        mut before_open: F,
        mut after_metadata: G,
    ) -> Result<Self, FlowEditorError>
    where
        F: FnMut(&Dir, &str),
        G: FnMut(&Dir, &str),
    {
        let project_root = project_root
            .canonicalize()
            .map_err(FlowEditorError::ProjectRoot)?;
        let project_directory = Arc::new(
            Dir::open_ambient_dir(&project_root, ambient_authority())
                .map_err(FlowEditorError::ProjectRoot)?,
        );
        let entries = load_catalog(
            project_directory.as_ref(),
            &mut before_open,
            &mut after_metadata,
        )?;
        Ok(Self {
            project_root,
            project_directory,
            entries,
        })
    }

    #[cfg(test)]
    pub(crate) fn open_after_candidate<F>(
        project_root: &Path,
        before_open: F,
    ) -> Result<Self, FlowEditorError>
    where
        F: FnMut(&Dir, &str),
    {
        Self::open_with_hooks(project_root, before_open, |_, _| {})
    }

    #[cfg(test)]
    pub(crate) fn open_after_metadata<F>(
        project_root: &Path,
        after_metadata: F,
    ) -> Result<Self, FlowEditorError>
    where
        F: FnMut(&Dir, &str),
    {
        Self::open_with_hooks(project_root, |_, _| {}, after_metadata)
    }

    #[must_use]
    pub fn project_root(&self) -> &Path {
        &self.project_root
    }

    #[must_use]
    pub fn entries(&self) -> &[FlowCatalogEntry] {
        &self.entries
    }

    /// Reopens the bounded catalog through the retained project authority.
    ///
    /// # Errors
    ///
    /// Returns an error if the catalog is no longer safe and valid.
    pub fn reload(&mut self) -> Result<(), FlowEditorError> {
        self.entries = load_catalog(
            self.project_directory.as_ref(),
            &mut |_, _| {},
            &mut |_, _| {},
        )?;
        Ok(())
    }

    /// Selects a definition by exact ID or exact `<id>.toml` file name.
    ///
    /// # Errors
    ///
    /// Rejects traversal-like selectors and missing definitions.
    pub fn entry(&self, selector: &str) -> Result<&FlowCatalogEntry, FlowEditorError> {
        validate_selector(selector)?;
        self.entries
            .iter()
            .find(|entry| selector == entry.identity.id() || selector == entry.identity.file_name())
            .ok_or_else(|| FlowEditorError::NotFound(selector.to_owned()))
    }

    /// Opens an existing definition as an editable document.
    ///
    /// # Errors
    ///
    /// Rejects an unsafe selector or a missing definition.
    pub fn open_document(&self, selector: &str) -> Result<FlowEditorDocument, FlowEditorError> {
        let entry = self.entry(selector)?;
        Ok(FlowEditorDocument {
            project_directory: Arc::clone(&self.project_directory),
            source: entry.source.clone(),
            baseline: Some(SavedBaseline::from_entry(entry)),
        })
    }

    /// Creates an unsaved editable document without touching the filesystem.
    ///
    /// # Errors
    ///
    /// Rejects source larger than the flow schema's document bound.
    pub fn new_document(
        &self,
        source: impl Into<String>,
    ) -> Result<FlowEditorDocument, FlowEditorError> {
        let source = source.into();
        validate_source_size(&source)?;
        Ok(FlowEditorDocument {
            project_directory: Arc::clone(&self.project_directory),
            source,
            baseline: None,
        })
    }
}

/// Editable source plus a stable on-disk baseline used for conflict detection.
pub struct FlowEditorDocument {
    project_directory: Arc<Dir>,
    source: String,
    baseline: Option<SavedBaseline>,
}

impl fmt::Debug for FlowEditorDocument {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FlowEditorDocument")
            .field("source_bytes", &self.source.len())
            .field("baseline", &self.baseline)
            .finish_non_exhaustive()
    }
}

impl FlowEditorDocument {
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    #[must_use]
    pub fn saved_identity(&self) -> Option<&FlowIdentity> {
        self.baseline.as_ref().map(|baseline| &baseline.identity)
    }

    /// Replaces editor text without touching the filesystem.
    ///
    /// Invalid, in-bound TOML is retained so a UI can continue editing it.
    ///
    /// # Errors
    ///
    /// Rejects source larger than [`MAX_FLOW_DOCUMENT_BYTES`] and leaves the
    /// previous text intact.
    pub fn replace_source(&mut self, source: impl Into<String>) -> Result<(), FlowEditorError> {
        let source = source.into();
        validate_source_size(&source)?;
        self.source = source;
        Ok(())
    }

    /// Parses, validates, normalizes, and identifies the current editor text.
    ///
    /// # Errors
    ///
    /// Returns syntax/schema/identity/version validation feedback.
    pub fn validate(&self) -> Result<FlowEditorValidation, FlowEditorError> {
        validate_draft(&self.source, self.baseline.as_ref())
    }

    /// Builds a deterministic, non-executing plan from the current text.
    ///
    /// # Errors
    ///
    /// Returns current editor validation failures.
    pub fn dry_run(&self) -> Result<FlowDryRunPlan, FlowEditorError> {
        let validation = self.validate()?;
        Ok(FlowDryRunPlan::from_validation(&validation))
    }

    /// Computes a deterministic line-level diff of normalized flow versions.
    ///
    /// # Errors
    ///
    /// Returns current editor validation failures.
    pub fn version_diff(&self) -> Result<FlowVersionDiff, FlowEditorError> {
        let validation = self.validate()?;
        Ok(version_diff(
            self.baseline.as_ref(),
            &validation.identity,
            &validation.normalized,
        ))
    }

    /// Freezes the validated normalized bytes, identity, and version diff for
    /// a later user-confirmed save.
    ///
    /// # Errors
    ///
    /// Returns current editor validation failures.
    pub fn prepare_save(&self) -> Result<FlowSaveInteraction, FlowEditorError> {
        let validation = self.validate()?;
        let diff = version_diff(
            self.baseline.as_ref(),
            &validation.identity,
            &validation.normalized,
        );
        Ok(FlowSaveInteraction {
            edited_source: self.source.clone(),
            baseline: self.baseline.clone(),
            identity: validation.identity,
            normalized: validation.normalized,
            diff,
        })
    }

    /// Atomically publishes a previously prepared normalized save.
    ///
    /// The interaction must still match this document. Cooperating editor
    /// writers serialize through a process-crash-releasing advisory lock.
    /// Existing files are checked twice against their complete opened bytes,
    /// and new documents never overwrite an existing entry. Filesystems do
    /// not expose a portable compare-and-swap rename: a writer that ignores
    /// the advisory lock in the final verify-to-rename syscall interval is
    /// outside this save contract.
    ///
    /// # Errors
    ///
    /// Returns stale-interaction, observed external-edit, unsafe-path, busy, or
    /// I/O failures. Pre-publication failures leave the target unchanged. An
    /// explicit publication-uncertain error retains a named prior-byte backup
    /// and requires a reload before another save.
    pub fn commit_save(
        &mut self,
        interaction: FlowSaveInteraction,
    ) -> Result<FlowSaveResult, FlowEditorError> {
        self.commit_save_with_hook(interaction, || {})
    }

    fn commit_save_with_hook<F>(
        &mut self,
        interaction: FlowSaveInteraction,
        after_final_check: F,
    ) -> Result<FlowSaveResult, FlowEditorError>
    where
        F: FnOnce(),
    {
        if interaction.edited_source != self.source || interaction.baseline != self.baseline {
            return Err(FlowEditorError::StaleSaveInteraction);
        }
        let validation = self.validate()?;
        if interaction.identity != validation.identity
            || interaction.normalized != validation.normalized
        {
            return Err(FlowEditorError::StaleSaveInteraction);
        }

        let created = interaction.baseline.is_none();
        let publication = atomic_save(
            self.project_directory.as_ref(),
            &interaction.identity,
            interaction.baseline.as_ref(),
            interaction.normalized.as_bytes(),
            after_final_check,
        )?;
        self.source.clone_from(&interaction.normalized);
        self.baseline = Some(SavedBaseline {
            identity: interaction.identity.clone(),
            exact_source: interaction.normalized,
            normalized: validation.normalized,
        });
        Ok(FlowSaveResult {
            identity: interaction.identity,
            created,
            durability_confirmed: publication.durability_confirmed,
            cleanup_complete: publication.cleanup_complete,
        })
    }

    #[cfg(test)]
    pub(crate) fn commit_save_after_final_check<F>(
        &mut self,
        interaction: FlowSaveInteraction,
        after_final_check: F,
    ) -> Result<FlowSaveResult, FlowEditorError>
    where
        F: FnOnce(),
    {
        self.commit_save_with_hook(interaction, after_final_check)
    }
}

/// Successful parse/validation result for current editor text.
#[derive(Clone, Debug)]
pub struct FlowEditorValidation {
    definition: FlowDefinition,
    normalized: String,
    identity: FlowIdentity,
}

impl FlowEditorValidation {
    #[must_use]
    pub const fn definition(&self) -> &FlowDefinition {
        &self.definition
    }

    #[must_use]
    pub fn normalized_toml(&self) -> &str {
        &self.normalized
    }

    #[must_use]
    pub const fn identity(&self) -> &FlowIdentity {
        &self.identity
    }
}

/// User-reviewable save snapshot. Its internals are intentionally immutable.
#[derive(Debug)]
pub struct FlowSaveInteraction {
    edited_source: String,
    baseline: Option<SavedBaseline>,
    identity: FlowIdentity,
    normalized: String,
    diff: FlowVersionDiff,
}

impl FlowSaveInteraction {
    #[must_use]
    pub const fn identity(&self) -> &FlowIdentity {
        &self.identity
    }

    #[must_use]
    pub fn normalized_toml(&self) -> &str {
        &self.normalized
    }

    #[must_use]
    pub const fn diff(&self) -> &FlowVersionDiff {
        &self.diff
    }

    #[must_use]
    pub const fn creates_file(&self) -> bool {
        self.baseline.is_none()
    }
}

/// Result of one durable save publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlowSaveResult {
    identity: FlowIdentity,
    created: bool,
    durability_confirmed: bool,
    cleanup_complete: bool,
}

impl FlowSaveResult {
    #[must_use]
    pub const fn identity(&self) -> &FlowIdentity {
        &self.identity
    }

    #[must_use]
    pub const fn created(&self) -> bool {
        self.created
    }

    /// Whether directory synchronization confirmed the atomic publication.
    /// This is conservatively false on targets without a portable directory
    /// synchronization primitive.
    #[must_use]
    pub const fn durability_confirmed(&self) -> bool {
        self.durability_confirmed
    }

    /// Whether publication completed without a temporary-file cleanup debt.
    /// The reusable advisory lock inode intentionally remains in `.pam`.
    #[must_use]
    pub const fn cleanup_complete(&self) -> bool {
        self.cleanup_complete
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SavedBaseline {
    identity: FlowIdentity,
    exact_source: String,
    normalized: String,
}

impl SavedBaseline {
    fn from_entry(entry: &FlowCatalogEntry) -> Self {
        Self {
            identity: entry.identity.clone(),
            exact_source: entry.source.clone(),
            normalized: entry.normalized.clone(),
        }
    }
}

/// Deterministic dry-run plan. Constructing it performs no filesystem action
/// beyond the earlier catalog read and never starts a command or connector.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlowDryRunPlan {
    identity: FlowIdentity,
    steps: Vec<DryRunStep>,
    daemon_definition_eligible: bool,
}

impl FlowDryRunPlan {
    fn from_validation(validation: &FlowEditorValidation) -> Self {
        let definition = &validation.definition;
        let steps = definition
            .steps()
            .iter()
            .enumerate()
            .map(|(index, step)| {
                let action = ActionAuthority::from_definition(step.action());
                let daemon_authority = daemon_authority(definition, step);
                DryRunStep {
                    index,
                    id: step.id().to_owned(),
                    semantic_role: step.semantic_role(),
                    condition: DryRunCondition::from_definition(step.condition()),
                    approval: step.approval(),
                    retry: *step.retry(),
                    effect: step.effect(),
                    action,
                    daemon_authority,
                }
            })
            .collect::<Vec<_>>();
        let daemon_definition_eligible = steps.iter().all(|step| {
            matches!(
                step.daemon_authority,
                DaemonAuthority::EligibleAfterRuntimeChecks
            )
        });
        Self {
            identity: validation.identity.clone(),
            steps,
            daemon_definition_eligible,
        }
    }

    #[must_use]
    pub const fn identity(&self) -> &FlowIdentity {
        &self.identity
    }

    #[must_use]
    pub fn steps(&self) -> &[DryRunStep] {
        &self.steps
    }

    /// True only when every action has a shape accepted by the current daemon.
    /// Runtime workspace, executable, policy, and authorization checks remain.
    #[must_use]
    pub const fn daemon_definition_eligible(&self) -> bool {
        self.daemon_definition_eligible
    }
}

/// One declared step in a dry-run plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DryRunStep {
    index: usize,
    id: String,
    semantic_role: StepSemanticRole,
    condition: DryRunCondition,
    approval: ApprovalMode,
    retry: RetryPolicy,
    effect: EffectKind,
    action: ActionAuthority,
    daemon_authority: DaemonAuthority,
}

impl DryRunStep {
    #[must_use]
    pub const fn index(&self) -> usize {
        self.index
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub const fn semantic_role(&self) -> StepSemanticRole {
        self.semantic_role
    }

    #[must_use]
    pub const fn condition(&self) -> &DryRunCondition {
        &self.condition
    }

    #[must_use]
    pub const fn approval(&self) -> ApprovalMode {
        self.approval
    }

    #[must_use]
    pub const fn retry(&self) -> RetryPolicy {
        self.retry
    }

    #[must_use]
    pub const fn effect(&self) -> EffectKind {
        self.effect
    }

    #[must_use]
    pub const fn action(&self) -> &ActionAuthority {
        &self.action
    }

    #[must_use]
    pub const fn daemon_authority(&self) -> DaemonAuthority {
        self.daemon_authority
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DryRunCondition {
    Always,
    Succeeded { step_id: String },
    Failed { step_id: String },
}

impl DryRunCondition {
    fn from_definition(condition: &StepCondition) -> Self {
        match condition {
            StepCondition::Always => Self::Always,
            StepCondition::Succeeded { step } => Self::Succeeded {
                step_id: step.clone(),
            },
            StepCondition::Failed { step } => Self::Failed {
                step_id: step.clone(),
            },
        }
    }
}

/// Exact authority declared by a flow action, without executing it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActionAuthority {
    Command {
        program: String,
        arguments: Vec<String>,
        working_directory: String,
    },
    Connector {
        connector: String,
        capability: String,
        resource_kind: String,
        resource_id: String,
    },
}

impl ActionAuthority {
    fn from_definition(action: &pam_flow::StepAction) -> Self {
        if let Some(command) = action.as_command() {
            return Self::Command {
                program: command.program.to_owned(),
                arguments: command.args.to_vec(),
                working_directory: command.working_directory.to_owned(),
            };
        }
        let connector = action
            .as_connector()
            .expect("validated flow actions are command or connector");
        Self::Connector {
            connector: connector.connector.to_owned(),
            capability: connector.capability.to_owned(),
            resource_kind: connector.resource.kind().to_owned(),
            resource_id: connector.resource.id().to_owned(),
        }
    }
}

/// Current daemon support for one declared action shape.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DaemonAuthority {
    /// The definition shape is eligible, but workspace, executable, policy,
    /// approval, and authorization checks still occur at submission/runtime.
    EligibleAfterRuntimeChecks,
    Unsupported(UnsupportedDaemonAuthority),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnsupportedDaemonAuthority {
    Connector,
    StatefulEffect,
    Approval,
    Program,
    WorkingDirectory,
    GitArguments,
    SemanticRole,
}

/// One deterministic normalized-version diff.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlowVersionDiff {
    previous: Option<FlowIdentity>,
    edited: FlowIdentity,
    lines: Vec<FlowVersionDiffLine>,
    changed: bool,
    truncated: bool,
}

impl FlowVersionDiff {
    #[must_use]
    pub const fn previous(&self) -> Option<&FlowIdentity> {
        self.previous.as_ref()
    }

    #[must_use]
    pub const fn edited(&self) -> &FlowIdentity {
        &self.edited
    }

    #[must_use]
    pub fn lines(&self) -> &[FlowVersionDiffLine] {
        &self.lines
    }

    #[must_use]
    pub const fn truncated(&self) -> bool {
        self.truncated
    }

    #[must_use]
    pub const fn changed(&self) -> bool {
        self.changed
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlowVersionDiffLine {
    kind: FlowVersionDiffLineKind,
    text: String,
}

impl FlowVersionDiffLine {
    #[must_use]
    pub const fn kind(&self) -> FlowVersionDiffLineKind {
        self.kind
    }

    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowVersionDiffLineKind {
    Context,
    Removed,
    Added,
}

fn version_diff(
    baseline: Option<&SavedBaseline>,
    edited: &FlowIdentity,
    edited_normalized: &str,
) -> FlowVersionDiff {
    let previous_lines = baseline.map_or_else(Vec::new, |value| {
        value.normalized.lines().collect::<Vec<_>>()
    });
    let edited_lines = edited_normalized.lines().collect::<Vec<_>>();
    let (lines, truncated) = deterministic_diff(&previous_lines, &edited_lines);
    FlowVersionDiff {
        previous: baseline.map(|value| value.identity.clone()),
        edited: edited.clone(),
        lines,
        changed: baseline.is_none_or(|value| value.identity.digest != edited.digest),
        truncated,
    }
}

fn deterministic_diff(previous: &[&str], edited: &[&str]) -> (Vec<FlowVersionDiffLine>, bool) {
    let prefix = previous
        .iter()
        .zip(edited)
        .take_while(|(left, right)| left == right)
        .count();
    let suffix = previous[prefix..]
        .iter()
        .rev()
        .zip(edited[prefix..].iter().rev())
        .take_while(|(left, right)| left == right)
        .count();
    let previous_middle_end = previous.len() - suffix;
    let edited_middle_end = edited.len() - suffix;
    let total_lines = prefix
        .saturating_add(previous_middle_end - prefix)
        .saturating_add(edited_middle_end - prefix)
        .saturating_add(suffix);
    let mut lines = Vec::with_capacity(total_lines.min(MAX_VERSION_DIFF_LINES));
    for (kind, source) in [
        (FlowVersionDiffLineKind::Context, &previous[..prefix]),
        (
            FlowVersionDiffLineKind::Removed,
            &previous[prefix..previous_middle_end],
        ),
        (
            FlowVersionDiffLineKind::Added,
            &edited[prefix..edited_middle_end],
        ),
        (
            FlowVersionDiffLineKind::Context,
            &previous[previous_middle_end..],
        ),
    ] {
        for text in source {
            if lines.len() == MAX_VERSION_DIFF_LINES {
                return (lines, true);
            }
            lines.push(FlowVersionDiffLine {
                kind,
                text: (*text).to_owned(),
            });
        }
    }
    (lines, total_lines > MAX_VERSION_DIFF_LINES)
}

fn daemon_authority(definition: &FlowDefinition, step: &pam_flow::FlowStep) -> DaemonAuthority {
    let Some(command) = step.action().as_command() else {
        return DaemonAuthority::Unsupported(UnsupportedDaemonAuthority::Connector);
    };
    if command.working_directory != "." {
        return DaemonAuthority::Unsupported(UnsupportedDaemonAuthority::WorkingDirectory);
    }
    if command.program != "git" {
        return DaemonAuthority::Unsupported(UnsupportedDaemonAuthority::Program);
    }
    if step.effect() != EffectKind::ReadOnly {
        return DaemonAuthority::Unsupported(UnsupportedDaemonAuthority::StatefulEffect);
    }
    if step.approval() != ApprovalMode::None {
        return DaemonAuthority::Unsupported(UnsupportedDaemonAuthority::Approval);
    }
    if !safe_git_arguments(command.args) {
        return DaemonAuthority::Unsupported(UnsupportedDaemonAuthority::GitArguments);
    }
    let semantic_supported = match (
        command.args.first().map(String::as_str),
        step.semantic_role(),
    ) {
        (Some("diff"), StepSemanticRole::Verify)
        | (Some("status" | "rev-parse"), StepSemanticRole::Observe) => true,
        (Some("diff"), StepSemanticRole::Observe) if definition.schema_version() == 1 => true,
        _ => false,
    };
    if !semantic_supported {
        return DaemonAuthority::Unsupported(UnsupportedDaemonAuthority::SemanticRole);
    }
    DaemonAuthority::EligibleAfterRuntimeChecks
}

fn safe_git_arguments(arguments: &[String]) -> bool {
    match arguments.first().map(String::as_str) {
        Some("status") => arguments.iter().skip(1).all(|argument| {
            matches!(
                argument.as_str(),
                "--short" | "-s" | "--porcelain" | "--no-renames" | "--find-renames"
            ) || argument.starts_with("--porcelain=")
                || argument.starts_with("--untracked-files=")
                || argument.starts_with("--find-renames=")
        }),
        Some("rev-parse") if arguments.len() > 1 => arguments.iter().skip(1).all(|argument| {
            matches!(
                argument.as_str(),
                "HEAD"
                    | "--verify"
                    | "--quiet"
                    | "-q"
                    | "--short"
                    | "--show-toplevel"
                    | "--show-prefix"
                    | "--show-cdup"
                    | "--git-dir"
                    | "--absolute-git-dir"
                    | "--is-inside-work-tree"
            ) || argument.strip_prefix("--short=").is_some_and(|length| {
                !length.is_empty() && length.bytes().all(|byte| byte.is_ascii_digit())
            })
        }),
        Some("diff") => {
            arguments.iter().any(|argument| argument == "--quiet")
                && arguments
                    .iter()
                    .skip(1)
                    .all(|argument| argument == "--quiet")
        }
        _ => false,
    }
}

fn validate_draft(
    source: &str,
    baseline: Option<&SavedBaseline>,
) -> Result<FlowEditorValidation, FlowEditorError> {
    validate_source_size(source)?;
    let definition = FlowDefinition::parse_toml(source).map_err(invalid_parse)?;
    let normalized = definition
        .to_normalized_toml()
        .map_err(|error| invalid_validation(&error))?;
    validate_normalized_size(&normalized)?;
    let identity = FlowIdentity::from_definition(&definition)?;
    if let Some(baseline) = baseline {
        if identity.id != baseline.identity.id {
            return Err(FlowEditorError::IdentityChanged {
                expected: baseline.identity.id.clone(),
                actual: identity.id,
            });
        }
        if normalized != baseline.normalized && identity.revision <= baseline.identity.revision {
            return Err(FlowEditorError::RevisionNotAdvanced {
                previous: baseline.identity.revision,
                edited: identity.revision,
            });
        }
    }
    Ok(FlowEditorValidation {
        definition,
        normalized,
        identity,
    })
}

fn load_catalog<F, G>(
    project_directory: &Dir,
    before_open: &mut F,
    after_metadata: &mut G,
) -> Result<Vec<FlowCatalogEntry>, FlowEditorError>
where
    F: FnMut(&Dir, &str),
    G: FnMut(&Dir, &str),
{
    let Some(pam_directory) = open_optional_directory(project_directory, ".pam")? else {
        return Ok(Vec::new());
    };
    let Some(flow_directory) = open_optional_directory(&pam_directory, "flows")? else {
        return Ok(Vec::new());
    };
    let mut entries = Vec::new();
    let mut catalog_bytes = 0_usize;
    for (index, item) in flow_directory
        .entries()
        .map_err(FlowEditorError::ReadDirectory)?
        .enumerate()
    {
        if index >= MAX_FLOW_CATALOG_ENTRIES {
            return Err(FlowEditorError::TooManyEntries);
        }
        let item = item.map_err(FlowEditorError::ReadDirectory)?;
        let file_name = item
            .file_name()
            .into_string()
            .map_err(|_| FlowEditorError::NonUtf8Entry)?;
        let file_type = item.file_type().map_err(FlowEditorError::ReadEntry)?;
        if file_type.is_symlink() {
            return Err(FlowEditorError::UnsafeEntry(file_name));
        }
        if file_type.is_dir() {
            continue;
        }
        if !file_type.is_file() {
            return Err(FlowEditorError::UnsafeEntry(file_name));
        }
        if Path::new(&file_name)
            .extension()
            .and_then(|value| value.to_str())
            != Some("toml")
        {
            continue;
        }
        entries.push(load_catalog_entry(
            &flow_directory,
            file_name,
            &mut catalog_bytes,
            before_open,
            after_metadata,
        )?);
    }
    entries.sort_unstable_by(|left, right| left.identity.file_name.cmp(&right.identity.file_name));
    Ok(entries)
}

fn load_catalog_entry<F, G>(
    directory: &Dir,
    file_name: String,
    catalog_bytes: &mut usize,
    before_open: &mut F,
    after_metadata: &mut G,
) -> Result<FlowCatalogEntry, FlowEditorError>
where
    F: FnMut(&Dir, &str),
    G: FnMut(&Dir, &str),
{
    before_open(directory, &file_name);
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No).nonblock(true);
    let file = directory
        .open_with(&file_name, &options)
        .map_err(|_| FlowEditorError::UnsafeEntry(file_name.clone()))?;
    let metadata = file.metadata().map_err(FlowEditorError::ReadEntry)?;
    if !metadata.is_file() {
        return Err(FlowEditorError::UnsafeEntry(file_name));
    }
    let size = usize::try_from(metadata.len()).unwrap_or(usize::MAX);
    if size > MAX_FLOW_DOCUMENT_BYTES {
        return Err(FlowEditorError::FileTooLarge(file_name));
    }
    after_metadata(directory, &file_name);
    let mut bytes = Vec::with_capacity(size);
    file.take(u64::try_from(MAX_FLOW_DOCUMENT_BYTES + 1).unwrap())
        .read_to_end(&mut bytes)
        .map_err(FlowEditorError::ReadEntry)?;
    if bytes.len() > MAX_FLOW_DOCUMENT_BYTES {
        return Err(FlowEditorError::FileTooLarge(file_name));
    }
    let source = String::from_utf8(bytes)
        .map_err(|_| FlowEditorError::NonUtf8Definition(file_name.clone()))?;
    let definition = FlowDefinition::parse_toml(&source)
        .map_err(|error| invalid_catalog_definition(&file_name, error))?;
    let identity = FlowIdentity::from_definition(&definition)?;
    if file_name != identity.file_name {
        return Err(FlowEditorError::FileNameMismatch {
            file_name,
            expected_file_name: identity.file_name,
        });
    }
    let normalized = definition
        .to_normalized_toml()
        .map_err(|error| invalid_validation(&error))?;
    validate_normalized_size(&normalized)?;
    *catalog_bytes = catalog_bytes
        .checked_add(source.len())
        .and_then(|bytes| bytes.checked_add(normalized.len()))
        .ok_or(FlowEditorError::CatalogTooLarge)?;
    if *catalog_bytes > MAX_FLOW_CATALOG_BYTES {
        return Err(FlowEditorError::CatalogTooLarge);
    }
    Ok(FlowCatalogEntry {
        identity,
        source,
        normalized,
        definition,
    })
}

fn open_optional_directory(
    parent: &Dir,
    name: &'static str,
) -> Result<Option<Dir>, FlowEditorError> {
    match parent.open_dir_nofollow(name) {
        Ok(directory) => Ok(Some(directory)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(FlowEditorError::UnsafeDirectory(name)),
    }
}

fn open_or_create_directory(
    parent: &Dir,
    name: &'static str,
) -> Result<(Dir, bool), FlowEditorError> {
    match parent.open_dir_nofollow(name) {
        Ok(directory) => return Ok((directory, sync_directory(parent).unwrap_or(false))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err(FlowEditorError::UnsafeDirectory(name)),
    }
    match parent.create_dir(name) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(FlowEditorError::Write(error)),
    }
    let directory = parent
        .open_dir_nofollow(name)
        .map_err(|_| FlowEditorError::UnsafeDirectory(name))?;
    Ok((directory, sync_directory(parent).unwrap_or(false)))
}

fn atomic_save(
    project_directory: &Dir,
    identity: &FlowIdentity,
    baseline: Option<&SavedBaseline>,
    bytes: &[u8],
    after_final_check: impl FnOnce(),
) -> Result<SavePublication, FlowEditorError> {
    let (pam_directory, pam_link_durable) = open_or_create_directory(project_directory, ".pam")?;
    let lock = acquire_save_lock(&pam_directory)?;
    let (flow_directory, flow_link_durable) = open_or_create_directory(&pam_directory, "flows")?;
    let mut publication = atomic_save_locked(
        &flow_directory,
        identity,
        baseline,
        bytes,
        after_final_check,
    )?;
    drop(lock);
    publication.durability_confirmed &= pam_link_durable && flow_link_durable;
    Ok(publication)
}

fn acquire_save_lock(pam_directory: &Dir) -> Result<std::fs::File, FlowEditorError> {
    for _ in 0..SAVE_TEMP_ATTEMPTS {
        let mut create_options = OpenOptions::new();
        create_options
            .read(true)
            .write(true)
            .create_new(true)
            .follow(FollowSymlinks::No)
            .sync(true);
        match pam_directory.open_with(".flow-editor.lock", &create_options) {
            Ok(file) => {
                let mut lock = file.into_std();
                try_lock_save_file(&lock)?;
                let created_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |duration| duration.as_millis());
                write!(
                    lock,
                    "created_by_pid={}\ncreated_unix_ms={created_ms}\n",
                    std::process::id()
                )
                .map_err(FlowEditorError::Write)?;
                lock.sync_all().map_err(FlowEditorError::Write)?;
                let _ = sync_directory(pam_directory);
                return Ok(lock);
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(FlowEditorError::Write(error)),
        }

        let mut open_options = OpenOptions::new();
        open_options
            .read(true)
            .write(true)
            .follow(FollowSymlinks::No)
            .nonblock(true);
        match pam_directory.open_with(".flow-editor.lock", &open_options) {
            Ok(file) => {
                if !file.metadata().map_err(FlowEditorError::Write)?.is_file() {
                    return Err(FlowEditorError::Write(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "flow editor lock is not a regular file",
                    )));
                }
                let lock = file.into_std();
                try_lock_save_file(&lock)?;
                return Ok(lock);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(FlowEditorError::Write(error)),
        }
    }
    Err(FlowEditorError::SaveBusy)
}

fn try_lock_save_file(lock: &std::fs::File) -> Result<(), FlowEditorError> {
    lock.try_lock().map_err(|error| match error {
        std::fs::TryLockError::WouldBlock => FlowEditorError::SaveBusy,
        std::fs::TryLockError::Error(error) => FlowEditorError::Write(error),
    })
}

struct SavePublication {
    durability_confirmed: bool,
    cleanup_complete: bool,
}

fn atomic_save_locked(
    directory: &Dir,
    identity: &FlowIdentity,
    baseline: Option<&SavedBaseline>,
    bytes: &[u8],
    after_final_check: impl FnOnce(),
) -> Result<SavePublication, FlowEditorError> {
    verify_disk_baseline(directory, identity.file_name(), baseline)?;
    let backup_name = baseline
        .map(|_| create_backup_link(directory, identity.file_name()))
        .transpose()?;
    let (temporary_name, mut temporary) =
        match create_temporary_file(directory, identity.file_name()) {
            Ok(temporary) => temporary,
            Err(error) => {
                if let Some(backup_name) = backup_name.as_deref() {
                    let _ = directory.remove_file(backup_name);
                }
                return Err(error);
            }
        };
    let write_result = (|| -> Result<(), FlowEditorError> {
        temporary.write_all(bytes).map_err(FlowEditorError::Write)?;
        temporary.sync_all().map_err(FlowEditorError::Write)?;
        verify_disk_baseline(directory, identity.file_name(), baseline)?;
        if let (Some(baseline), Some(backup_name)) = (baseline, backup_name.as_deref())
            && read_direct_file(directory, backup_name)? != baseline.exact_source.as_bytes()
        {
            return Err(FlowEditorError::SaveConflict);
        }
        after_final_check();
        directory
            .rename(&temporary_name, directory, identity.file_name())
            .map_err(FlowEditorError::Write)?;
        Ok(())
    })();
    drop(temporary);
    if let Err(error) = write_result {
        let _ = directory.remove_file(&temporary_name);
        if let Some(backup_name) = backup_name.as_deref() {
            let _ = directory.remove_file(backup_name);
        }
        return Err(error);
    }
    let target_matches =
        read_direct_file(directory, identity.file_name()).is_ok_and(|actual| actual == bytes);
    let prior_unchanged = match (baseline, backup_name.as_deref()) {
        (Some(baseline), Some(name)) => read_direct_file(directory, name)
            .is_ok_and(|actual| actual == baseline.exact_source.as_bytes()),
        (None, None) => true,
        _ => false,
    };
    if !target_matches || !prior_unchanged {
        return Err(FlowEditorError::SavePublicationUncertain {
            recovery_file: backup_name,
        });
    }
    let durability_confirmed = sync_directory(directory).unwrap_or(false);
    let cleanup_complete = if durability_confirmed {
        backup_name.as_deref().is_none_or(|name| {
            directory.remove_file(name).is_ok() && sync_directory(directory).unwrap_or(false)
        })
    } else {
        backup_name.is_none()
    };
    Ok(SavePublication {
        durability_confirmed,
        cleanup_complete,
    })
}

fn create_backup_link(directory: &Dir, file_name: &str) -> Result<String, FlowEditorError> {
    for _ in 0..SAVE_TEMP_ATTEMPTS {
        let sequence = SAVE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let name = format!(".{file_name}.backup-{}-{sequence}", std::process::id());
        match directory.hard_link(file_name, directory, &name) {
            Ok(()) => {
                if let Err(error) = sync_directory(directory) {
                    let _ = directory.remove_file(&name);
                    return Err(FlowEditorError::Write(error));
                }
                return Ok(name);
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(FlowEditorError::Write(error)),
        }
    }
    Err(FlowEditorError::SaveBusy)
}

fn verify_disk_baseline(
    directory: &Dir,
    file_name: &str,
    baseline: Option<&SavedBaseline>,
) -> Result<(), FlowEditorError> {
    match baseline {
        None => match directory.symlink_metadata(file_name) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Ok(_) => Err(FlowEditorError::SaveConflict),
            Err(error) => Err(FlowEditorError::ReadEntry(error)),
        },
        Some(baseline) => {
            let actual = read_direct_file(directory, file_name)?;
            if actual == baseline.exact_source.as_bytes() {
                Ok(())
            } else {
                Err(FlowEditorError::SaveConflict)
            }
        }
    }
}

fn read_direct_file(directory: &Dir, file_name: &str) -> Result<Vec<u8>, FlowEditorError> {
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No).nonblock(true);
    let file = directory
        .open_with(file_name, &options)
        .map_err(|_| FlowEditorError::SaveConflict)?;
    let metadata = file.metadata().map_err(FlowEditorError::ReadEntry)?;
    if !metadata.is_file() || metadata.len() > u64::try_from(MAX_FLOW_DOCUMENT_BYTES).unwrap() {
        return Err(FlowEditorError::SaveConflict);
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    file.take(u64::try_from(MAX_FLOW_DOCUMENT_BYTES + 1).unwrap())
        .read_to_end(&mut bytes)
        .map_err(FlowEditorError::ReadEntry)?;
    if bytes.len() > MAX_FLOW_DOCUMENT_BYTES {
        return Err(FlowEditorError::SaveConflict);
    }
    Ok(bytes)
}

fn create_temporary_file(
    directory: &Dir,
    file_name: &str,
) -> Result<(String, cap_std::fs::File), FlowEditorError> {
    for _ in 0..SAVE_TEMP_ATTEMPTS {
        let sequence = SAVE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let name = format!(".{file_name}.tmp-{}-{sequence}", std::process::id());
        let mut options = OpenOptions::new();
        options
            .write(true)
            .create_new(true)
            .follow(FollowSymlinks::No)
            .sync(true);
        match directory.open_with(&name, &options) {
            Ok(file) => return Ok((name, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(FlowEditorError::Write(error)),
        }
    }
    Err(FlowEditorError::SaveBusy)
}

#[cfg(unix)]
fn sync_directory(directory: &Dir) -> io::Result<bool> {
    let handle = directory.open(".")?;
    if !handle.metadata()?.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "directory sync handle is not a directory",
        ));
    }
    handle.sync_all()?;
    Ok(true)
}

#[cfg(not(unix))]
fn sync_directory(_directory: &Dir) -> io::Result<bool> {
    // Rust's portable filesystem API cannot confirm directory-entry
    // durability on these targets. File contents are still synchronized, and
    // callers retain recovery backups while reporting durability unconfirmed.
    Ok(false)
}

#[cfg(test)]
pub(crate) fn sync_directory_path_for_test(path: &Path) -> io::Result<bool> {
    let directory = Dir::open_ambient_dir(path, ambient_authority())?;
    sync_directory(&directory)
}

fn validate_selector(selector: &str) -> Result<(), FlowEditorError> {
    if selector.is_empty()
        || selector.len() > MAX_SELECTOR_BYTES
        || selector == "."
        || selector == ".."
        || selector.contains(['/', '\\'])
        || selector.chars().any(char::is_control)
    {
        return Err(FlowEditorError::InvalidSelector);
    }
    Ok(())
}

fn validate_source_size(source: &str) -> Result<(), FlowEditorError> {
    if source.len() > MAX_FLOW_DOCUMENT_BYTES {
        Err(FlowEditorError::DocumentTooLarge {
            actual: source.len(),
            maximum: MAX_FLOW_DOCUMENT_BYTES,
        })
    } else {
        Ok(())
    }
}

fn validate_normalized_size(normalized: &str) -> Result<(), FlowEditorError> {
    if normalized.len() > MAX_FLOW_DOCUMENT_BYTES {
        Err(FlowEditorError::NormalizedDocumentTooLarge {
            actual: normalized.len(),
            maximum: MAX_FLOW_DOCUMENT_BYTES,
        })
    } else {
        Ok(())
    }
}

fn invalid_parse(error: FlowParseError) -> FlowEditorError {
    match error {
        FlowParseError::DocumentTooLarge { actual, maximum } => {
            FlowEditorError::DocumentTooLarge { actual, maximum }
        }
        FlowParseError::Toml(error) => {
            FlowEditorError::InvalidToml(bounded_message(&error.to_string()))
        }
        FlowParseError::Validation(error) => invalid_validation(&error),
    }
}

fn invalid_catalog_definition(file_name: &str, error: FlowParseError) -> FlowEditorError {
    let reason = match error {
        FlowParseError::DocumentTooLarge { .. } => "document exceeds the byte limit".to_owned(),
        FlowParseError::Toml(_) => "TOML syntax is invalid (source omitted)".to_owned(),
        FlowParseError::Validation(error) => {
            let path = error.path();
            if path.len() <= 128
                && path.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'[' | b']' | b'_')
                })
            {
                format!("schema validation failed at {path} (value omitted)")
            } else {
                "schema validation failed (value omitted)".to_owned()
            }
        }
    };
    FlowEditorError::InvalidCatalogDefinition {
        file_name: file_name.to_owned(),
        reason,
    }
}

fn invalid_validation(error: &pam_flow::FlowValidationError) -> FlowEditorError {
    FlowEditorError::InvalidDefinition {
        path: bounded_message(error.path()),
        message: bounded_message(error.message()),
    }
}

fn bounded_message(value: &str) -> String {
    if value.len() <= MAX_VALIDATION_MESSAGE_BYTES {
        return value.to_owned();
    }
    let mut end = MAX_VALIDATION_MESSAGE_BYTES;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &value[..end])
}

/// Bounded editor/catalog/save failure.
#[derive(Debug)]
pub enum FlowEditorError {
    ProjectRoot(io::Error),
    ReadDirectory(io::Error),
    ReadEntry(io::Error),
    Write(io::Error),
    UnsafeDirectory(&'static str),
    UnsafeEntry(String),
    NonUtf8Entry,
    NonUtf8Definition(String),
    TooManyEntries,
    CatalogTooLarge,
    FileTooLarge(String),
    FileNameMismatch {
        file_name: String,
        expected_file_name: String,
    },
    InvalidSelector,
    NotFound(String),
    DocumentTooLarge {
        actual: usize,
        maximum: usize,
    },
    NormalizedDocumentTooLarge {
        actual: usize,
        maximum: usize,
    },
    InvalidToml(String),
    InvalidDefinition {
        path: String,
        message: String,
    },
    InvalidCatalogDefinition {
        file_name: String,
        reason: String,
    },
    IdentityChanged {
        expected: String,
        actual: String,
    },
    RevisionNotAdvanced {
        previous: u64,
        edited: u64,
    },
    StaleSaveInteraction,
    SaveConflict,
    SavePublicationUncertain {
        recovery_file: Option<String>,
    },
    SaveBusy,
}

impl fmt::Display for FlowEditorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProjectRoot(_) => formatter.write_str("PAM could not resolve the project root."),
            Self::ReadDirectory(_) | Self::ReadEntry(_) => {
                formatter.write_str("PAM could not read the project flow catalog.")
            }
            Self::Write(_) => formatter.write_str("PAM could not safely save the flow definition."),
            Self::UnsafeDirectory(name) => write!(
                formatter,
                "Flow catalog directory {name} must be a real directory, not a symlink."
            ),
            Self::UnsafeEntry(name) => write!(
                formatter,
                "Flow catalog entry {name} is not a safe regular file."
            ),
            Self::NonUtf8Entry => formatter.write_str("Flow catalog contains a non-UTF-8 name."),
            Self::NonUtf8Definition(name) => {
                write!(formatter, "Flow definition {name} is not UTF-8.")
            }
            Self::TooManyEntries => write!(
                formatter,
                "Flow catalog exceeds the {MAX_FLOW_CATALOG_ENTRIES}-entry limit."
            ),
            Self::CatalogTooLarge => formatter.write_str("Flow catalog exceeds its byte limit."),
            Self::FileTooLarge(name) => write!(
                formatter,
                "Flow definition {name} exceeds the {MAX_FLOW_DOCUMENT_BYTES}-byte limit."
            ),
            Self::FileNameMismatch {
                file_name,
                expected_file_name,
            } => write!(
                formatter,
                "Flow definition {file_name} must be named {expected_file_name}."
            ),
            Self::InvalidSelector => formatter.write_str(
                "Flow selector must be an exact ID or <id>.toml name with no path traversal.",
            ),
            Self::NotFound(selector) => write!(formatter, "Flow {selector} was not found."),
            Self::DocumentTooLarge { actual, maximum } => write!(
                formatter,
                "Flow document is {actual} bytes; maximum is {maximum} bytes."
            ),
            Self::NormalizedDocumentTooLarge { actual, maximum } => write!(
                formatter,
                "Normalized flow document is {actual} bytes; maximum is {maximum} bytes."
            ),
            Self::InvalidToml(message) => write!(formatter, "Flow TOML is invalid: {message}"),
            Self::InvalidDefinition { path, message } => {
                write!(formatter, "Flow definition is invalid at {path}: {message}")
            }
            Self::InvalidCatalogDefinition { file_name, reason } => {
                write!(
                    formatter,
                    "Flow definition {file_name} is invalid: {reason}"
                )
            }
            Self::IdentityChanged { expected, actual } => write!(
                formatter,
                "Existing flow identity cannot change from {expected} to {actual}."
            ),
            Self::RevisionNotAdvanced { previous, edited } => write!(
                formatter,
                "Changed flow revision {edited} must be greater than saved revision {previous}."
            ),
            Self::StaleSaveInteraction => formatter.write_str(
                "The editor changed after this save interaction was prepared; review it again.",
            ),
            Self::SaveConflict => formatter.write_str(
                "The flow changed on disk or its target is unsafe; reload before saving.",
            ),
            Self::SavePublicationUncertain { recovery_file } => {
                formatter.write_str(
                    "The flow publication could not be verified; reload before saving again.",
                )?;
                if let Some(recovery_file) = recovery_file {
                    write!(formatter, " Prior bytes remain in {recovery_file}.")?;
                }
                Ok(())
            }
            Self::SaveBusy => formatter.write_str("Another flow save is already in progress."),
        }
    }
}

impl Error for FlowEditorError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ProjectRoot(error)
            | Self::ReadDirectory(error)
            | Self::ReadEntry(error)
            | Self::Write(error) => Some(error),
            _ => None,
        }
    }
}
