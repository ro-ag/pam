use std::{
    ffi::OsString,
    fmt,
    future::Future,
    path::{Path, PathBuf},
    pin::Pin,
    process::Stdio,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use pam_core::{ContentDigest, EvidenceHandle, ProjectId};
use pam_protocol::{BriefItem, BriefProvenance, BriefResult, OperationTruth, SourceAvailability};
use pam_store::{EvidenceRedaction, EvidenceRetention, PutEvidence, Store};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use tokio::{
    io::{AsyncRead, AsyncReadExt as _},
    process::Command,
    task::JoinHandle,
    time::timeout,
};

use crate::BriefProvider;

const COMMAND_TIMEOUT: Duration = Duration::from_secs(1);
const OUTPUT_DRAIN_TIMEOUT: Duration = Duration::from_millis(250);
const MAX_STDOUT_BYTES: usize = 256 * 1024;
const MAX_STDERR_BYTES: usize = 4 * 1024;
const MAX_SECTION_ITEMS: usize = 16;
const MAX_ITEM_BYTES: usize = 4 * 1024;
const MAX_DETAIL_BYTES: usize = 4 * 1024;
const MAX_REGISTERED_PROJECTS: usize = 256;
const MAX_PROJECT_NAME_BYTES: usize = 256;
const MAX_PROJECT_PATH_BYTES: usize = 4 * 1024;
const TRUNCATION_SUFFIX: &str = "... [truncated]";

pub(crate) struct PtrackBriefProvider {
    directory: PathBuf,
    project_id: ProjectId,
    executable: OsString,
}

impl PtrackBriefProvider {
    pub(crate) fn new(directory: PathBuf, project_id: ProjectId) -> Self {
        Self {
            directory,
            project_id,
            executable: OsString::from("ptrack"),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_executable(
        directory: PathBuf,
        project_id: ProjectId,
        executable: OsString,
    ) -> Self {
        Self {
            directory,
            project_id,
            executable,
        }
    }
}

impl fmt::Debug for PtrackBriefProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PtrackBriefProvider")
            .field("directory", &self.directory)
            .field("project_id", &self.project_id)
            .finish_non_exhaustive()
    }
}

impl BriefProvider for PtrackBriefProvider {
    fn brief<'a>(
        &'a self,
        project_id: &'a ProjectId,
        store: &'a Store,
    ) -> Pin<Box<dyn Future<Output = BriefResult> + Send + 'a>> {
        Box::pin(async move {
            if project_id != &self.project_id {
                return unavailable(
                    "The configured ptrack source belongs to another project.".to_owned(),
                );
            }

            let projects = match run_command(
                &self.executable,
                &self.directory,
                &["projects", "--json"],
                "ptrack projects --json",
            )
            .await
            {
                Ok(bytes) => bytes,
                Err(detail) => return unavailable(detail),
            };
            if let Err(detail) = validate_registered_project(&projects, &self.directory) {
                return unavailable(detail);
            }

            let bytes = match run_command(
                &self.executable,
                &self.directory,
                &["context", "--json"],
                "ptrack context --json",
            )
            .await
            {
                Ok(bytes) => bytes,
                Err(detail) => return unavailable(detail),
            };
            let context = match serde_json::from_slice::<ContextDigest>(&bytes) {
                Ok(context) => context,
                Err(error) => {
                    return unavailable(bounded_detail(format!(
                        "ptrack returned incompatible context JSON: {error}"
                    )));
                }
            };
            let handle = context_handle(&bytes);
            let evidence = PutEvidence {
                handle: handle.clone(),
                project_id: project_id.clone(),
                media_type: "application/json".to_owned(),
                retention: EvidenceRetention::Project,
                redaction: EvidenceRedaction::Unredacted,
                bytes,
            };
            if let Err(error) = store.put_evidence(evidence, now_ms()).await {
                return unavailable(bounded_detail(format!(
                    "ptrack context was read, but PAM could not retain its exact evidence: {error}"
                )));
            }

            context.into_brief(handle)
        })
    }
}

#[derive(Deserialize)]
pub(super) struct ContextDigest {
    goal: String,
    summary: String,
    active_plan: Option<Plan>,
    #[serde(default)]
    blocked: Option<Vec<Task>>,
    #[serde(default)]
    blocked_more: usize,
    #[serde(default)]
    on_hold: Option<Vec<Task>>,
    #[serde(default)]
    on_hold_more: usize,
    #[serde(default)]
    open_issues: Option<Vec<Issue>>,
    #[serde(default)]
    open_issues_more: usize,
    #[serde(default)]
    recent_notes: Option<Vec<Note>>,
}

#[derive(Deserialize)]
struct Plan {
    id: u64,
    title: String,
    #[serde(default)]
    open_tasks: Option<Vec<Task>>,
    #[serde(default)]
    hold_reason: Option<String>,
}

#[derive(Deserialize)]
struct Task {
    id: u64,
    title: String,
    status: String,
    #[serde(default)]
    hold_reason: Option<String>,
}

#[derive(Deserialize)]
struct Issue {
    id: u64,
    title: String,
    severity: String,
}

#[derive(Deserialize)]
struct Note {
    target: String,
    target_id: u64,
    body: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct RegisteredProject {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Path")]
    path: PathBuf,
    #[serde(rename = "LastSeen")]
    last_seen: String,
}

impl RegisteredProject {
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub fn last_seen(&self) -> &str {
        &self.last_seen
    }
}

impl ContextDigest {
    pub(super) fn into_brief(self, handle: EvidenceHandle) -> BriefResult {
        let mut partial = false;
        let goal = item_if_present(&self.goal, OperationTruth::Observed, &handle, &mut partial);
        let mut decisions = Vec::new();
        for note in self.recent_notes.unwrap_or_default() {
            push_item(
                &mut decisions,
                format!("{} #{}: {}", note.target, note.target_id, note.body),
                OperationTruth::Observed,
                &handle,
                &mut partial,
            );
        }

        let mut verified = Vec::new();
        if !self.summary.trim().is_empty() {
            push_item(
                &mut verified,
                self.summary,
                OperationTruth::Observed,
                &handle,
                &mut partial,
            );
        }

        let mut next = Vec::new();
        let plan_detail = self.active_plan.as_ref().map(|plan| {
            let held = plan
                .hold_reason
                .as_deref()
                .map_or(String::new(), |reason| format!("; hold={reason}"));
            format!("active plan #{} {}{held}", plan.id, plan.title)
        });
        if let Some(plan) = self.active_plan {
            for task in plan.open_tasks.unwrap_or_default() {
                push_task(&mut next, task, &handle, &mut partial);
            }
        }
        for task in self.blocked.unwrap_or_default() {
            if !next
                .iter()
                .any(|item| item.text.starts_with(&format!("#{} ", task.id)))
            {
                push_task(&mut next, task, &handle, &mut partial);
            }
        }
        for task in self.on_hold.unwrap_or_default() {
            if !next
                .iter()
                .any(|item| item.text.starts_with(&format!("#{} ", task.id)))
            {
                push_task(&mut next, task, &handle, &mut partial);
            }
        }
        for issue in self.open_issues.unwrap_or_default() {
            push_item(
                &mut next,
                format!(
                    "issue #{} [severity={}] {}",
                    issue.id, issue.severity, issue.title
                ),
                OperationTruth::Unresolved,
                &handle,
                &mut partial,
            );
        }
        partial |= self.blocked_more > 0 || self.on_hold_more > 0 || self.open_issues_more > 0;

        let mut detail = "ptrack context --json via the supported CLI".to_owned();
        if let Some(plan_detail) = plan_detail {
            detail.push_str("; ");
            detail.push_str(&plan_detail);
        }
        if partial {
            detail.push_str("; bounded fields were truncated or omitted");
        }

        BriefResult {
            goal,
            decisions,
            verified,
            next,
            provenance: vec![BriefProvenance {
                source: "ptrack".to_owned(),
                availability: if partial {
                    SourceAvailability::Partial
                } else {
                    SourceAvailability::Available
                },
                truth: OperationTruth::Observed,
                evidence: Some(handle),
                detail: Some(bounded_detail(detail)),
            }],
        }
    }
}

fn item_if_present(
    text: &str,
    truth: OperationTruth,
    handle: &EvidenceHandle,
    partial: &mut bool,
) -> Option<BriefItem> {
    if text.trim().is_empty() {
        None
    } else {
        let (text, truncated) = bounded_text(text.to_owned(), MAX_ITEM_BYTES);
        *partial |= truncated;
        Some(BriefItem {
            text,
            truth,
            evidence: vec![handle.clone()],
        })
    }
}

fn push_task(items: &mut Vec<BriefItem>, task: Task, handle: &EvidenceHandle, partial: &mut bool) {
    let truth = if task.status == "blocked" || task.hold_reason.is_some() {
        OperationTruth::Blocked
    } else {
        OperationTruth::Unresolved
    };
    let hold = task
        .hold_reason
        .map_or(String::new(), |reason| format!(" hold={reason}"));
    push_item(
        items,
        format!("#{} [{}] {}{hold}", task.id, task.status, task.title),
        truth,
        handle,
        partial,
    );
}

fn push_item(
    items: &mut Vec<BriefItem>,
    text: String,
    truth: OperationTruth,
    handle: &EvidenceHandle,
    partial: &mut bool,
) {
    if items.len() >= MAX_SECTION_ITEMS {
        *partial = true;
        return;
    }
    let (text, truncated) = bounded_text(text, MAX_ITEM_BYTES);
    *partial |= truncated;
    items.push(BriefItem {
        text,
        truth,
        evidence: vec![handle.clone()],
    });
}

fn bounded_text(mut text: String, maximum: usize) -> (String, bool) {
    if text.len() <= maximum {
        return (text, false);
    }
    let content_limit = maximum.saturating_sub(TRUNCATION_SUFFIX.len());
    let mut boundary = content_limit.min(text.len());
    while !text.is_char_boundary(boundary) {
        boundary -= 1;
    }
    text.truncate(boundary);
    text.push_str(TRUNCATION_SUFFIX);
    (text, true)
}

fn bounded_detail(detail: String) -> String {
    bounded_text(detail, MAX_DETAIL_BYTES).0
}

fn unavailable(detail: String) -> BriefResult {
    BriefResult {
        goal: None,
        decisions: Vec::new(),
        verified: Vec::new(),
        next: Vec::new(),
        provenance: vec![BriefProvenance {
            source: "ptrack".to_owned(),
            availability: SourceAvailability::Unavailable,
            truth: OperationTruth::Unresolved,
            evidence: None,
            detail: Some(bounded_detail(detail)),
        }],
    }
}

pub(super) fn context_handle(bytes: &[u8]) -> EvidenceHandle {
    let digest = ContentDigest::from_sha256(Sha256::digest(bytes).into());
    EvidenceHandle::parse(format!("evidence://ptrack/context/{}", digest.sha256_hex()))
        .expect("a lowercase SHA-256 digest is a canonical evidence segment")
}

pub(super) fn validate_registered_project(bytes: &[u8], directory: &Path) -> Result<(), String> {
    let projects = parse_registered_projects(bytes)?;
    let registered = projects
        .into_iter()
        .any(|project| project.path == directory);
    if registered {
        Ok(())
    } else {
        Err("ptrack does not report this PAM project root through its supported projects interface."
            .to_owned())
    }
}

/// Returns the bounded ptrack project catalog used by the native control center.
///
/// # Errors
///
/// Returns a sanitized error when ptrack is unavailable, exceeds its deadline,
/// or returns an incompatible or unbounded project catalog.
pub async fn registered_projects(directory: &Path) -> Result<Vec<RegisteredProject>, String> {
    let bytes = run_command(
        &OsString::from("ptrack"),
        directory,
        &["projects", "--json"],
        "ptrack projects --json",
    )
    .await?;
    parse_registered_projects(&bytes)
}

fn parse_registered_projects(bytes: &[u8]) -> Result<Vec<RegisteredProject>, String> {
    let projects = serde_json::from_slice::<Vec<RegisteredProject>>(bytes).map_err(|error| {
        bounded_detail(format!(
            "ptrack returned incompatible projects JSON: {error}"
        ))
    })?;
    if projects.len() > MAX_REGISTERED_PROJECTS {
        return Err("ptrack returned too many registered projects.".to_owned());
    }
    for project in &projects {
        if project.name.trim().is_empty()
            || project.name.len() > MAX_PROJECT_NAME_BYTES
            || !project.path.is_absolute()
            || project.path.as_os_str().as_encoded_bytes().len() > MAX_PROJECT_PATH_BYTES
            || project.last_seen.len() > MAX_PROJECT_NAME_BYTES
        {
            return Err("ptrack returned an invalid registered project entry.".to_owned());
        }
    }
    Ok(projects)
}

async fn run_command(
    executable: &OsString,
    directory: &Path,
    arguments: &[&str],
    operation: &str,
) -> Result<Vec<u8>, String> {
    let mut child = Command::new(executable)
        .args(arguments)
        .current_dir(directory)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| "The ptrack executable is unavailable.".to_owned())?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "PAM could not capture ptrack output.".to_owned())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "PAM could not capture ptrack diagnostics.".to_owned())?;
    let mut stdout_task = tokio::spawn(read_bounded(stdout, MAX_STDOUT_BYTES));
    let mut stderr_task = tokio::spawn(read_bounded(stderr, MAX_STDERR_BYTES));

    let status = match timeout(COMMAND_TIMEOUT, child.wait()).await {
        Ok(Ok(status)) => status,
        Ok(Err(_)) => {
            abort_readers(&mut stdout_task, &mut stderr_task).await;
            return Err("PAM could not wait for ptrack context.".to_owned());
        }
        Err(_) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            abort_readers(&mut stdout_task, &mut stderr_task).await;
            return Err(format!("{operation} exceeded the one-second deadline."));
        }
    };
    let stdout = join_reader(&mut stdout_task, "output").await?;
    let stderr = join_reader(&mut stderr_task, "diagnostics").await?;
    if stdout.exceeded {
        return Err(format!(
            "{operation} exceeded the {MAX_STDOUT_BYTES}-byte output limit."
        ));
    }
    if !status.success() {
        let diagnostic = String::from_utf8_lossy(&stderr.bytes);
        let diagnostic = diagnostic.trim();
        let suffix = if diagnostic.is_empty() {
            String::new()
        } else {
            format!(" Details: {diagnostic}")
        };
        return Err(bounded_detail(format!(
            "{operation} exited with status {status}.{suffix}"
        )));
    }
    Ok(stdout.bytes)
}

pub(super) struct BoundedOutput {
    pub(super) bytes: Vec<u8>,
    pub(super) exceeded: bool,
}

pub(super) async fn read_bounded(
    mut reader: impl AsyncRead + Unpin,
    maximum: usize,
) -> std::io::Result<BoundedOutput> {
    let mut bytes = Vec::new();
    let mut exceeded = false;
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        let remaining = maximum.saturating_sub(bytes.len());
        let retained = remaining.min(read);
        bytes.extend_from_slice(&buffer[..retained]);
        exceeded |= retained < read;
    }
    Ok(BoundedOutput { bytes, exceeded })
}

async fn join_reader(
    task: &mut JoinHandle<std::io::Result<BoundedOutput>>,
    label: &str,
) -> Result<BoundedOutput, String> {
    match timeout(OUTPUT_DRAIN_TIMEOUT, &mut *task).await {
        Ok(Ok(Ok(output))) => Ok(output),
        Ok(Ok(Err(_)) | Err(_)) => Err(format!("PAM could not read ptrack {label}.")),
        Err(_) => {
            task.abort();
            Err(format!("ptrack {label} did not close after exit."))
        }
    }
}

async fn abort_readers(
    stdout: &mut JoinHandle<std::io::Result<BoundedOutput>>,
    stderr: &mut JoinHandle<std::io::Result<BoundedOutput>>,
) {
    stdout.abort();
    stderr.abort();
    let _ = stdout.await;
    let _ = stderr.await;
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}
