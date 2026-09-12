//! Fixed trusted Git HTTPS broker operations, never generic command privileges.
//! The caller prepares a durable effect receipt and rechecks GUI permissions
//! before push. No mutation retries; remote observation is a separate operation.
//! Raw Git diagnostics are discarded because a server can echo credentials.
use crate::{
    landing_checkout::{self, CheckoutError, CheckoutReceipt, CheckoutRequest, Workspace},
    landing_pack::PackBounds,
    request_budget::RequestBudget,
};
use pam_connectors::Secret;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::watch,
};

const PIPE_LIMIT: usize = 32 * 1024;
const MAX_OUTBOUND_OBJECTS: usize = 16_384;
const METADATA_LIMIT: usize = 1024 * 1024;
const MAX_OUTBOUND_BYTES: u64 = 64 * 1024 * 1024;

pub(crate) type GitError = CheckoutError;
pub(crate) trait GitAuthorization: Send + Sync {
    fn authorize(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), GitError>> + Send + '_>>;
}
#[derive(Clone)]
pub(crate) struct GitTransport {
    /// Canonical trusted installation's git-core directory, never a repo path.
    pub git_exec_path: PathBuf,
}
#[derive(Clone)]
pub(crate) struct GitTarget {
    pub request: CheckoutRequest,
    pub receipt: CheckoutReceipt,
    pub branch: String,
    pub expected_old: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RemoteRef {
    pub ref_name: String,
    pub oid: Option<String>,
}
/// One guarded local synchronization that provably happened: the base ref
/// moved from `expected_old` to `requested_commit` through a pack whose
/// bounds were measured before Git indexed it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SyncObservation {
    pub ref_name: String,
    pub expected_old: String,
    pub requested_commit: String,
    /// The installed pack's name (`pack-<hash>`), as Git reported it.
    pub pack: String,
    pub bounds: PackBounds,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PushState {
    ReportedSuccess,
    Uncertain,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PushObservation {
    pub ref_name: String,
    pub expected_old: Option<String>,
    pub requested_commit: String,
    /// Even reported success requires a fresh exact remote-ref observation.
    pub state: PushState,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Reconciliation {
    Matched,
    Unchanged,
    Conflicting,
}

fn error(cause: &'static str, detail: &'static str) -> CheckoutError {
    CheckoutError { cause, detail }
}
fn invalid(detail: &'static str) -> CheckoutError {
    error("landing_git_invalid", detail)
}
fn oid(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && value.bytes().any(|b| b != b'0')
}
#[allow(clippy::case_sensitive_file_extension_comparisons)] // Literal Git ref grammar.
fn reference(branch: &str) -> Result<String, CheckoutError> {
    if branch.is_empty()
        || branch.len() > 240
        || branch.chars().any(char::is_control)
        || branch.contains(['\\', ' ', '~', '^', ':', '?', '*', '['])
        || branch.contains("..")
        || branch.contains("@{")
        || branch
            .split('/')
            .any(|p| p.is_empty() || p.starts_with('.') || p.ends_with('.') || p.ends_with(".lock"))
    {
        return Err(invalid("remote branch is not an exact literal ref"));
    }
    Ok(format!("refs/heads/{branch}"))
}
fn validate_target(
    request: &CheckoutRequest,
    receipt: &CheckoutReceipt,
) -> Result<(), CheckoutError> {
    if pam_flow::canonical_repository_url(&request.remote_url)
        .ok()
        .as_deref()
        != Some(request.remote_url.as_str())
        || receipt.remote_url != request.remote_url
        || receipt.repository != request.repository
        || receipt.commit != request.expected_commit
        || !oid(&receipt.commit)
    {
        return Err(invalid(
            "remote or source differs from the approved receipt",
        ));
    }
    Ok(())
}
fn trusted_path(
    path: &Path,
    request: &CheckoutRequest,
    directory: bool,
) -> Result<(), CheckoutError> {
    let canonical = path
        .canonicalize()
        .map_err(|_| invalid("trusted Git installation is unavailable"))?;
    if canonical != path
        || canonical.starts_with(&request.repository)
        || canonical.starts_with(&request.checkouts_root)
        || canonical.starts_with(&request.protected_base)
    {
        return Err(invalid(
            "Git executable or helper directory is not a trusted canonical path",
        ));
    }
    let meta =
        fs::metadata(path).map_err(|_| invalid("trusted Git installation is unavailable"))?;
    if meta.is_dir() != directory || (!directory && !meta.is_file()) {
        return Err(invalid("Git installation has the wrong file type"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o022 != 0
            || (!directory && meta.permissions().mode() & 0o111 == 0)
        {
            return Err(invalid(
                "Git installation is writable by other users or nonexecutable",
            ));
        }
    }
    Ok(())
}
fn validate_installation(
    config: &GitTransport,
    request: &CheckoutRequest,
) -> Result<(), CheckoutError> {
    trusted_path(&request.git_program, request, false)?;
    trusted_path(&config.git_exec_path, request, true)?;
    // The only allowed protocol helper is from this exact trusted installation.
    let helper = config.git_exec_path.join("git-remote-https");
    let helper = helper
        .canonicalize()
        .map_err(|_| invalid("trusted HTTPS Git helper unavailable"))?;
    if !helper.starts_with(&config.git_exec_path) {
        return Err(invalid("HTTPS Git helper escapes its trusted installation"));
    }
    trusted_path(&helper, request, false)
}
/// The `Basic` credential GitHub accepts for Git over HTTPS with a token.
pub(crate) fn basic_token(token: &str) -> String {
    base64(format!("x-access-token:{token}").as_bytes())
}
fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        output.push(char::from(TABLE[usize::from(first >> 2)]));
        output.push(char::from(
            TABLE[usize::from(((first & 3) << 4) | (second >> 4))],
        ));
        output.push(if chunk.len() > 1 {
            char::from(TABLE[usize::from(((second & 15) << 2) | (third >> 6))])
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            char::from(TABLE[usize::from(third & 63)])
        } else {
            '='
        });
    }
    output
}
struct Session<'a> {
    config: &'a GitTransport,
    request: &'a CheckoutRequest,
    workspace: Workspace,
    credential: Secret,
    budget: Arc<RequestBudget>,
    deadline: Instant,
    started: Arc<AtomicBool>,
    authorization: Arc<dyn GitAuthorization>,
}
impl Session<'_> {
    fn command(&self, network: bool) -> Result<tokio::process::Command, CheckoutError> {
        let mut command = tokio::process::Command::new(&self.request.git_program);
        command
            .env_clear()
            .current_dir(&self.workspace.root)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        command
            .env("PATH", "/usr/bin:/bin")
            .env("GIT_EXEC_PATH", &self.config.git_exec_path)
            .env("GIT_DIR", self.workspace.root.join("metadata"))
            .env("HOME", &self.workspace.root)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_NO_REPLACE_OBJECTS", "1")
            .env("GIT_NO_LAZY_FETCH", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_ATTR_NOSYSTEM", "1")
            .env("LC_ALL", "C");
        let mut values = vec![
            ("core.hooksPath", "/dev/null".to_owned()),
            ("credential.helper", String::new()),
            ("credential.interactive", "false".into()),
            ("core.fsmonitor", "false".into()),
            ("protocol.allow", "never".into()),
            (
                "protocol.https.allow",
                if network { "always" } else { "never" }.into(),
            ),
            ("http.followRedirects", "false".into()),
            ("http.sslVerify", "true".into()),
            ("http.proxy", String::new()),
            ("http.extraHeader", String::new()),
            ("submodule.recurse", "false".into()),
            ("gc.auto", "0".into()),
            ("maintenance.auto", "false".into()),
            ("pack.window", "0".into()),
            ("pack.threads", "1".into()),
            ("pack.deltaCacheSize", "1m".into()),
            ("pack.windowMemory", "16m".into()),
            ("core.bigFileThreshold", "4m".into()),
            ("http.maxRequests", "1".into()),
        ];
        if network {
            if self.credential.expose().is_empty()
                || self.credential.expose().len() > 16 * 1024
                || self.credential.expose().chars().any(char::is_control)
            {
                return Err(invalid("GitHub credential is unavailable or invalid"));
            }
            values.push((
                "http.extraHeader",
                format!(
                    "Authorization: Basic {}",
                    base64(format!("x-access-token:{}", self.credential.expose()).as_bytes())
                ),
            ));
        }
        command.env("GIT_CONFIG_COUNT", values.len().to_string());
        for (index, (name, value)) in values.into_iter().enumerate() {
            command
                .env(format!("GIT_CONFIG_KEY_{index}"), name)
                .env(format!("GIT_CONFIG_VALUE_{index}"), value);
        }
        if network {
            return Ok(command);
        }
        command.env("GIT_WORK_TREE", &self.request.repository);
        self.contain_local(&command)
    }
    fn contain_local(
        &self,
        command: &tokio::process::Command,
    ) -> Result<tokio::process::Command, CheckoutError> {
        let env = command
            .as_std()
            .get_envs()
            .map(|(name, value)| {
                Ok((
                    name.to_str()
                        .ok_or_else(|| invalid("Git environment name is invalid"))?
                        .to_owned(),
                    value
                        .and_then(|v| v.to_str())
                        .ok_or_else(|| invalid("Git environment value is invalid"))?
                        .to_owned(),
                ))
            })
            .collect::<Result<Vec<_>, CheckoutError>>()?;
        let containment = crate::command_containment::CommandContainment {
            protected_base: self.request.protected_base.clone(),
            repository: self.workspace.root.clone(),
            read_only_roots: vec![
                self.request.repository.clone(),
                self.request
                    .git_program
                    .parent()
                    .ok_or_else(|| invalid("Git installation has no parent"))?
                    .to_owned(),
                self.config.git_exec_path.clone(),
            ],
            allow_repository_writes: true,
            artifact_roots: Vec::new(),
        };
        let prepared = containment
            .prepare(&self.request.git_program, &self.workspace.root, &env)
            .map_err(|_| {
                error(
                    "command_containment_unavailable",
                    "local Git preparation is not contained",
                )
            })?;
        let mut wrapped = tokio::process::Command::new(prepared.program);
        wrapped
            .args(prepared.argv)
            .env_clear()
            .current_dir(&self.workspace.root)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        Ok(wrapped)
    }
    async fn run(
        &self,
        args: &[String],
        network: bool,
        mutation: bool,
        cancel: &mut watch::Receiver<bool>,
    ) -> Result<Capture, CheckoutError> {
        self.run_input(args, &[], network, mutation, cancel).await
    }
    async fn reserve_network(&self, mutation: bool) -> Result<(), CheckoutError> {
        // Conservative transaction admission, not physical HTTP metering: Git
        // does not expose exact wire bytes or authentication round trips.
        let maximum = if mutation {
            80 * 1024 * 1024
        } else {
            4 * 1024 * 1024
        };
        for _ in 0..4 {
            let reservation = self
                .budget
                .http_persisted(maximum / 4)
                .await
                .map_err(|e| error(e.cause, e.resource))?;
            // Fully charged on success, cancellation, and transport ambiguity.
            drop(reservation);
        }
        Ok(())
    }
    async fn authorize_network(
        &self,
        mutation: bool,
        cancel: &mut watch::Receiver<bool>,
    ) -> Result<(), CheckoutError> {
        if self
            .workspace
            .root
            .join("metadata/objects/info/alternates")
            .exists()
        {
            return Err(invalid(
                "network Git cannot retain a source object alternate",
            ));
        }
        self.reserve_network(mutation).await?;
        tokio::select! {
            biased;
            () = crate::flow_exec::cancelled(cancel) => return Err(error("cancelled", "Git authorization cancelled")),
            () = tokio::time::sleep_until(self.deadline.into()) => return Err(error("deadline_exceeded", "Git authorization deadline elapsed")),
            result = self.authorization.authorize() => result?,
        }
        Ok(())
    }
    async fn run_input(
        &self,
        args: &[String],
        input: &[u8],
        network: bool,
        mutation: bool,
        cancel: &mut watch::Receiver<bool>,
    ) -> Result<Capture, CheckoutError> {
        active(cancel, self.deadline)?;
        self.budget
            .attempt_persisted()
            .await
            .map_err(|e| error(e.cause, e.resource))?;
        let output_limit = if !network
            && matches!(
                args.first().map(String::as_str),
                Some("rev-list" | "cat-file")
            ) {
            METADATA_LIMIT
        } else {
            PIPE_LIMIT
        };
        let reservation = self
            .budget
            .command_persisted((output_limit + PIPE_LIMIT) as u64)
            .await
            .map_err(|e| error(e.cause, e.resource))?;
        if network {
            self.authorize_network(mutation, cancel).await?;
        }
        let mut command = self.command(network)?;
        command.args(args).stdin(Stdio::piped());
        active(cancel, self.deadline)?;
        if mutation {
            self.started.store(true, Ordering::SeqCst);
        }
        let mut child = command
            .spawn()
            .map_err(|_| error("landing_git_spawn_failed", "trusted Git could not start"))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| invalid("Git input pipe unavailable"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| invalid("Git output pipe unavailable"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| invalid("Git diagnostic pipe unavailable"))?;
        let collect = async {
            let ((), output, diagnostics) = tokio::try_join!(
                send_input(stdin, input),
                bounded_pipe(stdout, output_limit),
                pipe(stderr)
            )
            .map_err(|_| {
                error(
                    "landing_git_output_limit",
                    "Git output exceeded its bounded capture",
                )
            })?;
            let code = child
                .wait()
                .await
                .map_err(|_| {
                    error(
                        "landing_git_transport_failed",
                        "Git did not report completion",
                    )
                })?
                .code();
            Ok::<_, CheckoutError>(Capture {
                code,
                output,
                diagnostics: diagnostics.len(),
            })
        };
        let result = tokio::select! {
            biased;
            () = crate::flow_exec::cancelled(cancel) => Err(error("cancelled", "Git operation cancelled")),
            () = tokio::time::sleep_until(self.deadline.into()) => Err(error("deadline_exceeded", "Git operation deadline elapsed")),
            result = collect => result,
        };
        let capture = result.map_err(|failure| if mutation { uncertain() } else { failure })?;
        reservation
            .finish_persisted((capture.output.len() + capture.diagnostics) as u64)
            .await
            .map_err(|e| {
                if mutation {
                    uncertain()
                } else {
                    error(e.cause, e.resource)
                }
            })?;
        Ok(capture)
    }
}
struct Capture {
    code: Option<i32>,
    output: Vec<u8>,
    diagnostics: usize,
}
fn uncertain() -> CheckoutError {
    error(
        "landing_git_effect_uncertain",
        "push completion is unconfirmed; inspect the exact remote ref before any further write",
    )
}
fn sync_uncertain() -> CheckoutError {
    error(
        "landing_git_effect_uncertain",
        "sync completion is unconfirmed; inspect the exact local base ref before any further write",
    )
}
/// The `pack\t<hash>` line `index-pack --stdin` reports, as `pack-<hash>`.
fn indexed_pack_name(capture: &Capture) -> Result<String, CheckoutError> {
    if capture.code != Some(0) {
        return Err(error(
            "landing_sync_pack_invalid",
            "Git refused the synchronization pack",
        ));
    }
    let text = std::str::from_utf8(&capture.output)
        .map_err(|_| invalid("index-pack report is malformed"))?;
    let mut names = text
        .lines()
        .filter_map(|line| line.strip_prefix("pack\t"))
        .filter(|hash| oid(hash));
    let name = names
        .next()
        .ok_or_else(|| invalid("index-pack did not report the pack identity"))?;
    if names.next().is_some() {
        return Err(invalid("index-pack reported more than one pack"));
    }
    Ok(format!("pack-{name}"))
}
/// Copies the verified `.pack` then `.idx` into the canonical pack directory
/// through temporary names, so the source repository only ever sees a
/// complete pack. A pack already present under the same content hash is
/// left alone.
fn install_pack(source: &Path, target: &Path, name: &str) -> Result<(), CheckoutError> {
    let failed = || {
        error(
            "landing_sync_install_failed",
            "the verified pack could not be installed into the source object store",
        )
    };
    fs::create_dir_all(target).map_err(|_| failed())?;
    for extension in ["pack", "idx"] {
        let installed = target.join(format!("{name}.{extension}"));
        if installed.exists() {
            continue;
        }
        let temporary = target.join(format!("tmp_pam_{}.{extension}", ulid::Ulid::new()));
        let copied =
            fs::copy(source.join(format!("{name}.{extension}")), &temporary).and_then(|_| {
                let mut permissions = fs::metadata(&temporary)?.permissions();
                permissions.set_readonly(true);
                fs::set_permissions(&temporary, permissions)?;
                fs::rename(&temporary, &installed)
            });
        if copied.is_err() {
            let _ = fs::remove_file(&temporary);
            return Err(failed());
        }
    }
    Ok(())
}
/// Moves one branch ref from `old` to `new` with Git's own lock protocol:
/// the `.lock` file is created exclusively, the current value is re-read
/// under the lock and must still be `old`, then the lock is renamed over the
/// ref. Nothing else in the repository is written; the reflog line is
/// appended afterwards on a best-effort basis, as Git does for a plain ref
/// update.
fn update_ref_exact(
    request: &CheckoutRequest,
    reference: &str,
    old: &str,
    new: &str,
) -> Result<(), CheckoutError> {
    use std::io::Write as _;
    let git = request.repository.join(".git");
    let path = git.join(reference);
    let lock = git.join(format!("{reference}.lock"));
    let parent = path
        .parent()
        .ok_or_else(|| invalid("base ref has no parent directory"))?;
    fs::create_dir_all(parent).map_err(|_| {
        error(
            "landing_sync_install_failed",
            "the base ref directory could not be prepared",
        )
    })?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock)
        .map_err(|_| {
            error(
                "landing_sync_install_failed",
                "the base ref is locked by another Git process",
            )
        })?;
    let committed = (|| {
        if landing_checkout::resolve_local_ref(request, reference)? != old {
            return Err(error(
                "landing_checkout_changed",
                "the base ref moved after it was observed",
            ));
        }
        file.write_all(format!("{new}\n").as_bytes())
            .and_then(|()| file.sync_all())
            .and_then(|()| fs::rename(&lock, &path))
            .map_err(|_| {
                error(
                    "landing_sync_install_failed",
                    "the base ref could not be written",
                )
            })
    })();
    if committed.is_err() {
        let _ = fs::remove_file(&lock);
    }
    committed?;
    let log = git.join("logs").join(reference);
    if let Some(parent) = log.parent() {
        let seconds = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_default();
        let _ = fs::create_dir_all(parent).and_then(|()| {
            fs::OpenOptions::new()
                .append(true)
                .create(true)
                .open(&log)?
                .write_all(
                    format!(
                        "{old} {new} PAM <pam@localhost> {seconds} +0000\tpam guarded-land sync\n"
                    )
                    .as_bytes(),
                )
        });
    }
    Ok(())
}
fn active(cancel: &watch::Receiver<bool>, deadline: Instant) -> Result<(), CheckoutError> {
    if *cancel.borrow() || cancel.has_changed().is_err() {
        return Err(error("cancelled", "Git operation cancelled"));
    }
    if Instant::now() >= deadline {
        return Err(error("deadline_exceeded", "Git operation deadline elapsed"));
    }
    Ok(())
}
async fn send_input(
    mut writer: impl tokio::io::AsyncWrite + Unpin,
    input: &[u8],
) -> std::io::Result<()> {
    writer.write_all(input).await?;
    drop(writer);
    Ok(())
}
fn outbound_ids(output: &Capture) -> Result<Vec<String>, CheckoutError> {
    if output.code != Some(0) {
        return Err(error(
            "landing_git_outbound_unproven",
            "outbound object set could not be established",
        ));
    }
    let text = std::str::from_utf8(&output.output)
        .map_err(|_| invalid("outbound object set is malformed"))?;
    let ids: Vec<_> = text.lines().map(str::to_owned).collect();
    let unique: std::collections::BTreeSet<_> = ids.iter().collect();
    if ids.len() > MAX_OUTBOUND_OBJECTS
        || unique.len() != ids.len()
        || ids.iter().any(|id| !oid(id))
    {
        return Err(error(
            "landing_git_outbound_limit",
            "outbound object count exceeds16384 or contains invalid identities",
        ));
    }
    Ok(ids)
}
fn projection_boundaries(
    output: &Capture,
    old: &str,
    new: &str,
) -> Result<Vec<String>, CheckoutError> {
    if !oid(old) || !oid(new) || output.code != Some(0) || output.output.len() > METADATA_LIMIT {
        return Err(invalid("private projection ancestry is unproven"));
    }
    let text = std::str::from_utf8(&output.output)
        .map_err(|_| invalid("private projection ancestry is malformed"))?;
    let mut seen = std::collections::BTreeSet::new();
    let mut boundaries = Vec::new();
    for line in text.lines() {
        let id = line.strip_prefix('-').unwrap_or(line);
        if !oid(id) || !seen.insert(id) || seen.len() > MAX_OUTBOUND_OBJECTS {
            return Err(invalid(
                "private projection ancestry exceeds its identity bound",
            ));
        }
        if line.starts_with('-') {
            boundaries.push(id.to_owned());
        }
    }
    // A no-op push has an empty range; old itself is a complete shallow root.
    if old == new && seen.is_empty() {
        boundaries.push(old.to_owned());
    }
    if boundaries.is_empty() || (old != new && !seen.contains(new)) {
        return Err(invalid("private projection has no proven boundary"));
    }
    boundaries.sort();
    Ok(boundaries)
}
fn outbound_sizes(ids: &[String], output: &Capture) -> Result<u64, CheckoutError> {
    if output.code != Some(0) {
        return Err(error(
            "landing_git_outbound_unproven",
            "outbound object sizes could not be established",
        ));
    }
    let text = std::str::from_utf8(&output.output)
        .map_err(|_| invalid("outbound object metadata is malformed"))?;
    let lines: Vec<_> = text.lines().collect();
    if lines.len() != ids.len() {
        return Err(invalid("outbound object count changed"));
    }
    let mut total = 0_u64;
    for (id, line) in ids.iter().zip(lines) {
        let fields: Vec<_> = line.split(' ').collect();
        if fields.len() != 3 || fields[0] != id || !matches!(fields[1], "blob" | "tree" | "commit")
        {
            return Err(invalid("outbound object identity or type changed"));
        }
        let size = fields[2]
            .parse::<u64>()
            .map_err(|_| invalid("invalid outbound object size"))?;
        total = total
            .checked_add(size)
            .ok_or_else(|| invalid("outbound object size overflow"))?;
        if size > 4 * 1024 * 1024 || total > MAX_OUTBOUND_BYTES {
            return Err(error(
                "landing_git_outbound_limit",
                "outbound objects exceed the4MiB individual or64MiB total limit",
            ));
        }
    }
    Ok(total)
}
async fn pipe(reader: impl tokio::io::AsyncRead + Unpin) -> std::io::Result<Vec<u8>> {
    bounded_pipe(reader, PIPE_LIMIT).await
}
async fn bounded_pipe(
    reader: impl tokio::io::AsyncRead + Unpin,
    limit: usize,
) -> std::io::Result<Vec<u8>> {
    let mut output = Vec::new();
    reader
        .take((limit + 1) as u64)
        .read_to_end(&mut output)
        .await?;
    if output.len() > limit {
        return Err(std::io::Error::other("Git pipe limit"));
    }
    Ok(output)
}
fn parse_ref(capture: &Capture, reference: &str) -> Result<RemoteRef, CheckoutError> {
    if capture.code == Some(2) && capture.output.is_empty() {
        return Ok(RemoteRef {
            ref_name: reference.into(),
            oid: None,
        });
    }
    if capture.code != Some(0) {
        return Err(error(
            "landing_git_transport_failed",
            "exact remote ref could not be observed",
        ));
    }
    let text = std::str::from_utf8(&capture.output)
        .map_err(|_| invalid("remote ref response is malformed"))?;
    let (value, name) = text
        .strip_suffix('\n')
        .and_then(|line| line.split_once('\t'))
        .ok_or_else(|| invalid("remote ref response is malformed"))?;
    if name != reference || !oid(value) {
        return Err(invalid("remote ref response substituted an identity"));
    }
    Ok(RemoteRef {
        ref_name: reference.into(),
        oid: Some(value.into()),
    })
}
fn read_args(url: &str, reference: &str) -> Vec<String> {
    ["ls-remote", "--refs", "--exit-code", "--", url, reference]
        .into_iter()
        .map(str::to_owned)
        .collect()
}
fn push_args(url: &str, reference: &str, commit: &str, old: Option<&str>) -> Vec<String> {
    vec![
        "push".into(),
        "--porcelain".into(),
        "--no-verify".into(),
        "--no-follow-tags".into(),
        "--recurse-submodules=no".into(),
        "--signed=false".into(),
        format!("--force-with-lease={reference}:{}", old.unwrap_or("")),
        "--".into(),
        url.into(),
        format!("{commit}:{reference}"),
    ]
}

async fn resolve_exec_path(
    request: &CheckoutRequest,
    workspace: &Workspace,
    budget: Arc<RequestBudget>,
    cancel: &mut watch::Receiver<bool>,
    deadline: Instant,
) -> Result<PathBuf, CheckoutError> {
    active(cancel, deadline)?;
    budget
        .attempt_persisted()
        .await
        .map_err(|e| error(e.cause, e.resource))?;
    let reservation = budget
        .command_persisted((PIPE_LIMIT * 2) as u64)
        .await
        .map_err(|e| error(e.cause, e.resource))?;
    let mut child = tokio::process::Command::new(&request.git_program)
        .arg("--exec-path")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &workspace.root)
        .env("GIT_DIR", workspace.root.join("metadata"))
        .env("GIT_CONFIG_COUNT", "0")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .current_dir(&workspace.root)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| invalid("trusted Git resolver could not start"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| invalid("resolver output unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| invalid("resolver diagnostics unavailable"))?;
    let collect = async {
        let (output, diagnostics) = tokio::try_join!(pipe(stdout), pipe(stderr))
            .map_err(|_| invalid("Git helper path response exceeds limit"))?;
        let status = child
            .wait()
            .await
            .map_err(|_| invalid("Git helper resolver did not complete"))?;
        Ok::<_, CheckoutError>((status.success(), output, diagnostics))
    };
    let (success, output, diagnostics) = tokio::select! {
        biased;
        () = crate::flow_exec::cancelled(cancel) => return Err(error("cancelled", "Git resolver cancelled")),
        () = tokio::time::sleep_until(deadline.into()) => return Err(error("deadline_exceeded", "Git resolver deadline elapsed")),
        result = collect => result?,
    };
    reservation
        .finish_persisted((output.len() + diagnostics.len()) as u64)
        .await
        .map_err(|e| error(e.cause, e.resource))?;
    if !success || !diagnostics.is_empty() {
        return Err(invalid("trusted Git helper path unavailable"));
    }
    let path = std::str::from_utf8(&output)
        .ok()
        .and_then(|s| s.strip_suffix('\n'))
        .filter(|s| !s.is_empty() && s.len() <= 4096 && !s.chars().any(char::is_control))
        .ok_or_else(|| invalid("Git helper path is malformed"))?;
    let path = Path::new(path);
    if !path.is_absolute() {
        return Err(invalid("Git helper path is not absolute"));
    }
    path.canonicalize()
        .map_err(|_| invalid("Git helper path does not exist"))
}

impl GitTransport {
    pub(crate) async fn resolve(
        request: &CheckoutRequest,
        budget: Arc<RequestBudget>,
        cancel: &mut watch::Receiver<bool>,
        deadline: Instant,
    ) -> Result<Self, CheckoutError> {
        let request = request.clone();
        let runtime = tokio::runtime::Handle::current();
        landing_checkout::owned_worker(cancel, move |mut cancelled| {
            active(&cancelled, deadline)?;
            landing_checkout::validate_layout(&request)?;
            trusted_path(&request.git_program, &request, false)?;
            let workspace = Workspace::create(&request.checkouts_root, &request.repository)?;
            let git_exec_path = runtime.block_on(resolve_exec_path(
                &request,
                &workspace,
                budget,
                &mut cancelled,
                deadline,
            ))?;
            let config = Self { git_exec_path };
            validate_installation(&config, &request)?;
            Ok(config)
        })
        .await
    }

    pub(crate) async fn observe_ref(
        &self,
        target: &GitTarget,
        credential: &Secret,
        budget: Arc<RequestBudget>,
        cancel: &mut watch::Receiver<bool>,
        deadline: Instant,
        authorization: Arc<dyn GitAuthorization>,
    ) -> Result<RemoteRef, CheckoutError> {
        let GitTarget {
            request,
            receipt,
            branch,
            ..
        } = target;
        validate_target(request, receipt)?;
        let reference = reference(branch)?;
        let request = request.clone();
        let config = self.clone();
        let secret = Secret::new(credential.expose().to_owned());
        let runtime = tokio::runtime::Handle::current();
        landing_checkout::owned_worker(cancel, move |mut cancelled| {
            active(&cancelled, deadline)?;
            landing_checkout::validate_layout(&request)?;
            validate_installation(&config, &request)?;
            let workspace = Workspace::create(&request.checkouts_root, &request.repository)?;
            let session = Session {
                config: &config,
                request: &request,
                workspace,
                credential: secret,
                budget,
                deadline,
                started: Arc::new(AtomicBool::new(false)),
                authorization,
            };
            session.disconnect_source()?;
            runtime.block_on(async {
                let capture = session
                    .run(
                        &read_args(&request.remote_url, &reference),
                        true,
                        false,
                        &mut cancelled,
                    )
                    .await?;
                parse_ref(&capture, &reference)
            })
        })
        .await
    }
    /// Caller must persist a prepared mutation journal and obtain current approval
    /// before invocation. This function never retries or accepts unknown ancestry.
    pub(crate) async fn push_exact(
        &self,
        target: &GitTarget,
        credential: &Secret,
        budget: Arc<RequestBudget>,
        cancel: &mut watch::Receiver<bool>,
        deadline: Instant,
        authorization: Arc<dyn GitAuthorization>,
    ) -> Result<PushObservation, CheckoutError> {
        let GitTarget {
            request,
            receipt,
            branch,
            ..
        } = target;
        validate_target(request, receipt)?;
        let reference = reference(branch)?;
        let expected_old = target.expected_old.as_deref();
        if reference != receipt.branch || expected_old.is_some_and(|value| !oid(value)) {
            return Err(invalid(
                "push branch or old commit differs from the approved shape",
            ));
        }
        landing_checkout::revalidate(request, receipt, budget.clone(), cancel, deadline).await?;
        let request = request.clone();
        let config = self.clone();
        let old = expected_old.map(str::to_owned);
        let expected_base = receipt.base_commit.clone();
        let secret = Secret::new(credential.expose().to_owned());
        let runtime = tokio::runtime::Handle::current();
        let started = Arc::new(AtomicBool::new(false));
        let worker_started = started.clone();
        let result = landing_checkout::owned_worker(cancel, move |mut cancelled| {
            active(&cancelled, deadline)?;
            landing_checkout::validate_layout(&request)?;
            validate_installation(&config, &request)?;
            let workspace = Workspace::create(&request.checkouts_root, &request.repository)?;
            let session = Session {
                config: &config,
                request: &request,
                workspace,
                credential: secret,
                budget,
                deadline,
                started: worker_started,
                authorization,
            };
            runtime.block_on(session.push(&reference, old, &expected_base, &mut cancelled))
        })
        .await;
        result.map_err(|failure| {
            if started.load(Ordering::SeqCst) {
                uncertain()
            } else {
                failure
            }
        })
    }
}
impl GitTransport {
    /// Caller must persist a prepared sync intent and hold current approval.
    /// Indexes one preflighted pack in the private workspace, proves the
    /// merge commit fast-forwards the leased base commit, installs the pack
    /// into the canonical object store and moves the base ref with an exact
    /// old-value lease. Never touches the working tree; never retries.
    #[allow(
        clippy::too_many_arguments,
        reason = "Keep the lease, pack, bounds, budget and cancellation explicit"
    )]
    pub(crate) async fn sync_exact(
        &self,
        target: &GitTarget,
        merge_commit: &str,
        pack: Vec<u8>,
        bounds: PackBounds,
        budget: Arc<RequestBudget>,
        cancel: &mut watch::Receiver<bool>,
        deadline: Instant,
        authorization: Arc<dyn GitAuthorization>,
    ) -> Result<SyncObservation, CheckoutError> {
        let GitTarget {
            request,
            receipt,
            branch,
            ..
        } = target;
        validate_target(request, receipt)?;
        let reference = reference(branch)?;
        let Some(expected_old) = target.expected_old.clone() else {
            return Err(invalid(
                "sync requires the observed base commit as its lease",
            ));
        };
        if reference != request.base_ref
            || !oid(&expected_old)
            || !oid(merge_commit)
            || expected_old == merge_commit
        {
            return Err(invalid(
                "sync ref, lease or merge commit differs from the approved shape",
            ));
        }
        let merge_commit = merge_commit.to_owned();
        let request = request.clone();
        let config = self.clone();
        let runtime = tokio::runtime::Handle::current();
        let started = Arc::new(AtomicBool::new(false));
        let worker_started = started.clone();
        let result = landing_checkout::owned_worker(cancel, move |mut cancelled| {
            active(&cancelled, deadline)?;
            landing_checkout::validate_layout(&request)?;
            validate_installation(&config, &request)?;
            let workspace = Workspace::create(&request.checkouts_root, &request.repository)?;
            let session = Session {
                config: &config,
                request: &request,
                workspace,
                credential: Secret::new(String::new()),
                budget,
                deadline,
                started: worker_started,
                authorization,
            };
            runtime.block_on(session.sync(
                &reference,
                &expected_old,
                &merge_commit,
                &pack,
                bounds,
                &mut cancelled,
            ))
        })
        .await;
        result.map_err(|failure| {
            if started.load(Ordering::SeqCst) {
                sync_uncertain()
            } else {
                failure
            }
        })
    }
}
impl Session<'_> {
    async fn sync(
        &self,
        reference: &str,
        expected_old: &str,
        merge_commit: &str,
        pack: &[u8],
        bounds: PackBounds,
        cancel: &mut watch::Receiver<bool>,
    ) -> Result<SyncObservation, CheckoutError> {
        // The stage never writes the working tree, so the base branch must
        // not be the checked-out branch.
        if landing_checkout::head_branch(self.request)? == reference {
            return Err(error(
                "landing_sync_base_checked_out",
                "the base branch is checked out; sync never writes the working tree",
            ));
        }
        if landing_checkout::resolve_local_ref(self.request, reference)? != expected_old {
            return Err(error(
                "landing_checkout_changed",
                "the base ref moved after it was observed",
            ));
        }
        let directory = self.workspace.root.join("metadata/objects/pack");
        fs::create_dir(&directory)
            .map_err(|_| invalid("private object pack directory unavailable"))?;
        // Thin deltas complete against the source object store through the
        // workspace alternates; --strict runs Git's own object checks.
        let indexed = self
            .run_input(
                &[
                    "index-pack".into(),
                    "--strict".into(),
                    "--fix-thin".into(),
                    "--stdin".into(),
                ],
                pack,
                false,
                false,
                cancel,
            )
            .await?;
        let name = indexed_pack_name(&indexed)?;
        let kind = self
            .run(
                &["cat-file".into(), "-t".into(), merge_commit.into()],
                false,
                false,
                cancel,
            )
            .await?;
        if kind.code != Some(0) || kind.output.trim_ascii() != b"commit" {
            return Err(error(
                "landing_sync_ancestry_unproven",
                "the merge commit is not a commit in the synchronization pack",
            ));
        }
        let ancestry = self
            .run(
                &[
                    "merge-base".into(),
                    "--is-ancestor".into(),
                    expected_old.into(),
                    merge_commit.into(),
                ],
                false,
                false,
                cancel,
            )
            .await?;
        if ancestry.code != Some(0) {
            return Err(error(
                "landing_sync_ancestry_unproven",
                "the leased base commit is not an ancestor of the merge commit; sync only fast-forwards",
            ));
        }
        // Every new object must be reachable and countable; rev-list fails
        // on a missing object and the id parser bounds the count.
        let listed = self
            .run(
                &[
                    "rev-list".into(),
                    "--objects".into(),
                    "--no-object-names".into(),
                    format!("{expected_old}..{merge_commit}"),
                    "--".into(),
                ],
                false,
                false,
                cancel,
            )
            .await?;
        if outbound_ids(&listed)?.is_empty() {
            return Err(error(
                "landing_sync_ancestry_unproven",
                "the merge commit adds no objects over the leased base commit",
            ));
        }
        active(cancel, self.deadline)?;
        self.started.store(true, Ordering::SeqCst);
        install_pack(
            &directory,
            &self.request.repository.join(".git/objects/pack"),
            &name,
        )?;
        update_ref_exact(self.request, reference, expected_old, merge_commit)?;
        Ok(SyncObservation {
            ref_name: reference.to_owned(),
            expected_old: expected_old.to_owned(),
            requested_commit: merge_commit.to_owned(),
            pack: name,
            bounds,
        })
    }
    async fn project_history(
        &self,
        old: Option<&str>,
        cancel: &mut watch::Receiver<bool>,
    ) -> Result<(), CheckoutError> {
        let Some(old) = old else {
            return Ok(());
        };
        let captured = self
            .run(
                &[
                    "rev-list".into(),
                    "--boundary".into(),
                    self.request.expected_commit.clone(),
                    format!("^{old}"),
                    "--".into(),
                ],
                false,
                false,
                cancel,
            )
            .await?;
        let boundaries = projection_boundaries(&captured, old, &self.request.expected_commit)?;
        fs::write(
            self.workspace.root.join("metadata/shallow"),
            boundaries.join("\n") + "\n",
        )
        .map_err(|_| invalid("private shallow boundary could not be written"))
    }
    async fn isolate_objects(
        &self,
        old: Option<&str>,
        cancel: &mut watch::Receiver<bool>,
    ) -> Result<(), CheckoutError> {
        self.project_history(old, cancel).await?;
        // Git traverses all trees but stops commit ancestry at the verified
        // private shallow boundaries. Without an old ref, full closure remains
        // bounded: new branches with oversized history are explicitly refused.
        let args = vec![
            "rev-list".into(),
            "--objects".into(),
            "--no-object-names".into(),
            self.request.expected_commit.clone(),
            "--".into(),
        ];
        let listed = self.run(&args, false, false, cancel).await?;
        let ids = outbound_ids(&listed)?;
        if ids.is_empty() {
            return Err(invalid("approved commit has no reachable objects"));
        }
        let input = format!("{}\n", ids.join("\n"));
        let metadata = self
            .run_input(
                &["cat-file".into(), "--batch-check".into()],
                input.as_bytes(),
                false,
                false,
                cancel,
            )
            .await?;
        outbound_sizes(&ids, &metadata)?;
        let directory = self.workspace.root.join("metadata/objects/pack");
        fs::create_dir(&directory)
            .map_err(|_| invalid("private object pack directory unavailable"))?;
        let prefix = directory.join("pack");
        let prefix = prefix
            .to_str()
            .ok_or_else(|| invalid("private object path is invalid"))?;
        let packed = self
            .run_input(
                &[
                    "pack-objects".into(),
                    "--no-reuse-delta".into(),
                    "--no-reuse-object".into(),
                    prefix.into(),
                ],
                input.as_bytes(),
                false,
                false,
                cancel,
            )
            .await?;
        if packed.code != Some(0) {
            return Err(error(
                "landing_git_outbound_unproven",
                "private object pack could not be constructed",
            ));
        }
        self.disconnect_source()?;
        let mut stored = 0_u64;
        for entry in
            fs::read_dir(&directory).map_err(|_| invalid("private pack cannot be inspected"))?
        {
            let meta = entry
                .map_err(|_| invalid("private pack entry unavailable"))?
                .metadata()
                .map_err(|_| invalid("private pack metadata unavailable"))?;
            stored = stored
                .checked_add(meta.len())
                .ok_or_else(|| invalid("private pack size overflow"))?;
            if !meta.is_file() || stored > 80 * 1024 * 1024 {
                return Err(error(
                    "landing_git_outbound_limit",
                    "private pack exceeds its80MiB disk bound",
                ));
            }
        }
        let checked = self
            .run(
                &[
                    "fsck".into(),
                    "--strict".into(),
                    "--no-reflogs".into(),
                    self.request.expected_commit.clone(),
                ],
                false,
                false,
                cancel,
            )
            .await?;
        if checked.code != Some(0) {
            return Err(error(
                "landing_git_outbound_unproven",
                "private object pack failed integrity verification",
            ));
        }
        Ok(())
    }
    fn disconnect_source(&self) -> Result<(), CheckoutError> {
        fs::remove_file(self.workspace.root.join("metadata/objects/info/alternates"))
            .map_err(|_| invalid("source object store could not be disconnected"))
    }
    async fn recheck_source(
        &self,
        reference: &str,
        expected_base: &str,
        cancel: &mut watch::Receiver<bool>,
    ) -> Result<(), CheckoutError> {
        fs::write(
            self.workspace.root.join("metadata/HEAD"),
            format!("{}\n", self.request.expected_commit),
        )
        .map_err(|_| invalid("private source check metadata unavailable"))?;
        let index = self
            .run(
                &["read-tree".into(), self.request.expected_commit.clone()],
                false,
                false,
                cancel,
            )
            .await?;
        if index.code != Some(0) {
            return Err(invalid("private source check index unavailable"));
        }
        let status = self
            .run(
                &[
                    "status".into(),
                    "--porcelain=v1".into(),
                    "-z".into(),
                    "--untracked-files=all".into(),
                ],
                false,
                false,
                cancel,
            )
            .await?;
        if status.code != Some(0) || !status.output.is_empty() {
            return Err(error(
                "landing_checkout_changed",
                "source changed during push preparation",
            ));
        }
        if landing_checkout::ref_state(self.request)?
            != (reference.to_owned(), expected_base.to_owned())
        {
            return Err(error(
                "landing_checkout_changed",
                "source refs changed during push preparation",
            ));
        }
        Ok(())
    }
    async fn push(
        &self,
        reference: &str,
        old: Option<String>,
        expected_base: &str,
        cancel: &mut watch::Receiver<bool>,
    ) -> Result<PushObservation, CheckoutError> {
        if let Some(prior) = old.as_ref() {
            let proof = self
                .run(
                    &[
                        "merge-base".into(),
                        "--is-ancestor".into(),
                        prior.clone(),
                        self.request.expected_commit.clone(),
                    ],
                    false,
                    false,
                    cancel,
                )
                .await?;
            if proof.code != Some(0) {
                return Err(error(
                    "landing_git_ancestry_unproven",
                    "remote old commit is not a proven ancestor of the proposed commit",
                ));
            }
        }
        self.isolate_objects(old.as_deref(), cancel).await?;
        self.recheck_source(reference, expected_base, cancel)
            .await?;
        let result = self
            .run(
                &push_args(
                    &self.request.remote_url,
                    reference,
                    &self.request.expected_commit,
                    old.as_deref(),
                ),
                true,
                true,
                cancel,
            )
            .await?;
        Ok(PushObservation {
            ref_name: reference.into(),
            expected_old: old,
            requested_commit: self.request.expected_commit.clone(),
            state: if result.code == Some(0) {
                PushState::ReportedSuccess
            } else {
                PushState::Uncertain
            },
        })
    }
}
pub(crate) fn reconcile(
    observed: &RemoteRef,
    prepared: &PushObservation,
) -> Result<Reconciliation, CheckoutError> {
    if observed.ref_name != prepared.ref_name {
        return Err(invalid("reconciliation ref differs from the prepared push"));
    }
    Ok(
        if observed.oid.as_deref() == Some(prepared.requested_commit.as_str()) {
            Reconciliation::Matched
        } else if observed.oid == prepared.expected_old {
            Reconciliation::Unchanged
        } else {
            Reconciliation::Conflicting
        },
    )
}

#[cfg(test)]
#[path = "landing_git_test.rs"]
mod tests;
