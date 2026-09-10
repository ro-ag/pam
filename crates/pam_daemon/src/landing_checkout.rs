//! Local landing snapshots: no source Git configuration, hooks, filters or network.
//! Initial support is ordinary SHA-1 checkouts with regular tracked files only.
//! Linked worktrees, alternates, symlinks and submodules are explicit refusals.
//! The configured checkout parent must be host-owned and inaccessible to agents;
//! same-user unconstrained host mutation remains outside the containment model.
use crate::{command_containment::CommandContainment, request_budget::RequestBudget};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::Instant,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::watch,
};

const MAX_FILES: usize = 4096;
const MAX_FILE: usize = 4 * 1024 * 1024;
const MAX_TOTAL: usize = 64 * 1024 * 1024;
const MAX_LIST: usize = 5 * 1024 * 1024;
const MAX_STDERR: usize = 16 * 1024;

#[derive(Clone)]
pub(crate) struct CheckoutRequest {
    pub repository: PathBuf,
    pub protected_base: PathBuf,
    pub checkouts_root: PathBuf,
    pub git_program: PathBuf,
    pub expected_commit: String,
    pub base_ref: String,
    pub remote_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ManifestEntry {
    pub path: String,
    pub oid: String,
    pub sha256: String,
    pub mode: u32,
    pub bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CheckoutReceipt {
    pub repository: PathBuf,
    pub remote_url: String,
    pub branch: String,
    pub commit: String,
    pub base_ref: String,
    pub base_commit: String,
    pub tree: String,
    pub manifest: Vec<ManifestEntry>,
    pub manifest_sha256: String,
}

#[derive(Debug)]
pub(crate) struct CheckoutSnapshot {
    pub receipt: CheckoutReceipt,
    pub checktree: PathBuf,
}

#[derive(Debug, thiserror::Error)]
#[error("{cause}: {detail}")]
pub(crate) struct CheckoutError {
    pub cause: &'static str,
    pub detail: &'static str,
}
fn error(cause: &'static str, detail: &'static str) -> CheckoutError {
    CheckoutError { cause, detail }
}
fn invalid(detail: &'static str) -> CheckoutError {
    error("landing_checkout_unsupported", detail)
}
fn io_error(_: std::io::Error) -> CheckoutError {
    error("landing_checkout_io", "local checkout I/O failed")
}
fn valid_oid(value: &str) -> bool {
    value.len() == 40
        && value.bytes().all(|b| b.is_ascii_hexdigit())
        && value.bytes().any(|b| b != b'0')
}
fn bounded_read(path: &Path, max: usize) -> Result<Vec<u8>, CheckoutError> {
    if !fs::symlink_metadata(path).map_err(io_error)?.is_file() {
        return Err(invalid("non-regular Git metadata"));
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(io_error)?
        .take((max + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    if bytes.len() > max {
        return Err(invalid("Git metadata exceeds capture limit"));
    }
    Ok(bytes)
}
fn text(bytes: &[u8]) -> Result<&str, CheckoutError> {
    std::str::from_utf8(bytes).map_err(|_| invalid("Git metadata is not UTF-8"))
}
fn valid_ref(value: &str) -> bool {
    value.starts_with("refs/")
        && value.len() <= 256
        && !value.contains(['\\', ' ', '\t', '\n', '\r', '~', '^', ':', '?', '*', '['])
        && !value.contains("..")
        && !value.contains("@{")
        && value.split('/').all(|part| {
            !part.is_empty()
                && !part.starts_with('.')
                && !part.ends_with('.')
                && !part.ends_with(".lock")
        })
}
fn resolve_ref(git: &Path, reference: &str) -> Result<String, CheckoutError> {
    if !valid_ref(reference) {
        return Err(invalid("unsupported Git reference"));
    }
    let path = git.join(reference);
    let value = if path.exists() {
        text(&bounded_read(&path, 128)?)?.trim().to_owned()
    } else {
        let packed = bounded_read(&git.join("packed-refs"), 1024 * 1024)?;
        let mut found = text(&packed)?
            .lines()
            .filter_map(|line| line.split_once(' '))
            .filter(|(_, name)| *name == reference);
        let value = found
            .next()
            .ok_or_else(|| invalid("requested base or branch reference is unavailable"))?
            .0
            .to_owned();
        if found.next().is_some() {
            return Err(invalid("duplicate packed reference"));
        }
        value
    };
    if !valid_oid(&value) {
        return Err(invalid("only direct full SHA-1 refs are supported"));
    }
    Ok(value.to_ascii_lowercase())
}
fn ref_state(request: &CheckoutRequest) -> Result<(String, String), CheckoutError> {
    let git = request.repository.join(".git");
    let head = bounded_read(&git.join("HEAD"), 512)?;
    let branch = text(&head)?
        .trim()
        .strip_prefix("ref: ")
        .filter(|r| r.starts_with("refs/heads/"))
        .ok_or_else(|| invalid("detached HEAD is unsupported"))?;
    if resolve_ref(&git, branch)? != request.expected_commit {
        return Err(error(
            "landing_checkout_changed",
            "HEAD differs from the approved commit",
        ));
    }
    Ok((branch.to_owned(), resolve_ref(&git, &request.base_ref)?))
}
fn validate_layout(request: &CheckoutRequest) -> Result<(), CheckoutError> {
    if !valid_oid(&request.expected_commit)
        || request.expected_commit != request.expected_commit.to_ascii_lowercase()
    {
        return Err(invalid("expected commit must be lowercase full SHA-1"));
    }
    for path in [
        &request.repository,
        &request.protected_base,
        &request.checkouts_root,
    ] {
        if path
            .to_str()
            .is_none_or(|s| s.chars().any(char::is_control))
            || !path.is_absolute()
            || path.canonicalize().map_err(io_error)? != *path
            || !path.is_dir()
        {
            return Err(invalid(
                "checkout boundary must be an existing canonical directory",
            ));
        }
    }
    let root = &request.checkouts_root;
    let repo = &request.repository;
    if root.starts_with(repo)
        || repo.starts_with(root)
        || root.starts_with(&request.protected_base)
        || request.protected_base.starts_with(root)
    {
        return Err(invalid(
            "checkout parent overlaps source or private PAM state",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if fs::metadata(root).map_err(io_error)?.permissions().mode() & 0o077 != 0 {
            return Err(invalid("checkout parent must have private permissions"));
        }
    }
    let git = repo.join(".git");
    if !fs::symlink_metadata(&git).map_err(io_error)?.is_dir()
        || git.canonicalize().map_err(io_error)? != git
    {
        return Err(invalid(
            "linked worktrees and indirect Git directories are unsupported",
        ));
    }
    validate_git_paths(&git)?;
    Ok(())
}
fn validate_git_paths(git: &Path) -> Result<(), CheckoutError> {
    let mut pending = vec![git.to_owned()];
    let mut entries = 0;
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory).map_err(io_error)? {
            let entry = entry.map_err(io_error)?;
            entries += 1;
            if entries > 32_768 {
                return Err(invalid("Git metadata entry limit exceeded"));
            }
            let ty = entry.file_type().map_err(io_error)?;
            if ty.is_symlink() || (!ty.is_file() && !ty.is_dir()) {
                return Err(invalid("indirect Git metadata is unsupported"));
            }
            let path = entry.path();
            if path.ends_with("objects/info/alternates")
                || path.ends_with("objects/info/http-alternates")
                || path.ends_with("shallow")
            {
                return Err(invalid(
                    "alternate or shallow object stores are unsupported",
                ));
            }
            if ty.is_dir() {
                pending.push(path);
            }
        }
    }
    Ok(())
}

struct Workspace {
    root: PathBuf,
    tree: PathBuf,
    keep: bool,
}
impl Drop for Workspace {
    fn drop(&mut self) {
        if !self.keep {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}
impl Workspace {
    fn create(parent: &Path, source: &Path) -> Result<Self, CheckoutError> {
        let root = parent.join(format!("landing-{}", ulid::Ulid::new()));
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&root).map_err(io_error)?;
        let workspace = Self {
            tree: root.join("tree"),
            root,
            keep: false,
        };
        fs::create_dir(&workspace.tree).map_err(io_error)?;
        let git = workspace.root.join("metadata");
        fs::create_dir(&git).map_err(io_error)?;
        fs::create_dir(git.join("objects")).map_err(io_error)?;
        fs::create_dir(git.join("objects/info")).map_err(io_error)?;
        fs::write(
            git.join("objects/info/alternates"),
            format!("{}\n", source.join(".git/objects").display()),
        )
        .map_err(io_error)?;
        fs::create_dir(git.join("refs")).map_err(io_error)?;
        fs::write(git.join("HEAD"), "ref: refs/heads/unused\n").map_err(io_error)?;
        fs::write(
            git.join("config"),
            "[core]\nrepositoryformatversion = 0\nbare = false\n",
        )
        .map_err(io_error)?;
        Ok(workspace)
    }
}
struct Git<'a> {
    request: &'a CheckoutRequest,
    workspace: &'a Workspace,
    budget: Arc<RequestBudget>,
    deadline: Instant,
}
impl Git<'_> {
    fn environment(&self) -> Result<Vec<(String, String)>, CheckoutError> {
        let paths = [
            ("GIT_DIR", self.workspace.root.join("metadata")),
            ("GIT_WORK_TREE", self.request.repository.clone()),
            ("HOME", self.workspace.root.clone()),
        ];
        let mut env = Vec::new();
        for (key, path) in paths {
            env.push((
                key.to_owned(),
                path.to_str()
                    .ok_or_else(|| invalid("non-UTF-8 checkout path"))?
                    .to_owned(),
            ));
        }
        for (key, value) in [
            ("PATH", "/usr/bin:/bin"),
            ("GIT_CONFIG_NOSYSTEM", "1"),
            ("GIT_CONFIG_GLOBAL", "/dev/null"),
            ("GIT_CONFIG_SYSTEM", "/dev/null"),
            ("GIT_NO_REPLACE_OBJECTS", "1"),
            ("GIT_NO_LAZY_FETCH", "1"),
            ("GIT_TERMINAL_PROMPT", "0"),
            ("GIT_ATTR_NOSYSTEM", "1"),
            ("LC_ALL", "C"),
        ] {
            env.push((key.into(), value.into()));
        }
        Ok(env)
    }
    fn command(&self) -> Result<tokio::process::Command, CheckoutError> {
        let containment = CommandContainment {
            protected_base: self.request.protected_base.clone(),
            repository: self.workspace.root.clone(),
            read_only_roots: vec![
                self.request.repository.clone(),
                self.request
                    .git_program
                    .parent()
                    .ok_or_else(|| invalid("Git program has no directory"))?
                    .to_owned(),
            ],
            allow_repository_writes: true,
        };
        let prepared = containment
            .prepare(
                &self.request.git_program,
                &self.workspace.root,
                &self.environment()?,
            )
            .map_err(|_| {
                error(
                    "command_containment_unavailable",
                    "contained Git is unavailable",
                )
            })?;
        let mut command = tokio::process::Command::new(prepared.program);
        command
            .args(prepared.argv)
            .args([
                "--no-pager",
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.untrackedCache=false",
                "-c",
                "core.attributesFile=/dev/null",
                "-c",
                "core.excludesFile=/dev/null",
                "-c",
                "protocol.allow=never",
                "-c",
                "submodule.recurse=false",
            ])
            .current_dir(&self.workspace.root)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        Ok(command)
    }
    async fn run(
        &self,
        args: &[&str],
        input: &[u8],
        cap: usize,
        cancel: &mut watch::Receiver<bool>,
    ) -> Result<Vec<u8>, CheckoutError> {
        self.budget
            .attempt_persisted()
            .await
            .map_err(|e| error(e.cause, e.resource))?;
        let reservation = self
            .budget
            .command_persisted((cap + MAX_STDERR) as u64)
            .await
            .map_err(|e| error(e.cause, e.resource))?;
        let mut command = self.command()?;
        command.args(args);
        let mut child = command.spawn().map_err(io_error)?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| invalid("Git stdin unavailable"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| invalid("Git stdout unavailable"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| invalid("Git stderr unavailable"))?;
        let operation = async {
            let send = async {
                stdin.write_all(input).await?;
                stdin.shutdown().await
            };
            let read_out = read_pipe(stdout, cap);
            let read_err = read_pipe(stderr, MAX_STDERR);
            let (_, output, diagnostics) =
                tokio::try_join!(send, read_out, read_err).map_err(io_error)?;
            let status = child.wait().await.map_err(io_error)?;
            Ok::<_, CheckoutError>((status.success(), output, diagnostics.len()))
        };
        let result = tokio::select! {
            biased;
            () = crate::flow_exec::cancelled(cancel) => Err(error("cancelled", "checkout capture cancelled")),
            () = tokio::time::sleep_until(self.deadline.into()) => Err(error("deadline_exceeded", "checkout capture deadline elapsed")),
            result = operation => result,
        };
        let (success, output, diagnostics) = result?;
        reservation
            .finish_persisted((output.len() + diagnostics) as u64)
            .await
            .map_err(|e| error(e.cause, e.resource))?;
        if !success {
            return Err(error(
                "landing_checkout_git_failed",
                "contained Git rejected the local checkout",
            ));
        }
        if diagnostics != 0 {
            return Err(invalid("Git returned diagnostics during exact capture"));
        }
        Ok(output)
    }
    async fn clean(&self, cancel: &mut watch::Receiver<bool>) -> Result<(), CheckoutError> {
        fs::write(
            self.workspace.root.join("metadata/HEAD"),
            format!("{}\n", self.request.expected_commit),
        )
        .map_err(io_error)?;
        self.run(
            &["read-tree", &self.request.expected_commit],
            &[],
            1024,
            cancel,
        )
        .await?;
        let status = self
            .run(
                &[
                    "status",
                    "--porcelain=v1",
                    "-z",
                    "--untracked-files=all",
                    "--ignore-submodules=none",
                ],
                &[],
                MAX_LIST,
                cancel,
            )
            .await?;
        if !status.is_empty() {
            return Err(error(
                "landing_checkout_dirty",
                "tracked changes or nonignored untracked files are present",
            ));
        }
        Ok(())
    }
    async fn verified_commit_tree(
        &self,
        cancel: &mut watch::Receiver<bool>,
    ) -> Result<String, CheckoutError> {
        let commit = self
            .run(
                &["cat-file", "commit", &self.request.expected_commit],
                &[],
                1024 * 1024,
                cancel,
            )
            .await?;
        let oid = self
            .run(
                &["hash-object", "-t", "commit", "--stdin"],
                &commit,
                128,
                cancel,
            )
            .await?;
        if text(&oid)?.trim() != self.request.expected_commit {
            return Err(invalid("commit object hash mismatch"));
        }
        let tree = text(&commit)?
            .lines()
            .next()
            .and_then(|line| line.strip_prefix("tree "))
            .filter(|value| valid_oid(value))
            .ok_or_else(|| invalid("invalid commit tree"))?;
        Ok(tree.to_owned())
    }
    async fn verify_manifest(
        &self,
        manifest: &[ManifestEntry],
        tree: &str,
        cancel: &mut watch::Receiver<bool>,
    ) -> Result<(), CheckoutError> {
        let paths = manifest
            .iter()
            .map(|entry| format!("tree/{}\n", entry.path))
            .collect::<String>();
        let hashes = self
            .run(
                &["hash-object", "--no-filters", "--stdin-paths"],
                paths.as_bytes(),
                MAX_FILES * 41,
                cancel,
            )
            .await?;
        if !text(&hashes)?
            .lines()
            .eq(manifest.iter().map(|entry| entry.oid.as_str()))
        {
            return Err(invalid("exported blob hash mismatch"));
        }
        // Rebuild a fresh index, without read-tree's cached subtree identities.
        self.run(&["read-tree", "--empty"], &[], 1024, cancel)
            .await?;
        let records = manifest
            .iter()
            .map(|entry| {
                format!(
                    "{:o} {}\t{}\0",
                    entry.mode | 0o100000,
                    entry.oid,
                    entry.path
                )
            })
            .collect::<String>();
        self.run(
            &["update-index", "-z", "--index-info"],
            records.as_bytes(),
            1024,
            cancel,
        )
        .await?;
        let actual = self.run(&["write-tree"], &[], 128, cancel).await?;
        if text(&actual)?.trim() != tree {
            return Err(invalid("exported structure does not match commit tree"));
        }
        Ok(())
    }
    async fn remote(&self, cancel: &mut watch::Receiver<bool>) -> Result<(), CheckoutError> {
        let config = self.request.repository.join(".git/config");
        let config = config
            .to_str()
            .ok_or_else(|| invalid("non-UTF-8 Git configuration path"))?;
        let output = self
            .run(
                &[
                    "config",
                    "--file",
                    config,
                    "--no-includes",
                    "--get-all",
                    "remote.origin.url",
                ],
                &[],
                4096,
                cancel,
            )
            .await?;
        if text(&output)?.strip_suffix('\n') != Some(self.request.remote_url.as_str()) {
            return Err(error(
                "landing_checkout_changed",
                "origin URL differs from the approved remote",
            ));
        }
        Ok(())
    }
}
async fn read_pipe(
    reader: impl tokio::io::AsyncRead + Unpin,
    cap: usize,
) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take((cap + 1) as u64)
        .read_to_end(&mut bytes)
        .await?;
    if bytes.len() > cap {
        return Err(std::io::Error::other("bounded Git output exceeded"));
    }
    Ok(bytes)
}

fn parse_manifest(bytes: &[u8]) -> Result<Vec<ManifestEntry>, CheckoutError> {
    let mut entries = Vec::new();
    let mut names = BTreeSet::new();
    let mut total = 0_usize;
    for record in bytes.split(|b| *b == 0).filter(|r| !r.is_empty()) {
        if entries.len() >= MAX_FILES {
            return Err(invalid("tracked file count exceeds limit"));
        }
        let (header, path) = text(record)?
            .split_once('\t')
            .ok_or_else(|| invalid("invalid tree entry"))?;
        validate_path(path)?;
        if !names.insert(path.to_lowercase()) {
            return Err(invalid("case-colliding tracked paths are unsupported"));
        }
        let fields: Vec<_> = header.split_whitespace().collect();
        if fields.len() != 4 || fields[1] != "blob" || !valid_oid(fields[2]) {
            return Err(invalid("non-blob tree entry is unsupported"));
        }
        let mode = match fields[0] {
            "100644" => 0o644,
            "100755" => 0o755,
            _ => {
                return Err(invalid(
                    "symlinks and special tracked modes are unsupported",
                ));
            }
        };
        let size = fields[3]
            .parse::<usize>()
            .map_err(|_| invalid("invalid blob size"))?;
        total = total
            .checked_add(size)
            .ok_or_else(|| invalid("export size overflow"))?;
        if size > MAX_FILE || total > MAX_TOTAL {
            return Err(invalid("tracked content exceeds export limit"));
        }
        entries.push(ManifestEntry {
            path: path.into(),
            oid: fields[2].to_owned(),
            sha256: String::new(),
            mode,
            bytes: size,
        });
    }
    Ok(entries)
}
fn validate_path(path: &str) -> Result<(), CheckoutError> {
    if path.is_empty()
        || path.len() > 1024
        || path.chars().any(char::is_control)
        || path.contains('\\')
        || path
            .split('/')
            .any(|p| p.is_empty() || p == "." || p == ".." || p.eq_ignore_ascii_case(".git"))
    {
        return Err(invalid("unsafe tracked path"));
    }
    Ok(())
}
fn export_blobs(
    root: &Path,
    entries: &mut [ManifestEntry],
    mut data: &[u8],
) -> Result<(), CheckoutError> {
    for entry in entries {
        let end = data
            .iter()
            .position(|b| *b == b'\n')
            .ok_or_else(|| invalid("missing batch object header"))?;
        let expected = format!("{} blob {}", entry.oid, entry.bytes);
        if data.get(..end) != Some(expected.as_bytes()) {
            return Err(invalid("batch object identity or size mismatch"));
        }
        data = &data[end + 1..];
        let bytes = data
            .get(..entry.bytes)
            .ok_or_else(|| invalid("truncated batch object"))?;
        if data.get(entry.bytes) != Some(&b'\n') {
            return Err(invalid("missing batch object delimiter"));
        }
        let destination = root.join(&entry.path);
        fs::create_dir_all(
            destination
                .parent()
                .ok_or_else(|| invalid("missing tracked parent"))?,
        )
        .map_err(io_error)?;
        use std::io::Write;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&destination)
            .map_err(io_error)?;
        file.write_all(bytes).map_err(io_error)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(entry.mode & 0o555))
                .map_err(io_error)?;
        }
        entry.sha256 = pam_compact::sha256_hex(bytes);
        data = &data[entry.bytes + 1..];
    }
    if !data.is_empty() {
        return Err(invalid("unexpected trailing batch data"));
    }
    Ok(())
}

pub(crate) async fn capture(
    request: &CheckoutRequest,
    budget: Arc<RequestBudget>,
    cancel: &mut watch::Receiver<bool>,
    deadline: Instant,
) -> Result<CheckoutSnapshot, CheckoutError> {
    validate_layout(request)?;
    let (branch, base_commit) = ref_state(request)?;
    let mut workspace = Workspace::create(&request.checkouts_root, &request.repository)?;
    let git = Git {
        request,
        workspace: &workspace,
        budget,
        deadline,
    };
    git.remote(cancel).await?;
    git.clean(cancel).await?;
    let tree = git.verified_commit_tree(cancel).await?;
    let raw = git
        .run(
            &["ls-tree", "-rlz", &request.expected_commit],
            &[],
            MAX_LIST,
            cancel,
        )
        .await?;
    let mut manifest = parse_manifest(&raw)?;
    let input = manifest
        .iter()
        .map(|e| format!("{}\n", e.oid))
        .collect::<String>();
    let cap = manifest.iter().map(|e| e.bytes + 128).sum::<usize>();
    let data = git
        .run(&["cat-file", "--batch"], input.as_bytes(), cap, cancel)
        .await?;
    export_blobs(&workspace.tree, &mut manifest, &data)?;
    git.verify_manifest(&manifest, &tree, cancel).await?;
    git.clean(cancel).await?;
    git.remote(cancel).await?;
    if ref_state(request)? != (branch.clone(), base_commit.clone()) {
        return Err(error(
            "landing_checkout_changed",
            "source refs changed during capture",
        ));
    }
    let digest = pam_compact::sha256_hex(
        &serde_json::to_vec(&manifest).map_err(|_| invalid("manifest cannot be encoded"))?,
    );
    let receipt = CheckoutReceipt {
        repository: request.repository.clone(),
        remote_url: request.remote_url.clone(),
        branch,
        commit: request.expected_commit.clone(),
        base_ref: request.base_ref.clone(),
        base_commit,
        tree,
        manifest,
        manifest_sha256: digest,
    };
    workspace.keep = true;
    Ok(CheckoutSnapshot {
        receipt,
        checktree: workspace.tree.clone(),
    })
}

pub(crate) async fn revalidate(
    request: &CheckoutRequest,
    receipt: &CheckoutReceipt,
    budget: Arc<RequestBudget>,
    cancel: &mut watch::Receiver<bool>,
    deadline: Instant,
) -> Result<(), CheckoutError> {
    validate_layout(request)?;
    if receipt.repository != request.repository
        || receipt.remote_url != request.remote_url
        || receipt.commit != request.expected_commit
        || receipt.base_ref != request.base_ref
        || ref_state(request)? != (receipt.branch.clone(), receipt.base_commit.clone())
    {
        return Err(error(
            "landing_checkout_changed",
            "approved source identity changed",
        ));
    }
    let workspace = Workspace::create(&request.checkouts_root, &request.repository)?;
    let git = Git {
        request,
        workspace: &workspace,
        budget,
        deadline,
    };
    git.remote(cancel).await?;
    git.clean(cancel).await?;
    if ref_state(request)? != (receipt.branch.clone(), receipt.base_commit.clone()) {
        return Err(error(
            "landing_checkout_changed",
            "source changed during revalidation",
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "landing_checkout_test.rs"]
mod tests;
