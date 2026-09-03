//! AWS: an allowlisted passthrough to the local `aws` CLI.
//!
//! This connector stores no credential. The CLI resolves `~/.aws` the way
//! the human's own shell does, and the only thing pam keeps is an optional
//! profile name in the connector row's `username`.
//!
//! What pam does keep is the allowlist. [`ALLOWED`] is twenty-five exact
//! `(service, command)` pairs, and a prefix heuristic over `get`/`list`/
//! `describe` is refused on purpose: it would admit `ecr get-login-password`
//! and `s3 presign`, which read a credential out rather than a fact. Extra
//! arguments are bounded and scrubbed of `file://` and of the flags pam
//! itself owns, so a step cannot make the CLI read local files or redirect
//! the call somewhere else.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::{Duration, Instant};

use pam_flow::ArgValue;
use serde_json::{Value, json};
use tokio::process::Command;

use crate::curl::read_capped;
use crate::error::ConnectorError;
use crate::transport::{Connection, excerpt};
use crate::{CallResult, ConnectorId, VerifyReport, unknown_call};

/// The exact `(service, command)` pairs a flow may run.
///
/// Every addition is reviewed as a pair. Nothing here writes, and nothing
/// here prints a credential.
pub const ALLOWED: &[(&str, &str)] = &[
    ("sts", "get-caller-identity"),
    ("ec2", "describe-instances"),
    ("ec2", "describe-security-groups"),
    ("ec2", "describe-vpcs"),
    ("ec2", "describe-subnets"),
    ("s3api", "list-buckets"),
    ("s3api", "list-objects-v2"),
    ("s3api", "get-bucket-location"),
    ("iam", "list-users"),
    ("iam", "list-roles"),
    ("iam", "get-user"),
    ("iam", "list-attached-role-policies"),
    ("cloudformation", "list-stacks"),
    ("cloudformation", "describe-stacks"),
    ("cloudformation", "describe-stack-events"),
    ("lambda", "list-functions"),
    ("lambda", "get-function-configuration"),
    ("logs", "describe-log-groups"),
    ("logs", "describe-log-streams"),
    ("logs", "filter-log-events"),
    ("ecs", "list-clusters"),
    ("ecs", "list-services"),
    ("ecs", "describe-services"),
    ("rds", "describe-db-instances"),
    ("cloudwatch", "describe-alarms"),
    ("cloudwatch", "get-metric-data"),
];

/// Flags pam sets itself, or refuses outright.
///
/// A step may not spell them, in either the `--flag value` or the
/// `--flag=value` form: they decide where the call goes, what shape the
/// answer takes, and whether the CLI reads a local file for its input.
pub const FORBIDDEN_FLAGS: &[&str] = &[
    "--profile",
    "--output",
    "--no-cli-pager",
    "--cli-input-json",
    "--cli-input-yaml",
    "--endpoint-url",
    "--debug",
];

/// The most extra arguments a `cli` call may carry.
pub const MAX_EXTRA_ARGS: usize = 32;

/// The most bytes one extra argument may weigh.
pub const MAX_ARG_BYTES: usize = 512;

/// The most standard output pam keeps; beyond it the answer is `partial`.
pub const MAX_STDOUT_BYTES: u64 = 256 * 1024;

/// The most standard error pam keeps.
pub const MAX_STDERR_BYTES: u64 = 4 * 1024;

/// [`MAX_STDERR_BYTES`] as a length, for the excerpt helper.
fn stderr_excerpt_bytes() -> usize {
    usize::try_from(MAX_STDERR_BYTES).unwrap_or(usize::MAX)
}

/// The hard ceiling on one CLI call, whatever the step's deadline says.
pub const MAX_DURATION: Duration = Duration::from_secs(30);

#[cfg(any(test, feature = "testing"))]
thread_local! {
    /// The `aws` a test points this module at.
    ///
    /// Thread-local rather than global so two tests cannot overwrite each
    /// other's fake binary. `#[tokio::test]` runs on a current-thread
    /// runtime, so the child is spawned on the thread that set it.
    static BINARY_OVERRIDE: std::cell::RefCell<Option<PathBuf>> =
        const { std::cell::RefCell::new(None) };
}

/// Points this module at a stand-in for the `aws` binary.
///
/// Only tests call it: they write a script into a temporary directory and
/// name it here, rather than depending on a real AWS CLI being installed.
/// The override belongs to the calling thread.
#[cfg(any(test, feature = "testing"))]
pub fn set_binary_for_tests(path: PathBuf) {
    BINARY_OVERRIDE.with(|slot| *slot.borrow_mut() = Some(path));
}

/// Forgets a previous [`set_binary_for_tests`].
#[cfg(any(test, feature = "testing"))]
pub fn clear_binary_for_tests() {
    BINARY_OVERRIDE.with(|slot| *slot.borrow_mut() = None);
}

/// The `aws` executable on `PATH`, if there is one.
#[must_use]
pub fn aws_binary() -> Option<PathBuf> {
    #[cfg(any(test, feature = "testing"))]
    if let Some(path) = BINARY_OVERRIDE.with(|slot| slot.borrow().clone()) {
        return Some(path);
    }
    let name = if cfg!(windows) { "aws.exe" } else { "aws" };
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

/// Builds the argument vector for one allowlisted call.
///
/// The order is fixed: `service command args… [--profile P] --output json
/// --no-cli-pager`. pam's own flags come last so a step's arguments can
/// never be read as one of them.
pub fn argv(
    service: &str,
    command: &str,
    extra: &[String],
    profile: Option<&str>,
) -> Result<Vec<String>, ConnectorError> {
    if !ALLOWED.iter().any(|(allowed_service, allowed_command)| {
        *allowed_service == service && *allowed_command == command
    }) {
        return Err(ConnectorError::BadArgs(format!(
            "`aws {service} {command}` is not on pam's read-only allowlist; run the `commands` call to see what is"
        )));
    }
    check_args(extra)?;

    let mut line = Vec::with_capacity(extra.len() + 6);
    line.push(service.to_owned());
    line.push(command.to_owned());
    line.extend(extra.iter().cloned());
    if let Some(profile) = profile {
        check_profile(profile)?;
        line.push("--profile".to_owned());
        line.push(profile.to_owned());
    }
    line.push("--output".to_owned());
    line.push("json".to_owned());
    line.push("--no-cli-pager".to_owned());
    Ok(line)
}

/// Runs one AWS call.
pub(crate) async fn call(
    conn: &Connection,
    call: &str,
    args: &BTreeMap<String, ArgValue>,
    deadline: Instant,
) -> Result<CallResult, ConnectorError> {
    match call {
        "commands" => Ok(CallResult::Json(commands())),
        "cli" => Box::pin(cli(conn, args, deadline)).await,
        other => Err(unknown_call(ConnectorId::Aws, other)),
    }
}

/// `sts get-caller-identity` — who the local credentials belong to.
pub(crate) async fn verify(
    conn: &Connection,
    deadline: Instant,
) -> Result<VerifyReport, ConnectorError> {
    let line = argv("sts", "get-caller-identity", &[], conn.username.as_deref())?;
    let output = Box::pin(run(&line, deadline)).await?;
    if output.code != Some(0) {
        // A CLI that cannot authenticate exits non-zero; that is an
        // credential problem, not a bad argument.
        return Err(ConnectorError::Auth);
    }
    let identity: Value = serde_json::from_slice(&output.stdout).map_err(|error| {
        ConnectorError::BadResponse(format!("the aws CLI did not answer with JSON: {error}"))
    })?;
    let account = identity
        .get("Account")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ConnectorError::BadResponse("the aws CLI answered without an `Account`".to_owned())
        })?;
    let arn = identity.get("Arn").and_then(Value::as_str).ok_or_else(|| {
        ConnectorError::BadResponse("the aws CLI answered without an `Arn`".to_owned())
    })?;
    Ok(VerifyReport {
        detail: format!("account {account} arn {arn}"),
    })
}

/// The allowlist itself, so a flow author can read it without leaving pam.
fn commands() -> Value {
    let commands: Vec<Value> = ALLOWED
        .iter()
        .map(|(service, command)| json!({ "service": service, "command": command }))
        .collect();
    json!({ "commands": commands })
}

/// `aws <service> <command> …`, spawned without a shell.
async fn cli(
    conn: &Connection,
    args: &BTreeMap<String, ArgValue>,
    deadline: Instant,
) -> Result<CallResult, ConnectorError> {
    let service = crate::transport::text_arg(args, "service")?.to_owned();
    let command = crate::transport::text_arg(args, "command")?.to_owned();
    let extra = extra_args(args)?;
    let line = argv(&service, &command, &extra, conn.username.as_deref())?;
    let output = Box::pin(run(&line, deadline)).await?;

    let stderr = excerpt(&output.stderr, stderr_excerpt_bytes());
    if output.code != Some(0) {
        let code = output
            .code
            .map_or_else(|| "on a signal".to_owned(), |code| format!("{code}"));
        return Err(ConnectorError::Cli(format!(
            "`aws {service} {command}` exited {code}: {stderr}"
        )));
    }

    // A cut answer is not JSON any more, so it comes back as text with
    // `partial` set rather than as a half-parsed object.
    let parsed = if output.partial {
        None
    } else {
        serde_json::from_slice::<Value>(&output.stdout).ok()
    };
    let text = if parsed.is_some() {
        Value::Null
    } else {
        Value::String(String::from_utf8_lossy(&output.stdout).into_owned())
    };
    Ok(CallResult::Json(json!({
        "service": service,
        "command": command,
        "partial": output.partial,
        "exit_status": 0,
        "output": parsed,
        "text": text,
        "stderr": stderr,
    })))
}

/// What one CLI run produced.
struct Output {
    code: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    partial: bool,
}

/// Spawns the CLI, bounds it, and waits for it.
async fn run(line: &[String], deadline: Instant) -> Result<Output, ConnectorError> {
    let binary = aws_binary().ok_or(ConnectorError::CliMissing)?;
    let mut command = Command::new(&binary);
    command
        .args(line)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(ConnectorError::CliMissing);
        }
        Err(error) => {
            return Err(ConnectorError::Cli(format!(
                "the aws CLI could not start: {error}"
            )));
        }
    };

    let budget = deadline
        .saturating_duration_since(Instant::now())
        .min(MAX_DURATION)
        .max(Duration::from_secs(1));
    let mut stdout = child.stdout.take();
    let mut stderr = child.stderr.take();
    let collect = async {
        let ((stdout, partial), (stderr, _)) = tokio::join!(
            read_capped(&mut stdout, MAX_STDOUT_BYTES),
            read_capped(&mut stderr, MAX_STDERR_BYTES),
        );
        let status = child.wait().await;
        (stdout, partial, stderr, status)
    };

    match tokio::time::timeout(budget, Box::pin(collect)).await {
        Ok((stdout, partial, stderr, status)) => {
            let code = status
                .map_err(|error| {
                    ConnectorError::Cli(format!("the aws CLI could not be waited on: {error}"))
                })?
                .code();
            Ok(Output {
                code,
                stdout,
                stderr,
                partial,
            })
        }
        Err(_) => Err(ConnectorError::Timeout),
    }
}

/// The `args` argument: one string, split on ASCII whitespace.
///
/// There is no quoting. A flow that needs a value with a space in it is
/// asking for shell semantics, and this connector deliberately has none.
fn extra_args(args: &BTreeMap<String, ArgValue>) -> Result<Vec<String>, ConnectorError> {
    match args.get("args") {
        None => Ok(Vec::new()),
        Some(ArgValue::Text(raw)) => Ok(raw.split_ascii_whitespace().map(str::to_owned).collect()),
        Some(ArgValue::Int(_)) => Err(ConnectorError::BadArgs(
            "`args` must be text, not a number".to_owned(),
        )),
    }
}

/// Bounds and scrubs the extra arguments.
fn check_args(args: &[String]) -> Result<(), ConnectorError> {
    if args.len() > MAX_EXTRA_ARGS {
        return Err(ConnectorError::BadArgs(format!(
            "`args` carries {} arguments; at most {MAX_EXTRA_ARGS} are allowed",
            args.len()
        )));
    }
    for arg in args {
        if arg.is_empty() || arg.len() > MAX_ARG_BYTES {
            return Err(ConnectorError::BadArgs(format!(
                "each argument must be 1 to {MAX_ARG_BYTES} bytes"
            )));
        }
        if !arg.bytes().all(allowed_byte) {
            return Err(ConnectorError::BadArgs(format!(
                "`{arg}` carries a character the aws passthrough does not allow"
            )));
        }
        let lowered = arg.to_ascii_lowercase();
        if lowered.contains("file://") || lowered.contains("fileb://") {
            return Err(ConnectorError::BadArgs(
                "`file://` and `fileb://` make the CLI read local files; they are refused"
                    .to_owned(),
            ));
        }
        if let Some(flag) = FORBIDDEN_FLAGS
            .iter()
            .find(|flag| lowered == **flag || lowered.starts_with(&format!("{flag}=")))
        {
            return Err(ConnectorError::BadArgs(format!(
                "`{flag}` is set by pam and may not appear in `args`"
            )));
        }
    }
    Ok(())
}

/// Checks a profile name.
fn check_profile(profile: &str) -> Result<(), ConnectorError> {
    let ok = (1..=64).contains(&profile.len())
        && !profile.starts_with('-')
        && profile
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'));
    if !ok {
        return Err(ConnectorError::BadArgs(format!(
            "the AWS profile `{profile}` is not a profile name; open Pam → Settings → Connectors → AWS to fix it"
        )));
    }
    Ok(())
}

/// The bytes an extra argument may be built from.
///
/// Enough for filters, `JMESPath` queries and ARNs; never a NUL, a newline or
/// any other control character.
fn allowed_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'@' | b'_'
                | b','
                | b':'
                | b'='
                | b'+'
                | b'/'
                | b'.'
                | b'*'
                | b'?'
                | b'['
                | b']'
                | b'{'
                | b'}'
                | b'"'
                | b'\''
                | b'%'
                | b' '
                | b'-'
        )
}
