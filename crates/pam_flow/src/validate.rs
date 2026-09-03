//! Parsing and validation: YAML text in, a [`Flow`] or a legible refusal
//! out.
//!
//! Every rule the spec states lives here, and every violation is a
//! [`FlowError::Invalid`] naming the YAML path that broke it
//! (`steps[2].run[1]`), so the GUI can point at the line and an agent can
//! read the reason without guessing. Validation is also the crate's security
//! boundary: shells, path-shaped programs, credential-shaped arguments and
//! secret-looking strings are refused here, before anything reaches the
//! daemon's allowlist or a connector.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use thiserror::Error;

use crate::duration::parse_duration;
use crate::schema::{
    Action, Approval, ArgValue, ConnectorId, Effect, Flow, Input, RawFlow, RawRetry, RawStep,
    Retry, Role, SCHEMA_VERSION, Step, When,
};

/// Why a flow file was refused.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum FlowError {
    /// A rule was broken at `path` (a YAML path such as `steps[1].run[0]`).
    #[error("{path}: {message}")]
    Invalid {
        /// The YAML path of the offending value.
        path: String,
        /// What is wrong, in plain English.
        message: String,
    },
    /// The file is bigger than a flow is allowed to be.
    #[error("flow file is {actual} bytes; the limit is {maximum}")]
    TooLarge {
        /// The file's size.
        actual: usize,
        /// The limit.
        maximum: usize,
    },
    /// The library directory could not be read or written.
    #[error("{0}")]
    Io(String),
}

impl FlowError {
    fn invalid(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Invalid {
            path: path.into(),
            message: message.into(),
        }
    }
}

/// Programs a flow may never name: a shell, or a launcher that is one in
/// disguise.
pub const SHELLS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "fish",
    "dash",
    "pwsh",
    "powershell",
    "cmd",
    "cmd.exe",
    "env",
    "xargs",
    "sudo",
    "doas",
];

/// Longest flow id, step id or input name, in bytes.
pub const MAX_ID_BYTES: usize = 64;
/// Most steps in one flow.
pub const MAX_STEPS: usize = 64;
/// Most inputs in one flow.
pub const MAX_INPUTS: usize = 16;
/// Largest flow file, in bytes.
pub const MAX_FILE_BYTES: usize = 256 * 1024;
/// Longest flow name, in bytes.
pub const MAX_NAME_BYTES: usize = 120;
/// Longest flow description, in bytes.
pub const MAX_DESCRIPTION_BYTES: usize = 2 * 1024;
/// Most arguments after the program name.
pub const MAX_ARGS: usize = 64;
/// Longest single argument, in bytes.
pub const MAX_ARG_BYTES: usize = 4 * 1024;
/// Longest whole command line, in bytes.
pub const MAX_ARGV_BYTES: usize = 32 * 1024;
/// Step timeout when the YAML names none.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_mins(5);
/// Longest step timeout.
pub const MAX_TIMEOUT: Duration = Duration::from_hours(1);
/// Most attempts a step may make.
pub const MAX_RETRY_ATTEMPTS: u8 = 5;
/// Longest retry backoff.
pub const MAX_RETRY_BACKOFF: Duration = Duration::from_mins(1);
/// Most files the flow library directory may hold.
pub const MAX_LIBRARY_ENTRIES: usize = 256;

/// One read-only connector call and the arguments it takes.
///
/// `pam_connectors` mirrors this table; the two crates share it so they
/// cannot disagree about what a flow may ask for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallSpec {
    /// The call name as YAML spells it.
    pub name: &'static str,
    /// Argument names, paired with whether they are required.
    pub args: &'static [(&'static str, bool)],
    /// Whether the call answers with a log rather than JSON.
    pub yields_log: bool,
}

const GITHUB_CALLS: &[CallSpec] = &[
    CallSpec {
        name: "runs",
        args: &[("repo", true), ("status", false), ("limit", false)],
        yields_log: false,
    },
    CallSpec {
        name: "run",
        args: &[("repo", true), ("run_id", true)],
        yields_log: false,
    },
    CallSpec {
        name: "job_log",
        args: &[("repo", true), ("job_id", true)],
        yields_log: true,
    },
];

const JENKINS_CALLS: &[CallSpec] = &[
    CallSpec {
        name: "jobs",
        args: &[("limit", false)],
        yields_log: false,
    },
    CallSpec {
        name: "builds",
        args: &[("job", true), ("limit", false)],
        yields_log: false,
    },
    CallSpec {
        name: "console",
        args: &[("job", true), ("build", true)],
        yields_log: true,
    },
];

const SONARQUBE_CALLS: &[CallSpec] = &[
    CallSpec {
        name: "quality_gate",
        args: &[("project", true)],
        yields_log: false,
    },
    CallSpec {
        name: "issues",
        args: &[("project", true), ("limit", false)],
        yields_log: false,
    },
];

const JIRA_CALLS: &[CallSpec] = &[
    CallSpec {
        name: "search",
        args: &[("jql", true), ("limit", false)],
        yields_log: false,
    },
    CallSpec {
        name: "issue",
        args: &[("key", true)],
        yields_log: false,
    },
];

const CONFLUENCE_CALLS: &[CallSpec] = &[
    CallSpec {
        name: "search",
        args: &[("cql", true), ("limit", false)],
        yields_log: false,
    },
    CallSpec {
        name: "page",
        args: &[("id", true)],
        yields_log: false,
    },
];

const SHAREPOINT_CALLS: &[CallSpec] = &[
    CallSpec {
        name: "documents",
        args: &[("site", true), ("query", true), ("limit", false)],
        yields_log: false,
    },
    CallSpec {
        name: "lists",
        args: &[("site", true), ("limit", false)],
        yields_log: false,
    },
];

const AWS_CALLS: &[CallSpec] = &[
    CallSpec {
        name: "commands",
        args: &[],
        yields_log: false,
    },
    CallSpec {
        name: "cli",
        args: &[("service", true), ("command", true), ("args", false)],
        yields_log: false,
    },
];

/// The read-only calls a connector offers.
#[must_use]
pub fn connector_calls(id: ConnectorId) -> &'static [CallSpec] {
    match id {
        ConnectorId::Github => GITHUB_CALLS,
        ConnectorId::Jenkins => JENKINS_CALLS,
        ConnectorId::Sonarqube => SONARQUBE_CALLS,
        ConnectorId::Jira => JIRA_CALLS,
        ConnectorId::Confluence => CONFLUENCE_CALLS,
        ConnectorId::Sharepoint => SHAREPOINT_CALLS,
        ConnectorId::Aws => AWS_CALLS,
    }
}

/// Whether a program name is a shell or a launcher that hides one.
///
/// Matching is exact and case-insensitive, with a trailing `.exe` stripped,
/// so `CMD.EXE` and `cmd` are the same refusal and `bashful` is not one.
#[must_use]
pub fn is_shell(program: &str) -> bool {
    let lowered = program.to_ascii_lowercase();
    let stem = lowered.strip_suffix(".exe").unwrap_or(&lowered);
    SHELLS
        .iter()
        .any(|shell| shell.strip_suffix(".exe").unwrap_or(shell) == stem)
}

/// Whether a value looks like a credential a human pasted into a flow file.
///
/// Recognizes GitHub tokens, AWS access key ids, JWTs, `Bearer …` headers
/// and URLs carrying userinfo. It errs towards refusing: a flow file is
/// world-readable in the library and lands in evidence, so the fix is always
/// to move the value into the connector's credential.
#[must_use]
pub fn looks_secret_like(value: &str) -> bool {
    const GITHUB_PREFIXES: [&str; 6] = ["ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"];
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return false;
    }
    if GITHUB_PREFIXES
        .iter()
        .any(|prefix| trimmed.contains(prefix))
    {
        return true;
    }
    if has_aws_key_id(trimmed) || has_jwt(trimmed) || has_bearer(trimmed) {
        return true;
    }
    has_url_userinfo(trimmed)
}

/// `AKIA`/`ASIA` followed by sixteen upper-case alphanumerics.
fn has_aws_key_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.windows(20).any(|window| {
        (window.starts_with(b"AKIA") || window.starts_with(b"ASIA"))
            && window[4..]
                .iter()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    })
}

/// Two or more dot-separated base64url segments starting with `eyJ`.
fn has_jwt(value: &str) -> bool {
    value
        .split('.')
        .filter(|segment| segment.starts_with("eyJ"))
        .count()
        >= 2
}

/// `Bearer <something>`, however it is cased.
fn has_bearer(value: &str) -> bool {
    let lowered = value.to_ascii_lowercase();
    lowered
        .match_indices("bearer ")
        .any(|(at, _)| lowered[at + "bearer ".len()..].starts_with(|c: char| !c.is_whitespace()))
}

/// A URL whose authority carries `user@` or `user:password@`.
fn has_url_userinfo(value: &str) -> bool {
    let Some(after) = value.split("://").nth(1) else {
        return false;
    };
    let authority_end = after.find(['/', '?', '#']).unwrap_or(after.len());
    after[..authority_end].contains('@')
}

/// Whether an argument names a credential (`--token`, `--password=…`).
#[must_use]
pub fn is_sensitive_arg(arg: &str) -> bool {
    const SENSITIVE: [&str; 4] = ["--token", "--password", "--secret", "--api-key"];
    let name = arg.split('=').next().unwrap_or(arg).trim();
    SENSITIVE
        .iter()
        .any(|sensitive| name.eq_ignore_ascii_case(sensitive))
}

/// Reads a flow file and validates every rule in the schema.
///
/// # Errors
///
/// [`FlowError::TooLarge`] when the text is over [`MAX_FILE_BYTES`], and
/// [`FlowError::Invalid`] — naming the YAML path — for a malformed document
/// or any broken rule.
pub fn parse(yaml: &str) -> Result<Flow, FlowError> {
    if yaml.len() > MAX_FILE_BYTES {
        return Err(FlowError::TooLarge {
            actual: yaml.len(),
            maximum: MAX_FILE_BYTES,
        });
    }
    let raw: RawFlow = serde_yaml_ng::from_str(yaml).map_err(|error| from_yaml_error(&error))?;
    validate(raw)
}

/// [`parse`] for a flow already in memory as JSON in the file's own shape
/// (`run` / `connector` / `call` / `with`, …) — what the designer canvas
/// sends back. Same rules, same paths, no disk.
///
/// The value is rendered to YAML and handed to [`parse`], so both entry
/// points report identical paths (`serde_json` errors carry none) and the
/// size cap applies to the rendered text.
///
/// # Errors
///
/// As [`parse`]; a value YAML cannot render is `Invalid` at `yaml`.
pub fn parse_value(raw: &serde_json::Value) -> Result<Flow, FlowError> {
    let text = serde_yaml_ng::to_string(raw)
        .map_err(|error| FlowError::invalid("yaml", error.to_string()))?;
    parse(&text)
}

/// Turns a serde error into an `Invalid` error, keeping the path serde
/// already worked out (`steps[1].when: invalid type: map`).
fn from_yaml_error(error: &serde_yaml_ng::Error) -> FlowError {
    let text = error.to_string();
    if let Some((head, rest)) = text.split_once(": ")
        && !head.is_empty()
        && head
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-[]".contains(c))
    {
        return FlowError::invalid(head, rest);
    }
    FlowError::invalid("yaml", text)
}

fn validate(raw: RawFlow) -> Result<Flow, FlowError> {
    if raw.schema != SCHEMA_VERSION {
        return Err(FlowError::invalid(
            "schema",
            format!(
                "flow schema {} is not supported; this pam reads schema {SCHEMA_VERSION}",
                raw.schema
            ),
        ));
    }
    check_id(&raw.id, "id", "a flow id")?;
    if raw.name.trim().is_empty() {
        return Err(FlowError::invalid("name", "a flow needs a name"));
    }
    check_length("name", raw.name.len(), MAX_NAME_BYTES)?;
    check_length("description", raw.description.len(), MAX_DESCRIPTION_BYTES)?;

    if raw.inputs.len() > MAX_INPUTS {
        return Err(FlowError::invalid(
            "inputs",
            format!(
                "the flow declares {} inputs; the limit is {MAX_INPUTS}",
                raw.inputs.len()
            ),
        ));
    }
    let mut inputs = BTreeMap::new();
    for (name, raw_input) in raw.inputs {
        check_input_name(&name)?;
        if let Some(default) = &raw_input.default {
            let path = format!("inputs.{name}.default");
            check_secrets(default, &path)?;
            check_references(default, &path, &Scope::default())?;
        }
        inputs.insert(
            name,
            Input {
                description: raw_input.description,
                default: raw_input.default,
            },
        );
    }

    if raw.steps.is_empty() {
        return Err(FlowError::invalid(
            "steps",
            "a flow needs at least one step",
        ));
    }
    if raw.steps.len() > MAX_STEPS {
        return Err(FlowError::invalid(
            "steps",
            format!(
                "the flow has {} steps; the limit is {MAX_STEPS}",
                raw.steps.len()
            ),
        ));
    }

    let mut scope = Scope {
        inputs: inputs.keys().cloned().collect(),
        earlier: BTreeSet::new(),
    };
    let mut steps = Vec::with_capacity(raw.steps.len());
    for (index, raw_step) in raw.steps.into_iter().enumerate() {
        let step = validate_step(raw_step, index, &scope)?;
        scope.earlier.insert(step.id.clone());
        steps.push(step);
    }

    Ok(Flow {
        id: raw.id,
        name: raw.name,
        description: raw.description,
        inputs,
        steps,
    })
}

/// What `${…}` may name at this point in the file.
#[derive(Debug, Default)]
struct Scope {
    inputs: BTreeSet<String>,
    earlier: BTreeSet<String>,
}

fn validate_step(raw: RawStep, index: usize, scope: &Scope) -> Result<Step, FlowError> {
    let at = format!("steps[{index}]");
    check_id(&raw.id, &format!("{at}.id"), "a step id")?;
    if scope.earlier.contains(&raw.id) {
        return Err(FlowError::invalid(
            format!("{at}.id"),
            format!("duplicate step id `{}`", raw.id),
        ));
    }

    let action = match (raw.run, raw.connector) {
        (Some(_), Some(_)) => {
            return Err(FlowError::invalid(
                &at,
                "a step is either `run` or `connector`, never both",
            ));
        }
        (None, None) => {
            return Err(FlowError::invalid(
                &at,
                "a step needs `run` (a command) or `connector` (a connector call)",
            ));
        }
        (Some(argv), None) => {
            if raw.call.is_some() {
                return Err(FlowError::invalid(
                    format!("{at}.call"),
                    "`call` belongs to a connector step",
                ));
            }
            if raw.with.is_some() {
                return Err(FlowError::invalid(
                    format!("{at}.with"),
                    "`with` belongs to a connector step",
                ));
            }
            validate_command(&argv, &at, scope)?;
            Action::Command { argv }
        }
        (None, Some(connector)) => {
            if raw.env.is_some() {
                return Err(FlowError::invalid(
                    format!("{at}.env"),
                    "`env` belongs to a command step",
                ));
            }
            validate_connector(&connector, raw.call.as_deref(), raw.with, &at, scope)?
        }
    };

    let timeout = validate_timeout(raw.timeout.as_deref(), &at)?;

    let effect = raw.effect.unwrap_or_default();
    let role = raw.role.unwrap_or_else(|| Role::default_for(effect));
    if role == Role::Verify && effect == Effect::Stateful {
        return Err(FlowError::invalid(
            format!("{at}.role"),
            "a `verify` step is read-only; drop `effect: stateful` or use `role: change`",
        ));
    }
    let approval = if effect == Effect::Stateful {
        Approval::Required
    } else {
        raw.approval.unwrap_or_default()
    };

    let needs = raw.needs.unwrap_or_default();
    for (position, name) in needs.iter().enumerate() {
        if !scope.earlier.contains(name) {
            return Err(FlowError::invalid(
                format!("{at}.needs[{position}]"),
                format!("`needs` names `{name}`, which is not an earlier step"),
            ));
        }
    }

    let when = raw.when.unwrap_or_default();
    if let When::Succeeded(name) | When::Failed(name) = &when
        && !scope.earlier.contains(name)
    {
        return Err(FlowError::invalid(
            format!("{at}.when"),
            format!("`when` names `{name}`, which is not an earlier step"),
        ));
    }

    let retry = validate_retry(raw.retry, &at)?;

    let env = raw.env.unwrap_or_default();
    validate_env(&env, &at, scope)?;

    Ok(Step {
        id: raw.id,
        action,
        timeout,
        effect,
        role,
        output: raw.output.unwrap_or_default(),
        needs,
        when,
        retry,
        approval,
        env,
    })
}

fn validate_timeout(timeout: Option<&str>, at: &str) -> Result<Duration, FlowError> {
    let Some(text) = timeout else {
        return Ok(DEFAULT_TIMEOUT);
    };
    let path = format!("{at}.timeout");
    let value = parse_duration(text).map_err(|err| FlowError::invalid(&path, err.to_string()))?;
    if value.is_zero() {
        return Err(FlowError::invalid(&path, "the timeout must be above zero"));
    }
    if value > MAX_TIMEOUT {
        return Err(FlowError::invalid(
            &path,
            "the timeout is above the 1h limit",
        ));
    }
    Ok(value)
}

fn validate_retry(retry: Option<RawRetry>, at: &str) -> Result<Retry, FlowError> {
    let Some(raw) = retry else {
        return Ok(Retry::default());
    };
    if raw.attempts == 0 || raw.attempts > MAX_RETRY_ATTEMPTS {
        return Err(FlowError::invalid(
            format!("{at}.retry.attempts"),
            format!("attempts must be between 1 and {MAX_RETRY_ATTEMPTS}"),
        ));
    }
    let backoff = match raw.backoff {
        None => Retry::default().backoff,
        Some(text) => {
            let path = format!("{at}.retry.backoff");
            let value =
                parse_duration(&text).map_err(|err| FlowError::invalid(&path, err.to_string()))?;
            if value > MAX_RETRY_BACKOFF {
                return Err(FlowError::invalid(
                    &path,
                    "the backoff is above the 60s limit",
                ));
            }
            value
        }
    };
    Ok(Retry {
        attempts: raw.attempts,
        backoff,
    })
}

fn validate_env(env: &BTreeMap<String, String>, at: &str, scope: &Scope) -> Result<(), FlowError> {
    for (name, value) in env {
        let path = format!("{at}.env.{name}");
        if !is_env_name(name) {
            return Err(FlowError::invalid(
                &path,
                "an environment name is upper-case letters, digits and `_`, and never starts with a digit",
            ));
        }
        check_secrets(value, &path)?;
        check_references(value, &path, scope)?;
    }
    Ok(())
}

fn validate_command(argv: &[String], at: &str, scope: &Scope) -> Result<(), FlowError> {
    let Some(program) = argv.first() else {
        return Err(FlowError::invalid(
            format!("{at}.run"),
            "`run` needs a program name",
        ));
    };
    let program_path = format!("{at}.run[0]");
    if !is_program_name(program) {
        return Err(FlowError::invalid(
            &program_path,
            format!(
                "`{program}` is not a bare program name; flows name the program and pam resolves it on PATH"
            ),
        ));
    }
    if is_shell(program) {
        return Err(FlowError::invalid(
            &program_path,
            format!("`{program}` is a shell and is refused; name the program itself"),
        ));
    }
    if argv.len() - 1 > MAX_ARGS {
        return Err(FlowError::invalid(
            format!("{at}.run"),
            format!(
                "the step passes {} arguments; the limit is {MAX_ARGS}",
                argv.len() - 1
            ),
        ));
    }
    let total: usize = argv.iter().map(String::len).sum();
    if total > MAX_ARGV_BYTES {
        return Err(FlowError::invalid(
            format!("{at}.run"),
            format!("the command line is {total} bytes; the limit is {MAX_ARGV_BYTES}"),
        ));
    }
    for (position, arg) in argv.iter().enumerate().skip(1) {
        let path = format!("{at}.run[{position}]");
        if arg.len() > MAX_ARG_BYTES {
            return Err(FlowError::invalid(
                &path,
                format!(
                    "the argument is {} bytes; the limit is {MAX_ARG_BYTES}",
                    arg.len()
                ),
            ));
        }
        if is_sensitive_arg(arg) {
            return Err(FlowError::invalid(
                &path,
                format!(
                    "`{arg}` passes a credential on the command line; flows never carry secrets"
                ),
            ));
        }
        check_secrets(arg, &path)?;
        check_references(arg, &path, scope)?;
    }
    Ok(())
}

fn validate_connector(
    connector: &str,
    call: Option<&str>,
    with: Option<BTreeMap<String, ArgValue>>,
    at: &str,
    scope: &Scope,
) -> Result<Action, FlowError> {
    let Some(id) = ConnectorId::parse(connector) else {
        return Err(FlowError::invalid(
            format!("{at}.connector"),
            format!(
                "unknown connector `{connector}`; pam knows {}",
                names(&ConnectorId::ALL.map(ConnectorId::as_str))
            ),
        ));
    };
    let calls = connector_calls(id);
    let call_path = format!("{at}.call");
    let Some(call) = call else {
        return Err(FlowError::invalid(
            &call_path,
            format!(
                "a `{connector}` step needs a `call`; it offers {}",
                names(&calls.iter().map(|spec| spec.name).collect::<Vec<_>>())
            ),
        ));
    };
    let Some(spec) = calls.iter().find(|spec| spec.name == call) else {
        return Err(FlowError::invalid(
            &call_path,
            format!(
                "`{connector}` has no call `{call}`; it offers {}",
                names(&calls.iter().map(|spec| spec.name).collect::<Vec<_>>())
            ),
        ));
    };

    let with = with.unwrap_or_default();
    let with_path = format!("{at}.with");
    for (name, value) in &with {
        let path = format!("{with_path}.{name}");
        if !spec.args.iter().any(|(arg, _)| *arg == name) {
            return Err(FlowError::invalid(
                &path,
                format!(
                    "`{connector}` call `{call}` takes no argument `{name}`; it takes {}",
                    names(&spec.args.iter().map(|(arg, _)| *arg).collect::<Vec<_>>())
                ),
            ));
        }
        if let ArgValue::Text(text) = value {
            check_secrets(text, &path)?;
            check_references(text, &path, scope)?;
        }
    }
    for (name, required) in spec.args {
        if *required && !with.contains_key(*name) {
            return Err(FlowError::invalid(
                &with_path,
                format!("`{connector}` call `{call}` needs the argument `{name}`"),
            ));
        }
    }

    Ok(Action::Connector {
        connector: id,
        call: call.to_string(),
        with,
    })
}

/// `a, b and c` — the tail of a "it offers …" message.
fn names(items: &[&str]) -> String {
    items.join(", ")
}

fn check_length(path: &str, actual: usize, maximum: usize) -> Result<(), FlowError> {
    if actual > maximum {
        return Err(FlowError::invalid(
            path,
            format!("the value is {actual} bytes; the limit is {maximum}"),
        ));
    }
    Ok(())
}

fn check_id(id: &str, path: &str, what: &str) -> Result<(), FlowError> {
    let valid = !id.is_empty()
        && id.len() <= MAX_ID_BYTES
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if valid {
        return Ok(());
    }
    Err(FlowError::invalid(
        path,
        format!(
            "`{id}` is not {what}: lower-case letters, digits and `-`, 1 to {MAX_ID_BYTES} bytes"
        ),
    ))
}

fn check_input_name(name: &str) -> Result<(), FlowError> {
    let valid = !name.is_empty()
        && name.len() <= MAX_ID_BYTES
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_');
    if valid {
        return Ok(());
    }
    Err(FlowError::invalid(
        format!("inputs.{name}"),
        format!(
            "`{name}` is not an input name: lower-case letters, digits, `-` and `_`, 1 to {MAX_ID_BYTES} bytes"
        ),
    ))
}

fn is_program_name(program: &str) -> bool {
    let mut chars = program.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_alphanumeric()
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-'))
}

fn is_env_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_uppercase() || first == '_')
        && chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

fn check_secrets(value: &str, path: &str) -> Result<(), FlowError> {
    if looks_secret_like(value) {
        return Err(FlowError::invalid(
            path,
            "the value looks like a secret; flows never carry credentials — configure the connector in Pam → Settings → Connectors instead",
        ));
    }
    Ok(())
}

/// Rejects any `${…}` the flow could never fill in.
fn check_references(text: &str, path: &str, scope: &Scope) -> Result<(), FlowError> {
    for key in crate::vars::references(text) {
        if is_known_reference(&key, scope) {
            continue;
        }
        return Err(FlowError::invalid(
            path,
            format!("unknown variable `${{{key}}}`"),
        ));
    }
    Ok(())
}

fn is_known_reference(key: &str, scope: &Scope) -> bool {
    if matches!(key, "repo.path" | "repo.name" | "repo.origin") {
        return true;
    }
    if let Some(name) = key.strip_prefix("inputs.") {
        return scope.inputs.contains(name);
    }
    let Some(rest) = key.strip_prefix("steps.") else {
        return false;
    };
    let Some((id, tail)) = rest.split_once('.') else {
        return false;
    };
    scope.earlier.contains(id)
        && (tail == "exit_status" || tail == "result" || tail.starts_with("result."))
}
