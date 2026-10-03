//! The reference sandbox profiles behind `pam doctor --profile`.
//!
//! The text lives in `docs/sandbox/` (one file per harness, each opening with a
//! preamble that names its sources, the date it was verified, what it allows,
//! what it denies and the `pam doctor` run that proves it) and is embedded here
//! with `include_str!`, so the binary prints exactly what the repository ships.
//! A template names PAM's base directory with the placeholder `<base>`;
//! [`render`] replaces it with the real path, escaped for the format the
//! placeholder sits in (a quoted Seatbelt, JSON or TOML string), so a base with
//! a space, a quote or a backslash cannot break out of the string it lands in.
//!
//! PAM does not install, edit or lock a harness's sandbox: these are fragments
//! a human (or MDM) puts in the harness's own configuration. `pam doctor`, run
//! from inside the harness, is the evidence that the harness enforced them.
//! Rendering is a pure function of the base path: nothing here touches the
//! filesystem or the daemon.
//!
//! Every template keeps one invariant: allow the literal public socket
//! `<base>/run/pam.sock` (and read of `<base>/run/daemon.lock`), deny the rest
//! of the base, including the engine runtime inside `run`
//! (`<base>/run/engine.sock`, `<base>/run/engine/`), the keychain, process
//! control of the daemon, the launch brokers, and writes to the trusted
//! executable and bundle, wherever the harness has a setting for it.

use std::fmt;
use std::path::Path;

use pam_proto::caller::KNOWN_AGENTS;

/// The placeholder every template uses for PAM's base directory.
pub const BASE_PLACEHOLDER: &str = "<base>";

/// Characters that are pattern syntax in the JSON and TOML harness
/// configurations (their path entries are globs) or delimit a permission rule.
/// A base containing one cannot be written there without guessing an escape
/// the harness does not document, so rendering refuses it.
const PATTERN_CHARS: [char; 8] = ['*', '?', '[', ']', '{', '}', '(', ')'];

/// A harness a reference profile exists for. The names match the agents
/// `pam_proto::caller::KNOWN_AGENTS` recognises where the harness is one of
/// them (see [`Harness::agent`]); [`Harness::SandboxExec`] is the harness-less
/// fallback and covers every other agent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Harness {
    ClaudeCode,
    Codex,
    GeminiCli,
    CopilotCli,
    SandboxExec,
}

impl Harness {
    /// Every harness, in the order `pam doctor --profile` documents them.
    pub const ALL: [Harness; 5] = [
        Harness::ClaudeCode,
        Harness::Codex,
        Harness::GeminiCli,
        Harness::CopilotCli,
        Harness::SandboxExec,
    ];

    /// The name `pam doctor --profile <name>` takes.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Harness::ClaudeCode => "claude-code",
            Harness::Codex => "codex",
            Harness::GeminiCli => "gemini-cli",
            Harness::CopilotCli => "copilot-cli",
            Harness::SandboxExec => "sandbox-exec",
        }
    }

    /// The canonical `KNOWN_AGENTS` name a caller running under this harness
    /// reports (`claude`, `codex`, `gemini`, `copilot`), or `None` for the
    /// `sandbox-exec` fallback, which is not an agent.
    #[must_use]
    pub const fn agent(self) -> Option<&'static str> {
        match self {
            Harness::ClaudeCode => Some("claude"),
            Harness::Codex => Some("codex"),
            Harness::GeminiCli => Some("gemini"),
            Harness::CopilotCli => Some("copilot"),
            Harness::SandboxExec => None,
        }
    }

    /// Parses a harness from its `--profile` name or from a `KNOWN_AGENTS`
    /// name (case-insensitive, exact). Agents without a configuration format of
    /// their own (`cursor`, `aider`) resolve to the `sandbox-exec` fallback.
    #[must_use]
    pub fn parse(text: &str) -> Option<Harness> {
        match text.to_ascii_lowercase().as_str() {
            "claude-code" | "claude" => Some(Harness::ClaudeCode),
            "codex" => Some(Harness::Codex),
            "gemini-cli" | "gemini" => Some(Harness::GeminiCli),
            "copilot-cli" | "copilot" | "github-copilot" => Some(Harness::CopilotCli),
            "sandbox-exec" | "cursor" | "aider" => Some(Harness::SandboxExec),
            _ => None,
        }
    }

    /// The names `--profile` accepts, for a usage line.
    #[must_use]
    pub fn names() -> String {
        Harness::ALL.map(Harness::name).join("|")
    }

    /// The embedded profile for this harness.
    #[must_use]
    pub fn profile(self) -> &'static Profile {
        &PROFILES[self as usize]
    }
}

impl fmt::Display for Harness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The syntax of a profile file, which decides how the base path is escaped and
/// what a comment looks like.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    /// A Seatbelt profile (`.sb`): quoted strings, `;` comments.
    Sbpl,
    /// A JSON settings fragment: quoted strings, no comments.
    Json,
    /// A TOML configuration fragment: quoted strings, `#` comments.
    Toml,
    /// Markdown prose: the base is substituted as plain text.
    Markdown,
}

impl Format {
    /// The prefix that makes a line a comment, if the format has comments.
    const fn comment_prefix(self) -> Option<char> {
        match self {
            Format::Sbpl => Some(';'),
            Format::Toml => Some('#'),
            Format::Json | Format::Markdown => None,
        }
    }

    /// Whether the placeholder sits inside a quoted string that needs escaping.
    const fn quotes(self) -> bool {
        !matches!(self, Format::Markdown)
    }

    /// Whether path entries are patterns, so pattern characters in the base are
    /// refused.
    const fn pattern_paths(self) -> bool {
        matches!(self, Format::Json | Format::Toml)
    }
}

/// Which variant of a harness's profile to render.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Variant {
    /// The fragment a user merges into their own configuration.
    Standard,
    /// The administrator fragment: the standard one plus the locks that stop a
    /// developer widening it. Only Claude Code has one.
    Managed,
}

/// One embedded profile: where it lives under `docs/sandbox/`, what it is, and
/// its text.
#[derive(Debug)]
pub struct Profile {
    pub harness: Harness,
    /// The file under `docs/sandbox/` that `render` prints.
    pub file: &'static str,
    pub format: Format,
    /// The managed variant's file, when the harness has one.
    pub managed_file: Option<&'static str>,
    /// A prose file beside the fragment, for formats that cannot carry a
    /// preamble themselves (JSON).
    pub guide_file: Option<&'static str>,
    template: &'static str,
    managed_template: Option<&'static str>,
    guide: Option<&'static str>,
}

impl Profile {
    /// The raw template text of a variant, `<base>` unsubstituted.
    #[must_use]
    pub fn template(&self, variant: Variant) -> Option<&'static str> {
        match variant {
            Variant::Standard => Some(self.template),
            Variant::Managed => self.managed_template,
        }
    }

    /// The raw guide text, `<base>` unsubstituted.
    #[must_use]
    pub fn guide(&self) -> Option<&'static str> {
        self.guide
    }

    /// The text that carries the preamble: the guide where the fragment is JSON
    /// (no comments), the fragment itself otherwise.
    #[must_use]
    pub fn preamble_source(&self) -> &'static str {
        self.guide.unwrap_or(self.template)
    }
}

/// Indexed by `Harness as usize`: the order of [`Harness::ALL`].
static PROFILES: [Profile; 5] = [
    Profile {
        harness: Harness::ClaudeCode,
        file: "macos/claude-code.settings.json",
        format: Format::Json,
        managed_file: Some("macos/claude-code.managed-settings.json"),
        guide_file: Some("macos/claude-code.md"),
        template: include_str!("../../../../docs/sandbox/macos/claude-code.settings.json"),
        managed_template: Some(include_str!(
            "../../../../docs/sandbox/macos/claude-code.managed-settings.json"
        )),
        guide: Some(include_str!(
            "../../../../docs/sandbox/macos/claude-code.md"
        )),
    },
    Profile {
        harness: Harness::Codex,
        file: "macos/codex.config.toml",
        format: Format::Toml,
        managed_file: None,
        guide_file: None,
        template: include_str!("../../../../docs/sandbox/macos/codex.config.toml"),
        managed_template: None,
        guide: None,
    },
    Profile {
        harness: Harness::GeminiCli,
        file: "macos/gemini-cli.sandbox-macos-pam.sb",
        format: Format::Sbpl,
        managed_file: None,
        guide_file: None,
        template: include_str!("../../../../docs/sandbox/macos/gemini-cli.sandbox-macos-pam.sb"),
        managed_template: None,
        guide: None,
    },
    Profile {
        harness: Harness::CopilotCli,
        file: "macos/copilot-cli.md",
        format: Format::Markdown,
        managed_file: None,
        guide_file: None,
        template: include_str!("../../../../docs/sandbox/macos/copilot-cli.md"),
        managed_template: None,
        guide: None,
    },
    Profile {
        harness: Harness::SandboxExec,
        file: "macos/pam-agent.sb",
        format: Format::Sbpl,
        managed_file: None,
        guide_file: None,
        template: include_str!("../../../../docs/sandbox/macos/pam-agent.sb"),
        managed_template: None,
        guide: None,
    },
];

/// Every embedded profile, in [`Harness::ALL`] order.
#[must_use]
pub fn list() -> &'static [Profile] {
    &PROFILES
}

/// Why a profile could not be rendered. Each message names the cause and what
/// to do, in the style of the CLI's other refusals.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RenderError {
    /// The base is not an absolute POSIX path (`/Users/me/.pam`). The profiles
    /// are for macOS, where Seatbelt and the harnesses match resolved paths.
    NotAbsolute,
    /// The base is not valid UTF-8, so no text format can carry it.
    NotUtf8,
    /// The base is `/` or has an empty, `.` or `..` component: a rule written
    /// from it would not match the path the OS resolves.
    NotNormal,
    /// The base contains a control character, which no format can carry safely.
    ControlCharacter,
    /// The base contains a character that is pattern syntax in this harness's
    /// configuration.
    PatternCharacter { harness: Harness, character: char },
    /// The harness has no managed variant.
    NoManagedVariant(Harness),
}

impl fmt::Display for RenderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RenderError::NotAbsolute => f.write_str(
                "the base directory is not an absolute path: pass `--base /Users/<you>/.pam` \
                 (the profiles are for macOS)",
            ),
            RenderError::NotUtf8 => f.write_str(
                "the base directory is not valid UTF-8: choose a base whose path is plain text",
            ),
            RenderError::NotNormal => f.write_str(
                "the base directory has an empty, `.` or `..` component or is `/`: pass the \
                 resolved path (`realpath ~/.pam`)",
            ),
            RenderError::ControlCharacter => f.write_str(
                "the base directory contains a control character: choose a base without one",
            ),
            RenderError::PatternCharacter { harness, character } => write!(
                f,
                "the base directory contains {character:?}, which is pattern syntax in the {harness} \
                 configuration and has no documented escape: choose a base without it, or use \
                 `--profile sandbox-exec`"
            ),
            RenderError::NoManagedVariant(harness) => write!(
                f,
                "{harness} has no managed variant: drop `--managed`, or use `--profile claude-code`"
            ),
        }
    }
}

impl std::error::Error for RenderError {}

/// Renders the standard profile for `harness` with `<base>` replaced by `base`.
///
/// # Errors
///
/// See [`RenderError`]: the base must be an absolute, normalised POSIX path
/// without control characters (and, for the JSON and TOML formats, without
/// pattern characters).
pub fn render(harness: Harness, base: &Path) -> Result<String, RenderError> {
    render_variant(harness, Variant::Standard, base)
}

/// Renders one variant of the profile for `harness`.
///
/// # Errors
///
/// As [`render`], plus [`RenderError::NoManagedVariant`] when `variant` is
/// [`Variant::Managed`] and the harness has none.
pub fn render_variant(
    harness: Harness,
    variant: Variant,
    base: &Path,
) -> Result<String, RenderError> {
    let profile = harness.profile();
    let template = profile
        .template(variant)
        .ok_or(RenderError::NoManagedVariant(harness))?;
    let base = normalise_base(base)?;
    check_pattern_chars(harness, profile.format, &base)?;
    Ok(substitute(template, profile.format, &base))
}

/// Renders the guide that accompanies a JSON fragment (`None` when the harness
/// has none).
///
/// # Errors
///
/// As [`render`].
pub fn render_guide(harness: Harness, base: &Path) -> Result<Option<String>, RenderError> {
    let profile = harness.profile();
    let Some(guide) = profile.guide() else {
        return Ok(None);
    };
    let base = normalise_base(base)?;
    Ok(Some(substitute(guide, Format::Markdown, &base)))
}

/// The base as a plain POSIX path string without a trailing slash.
fn normalise_base(base: &Path) -> Result<String, RenderError> {
    let text = base.to_str().ok_or(RenderError::NotUtf8)?;
    if !text.starts_with('/') {
        return Err(RenderError::NotAbsolute);
    }
    if text.chars().any(char::is_control) {
        return Err(RenderError::ControlCharacter);
    }
    let text = text.strip_suffix('/').unwrap_or(text);
    if text.is_empty()
        || text[1..]
            .split('/')
            .any(|part| matches!(part, "" | "." | ".."))
    {
        return Err(RenderError::NotNormal);
    }
    Ok(text.to_owned())
}

fn check_pattern_chars(harness: Harness, format: Format, base: &str) -> Result<(), RenderError> {
    if !format.pattern_paths() {
        return Ok(());
    }
    match base.chars().find(|ch| PATTERN_CHARS.contains(ch)) {
        Some(character) => Err(RenderError::PatternCharacter { harness, character }),
        None => Ok(()),
    }
}

/// Replaces every `<base>` in `template`. A comment line takes the raw path (it
/// is prose, and the base has no control characters, so it cannot end the
/// line); anywhere else the placeholder sits inside a quoted string and takes
/// the escaped path. One pass: a base that itself contains `<base>` is not
/// expanded again.
fn substitute(template: &str, format: Format, base: &str) -> String {
    let escaped = if format.quotes() {
        escape_quoted(base)
    } else {
        base.to_owned()
    };
    let mut out = String::with_capacity(template.len() + 256);
    for line in template.split_inclusive('\n') {
        let comment = format
            .comment_prefix()
            .is_some_and(|prefix| line.trim_start().starts_with(prefix));
        let value = if comment { base } else { &escaped };
        out.push_str(&line.replace(BASE_PLACEHOLDER, value));
    }
    out
}

/// Escapes the contents of a double-quoted Seatbelt, JSON or TOML string: the
/// backslash and the quote are the only characters that can end the string or
/// change what follows. Control characters were refused earlier.
fn escape_quoted(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        if matches!(ch, '\\' | '"') {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

/// A `KNOWN_AGENTS` canonical name's harness: the profile a caller reported as
/// that agent would be given. `None` for a name that is not a known agent.
#[must_use]
pub fn harness_for_agent(agent: &str) -> Option<Harness> {
    KNOWN_AGENTS
        .iter()
        .find(|(_, canonical)| *canonical == agent)
        .and_then(|(_, canonical)| Harness::parse(canonical))
}

// Declared here, not from `doctor/mod.rs`: the tests reach the private items of this module
// through `super`.
#[cfg(test)]
#[path = "profiles_test.rs"]
mod profiles_test;
