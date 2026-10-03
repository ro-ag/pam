use std::path::Path;

use pam_proto::caller::KNOWN_AGENTS;
use pam_proto::doctor::{INVENTORY, Platform, ProbeClass, ProbeId};

use super::{
    BASE_PLACEHOLDER, Format, Harness, Profile, RenderError, Variant, WINDOWS_STATEMENT,
    harness_for_agent, list, render, render_guide, render_variant,
};

const BASE: &str = "/Users/tester/.pam";
/// A base a careless renderer would break on: a space, quotes and a backslash.
const AWKWARD_BASE: &str = "/Users/te ster/\"q\"/a\\b/.pam";

fn all_variants() -> Vec<(Harness, Variant, &'static str)> {
    let mut variants = Vec::new();
    for profile in list() {
        for variant in [Variant::Standard, Variant::Managed] {
            if let Some(template) = profile.template(variant) {
                variants.push((profile.harness, variant, template));
            }
        }
    }
    variants
}

fn rendered(harness: Harness, variant: Variant, base: &str) -> String {
    render_variant(harness, variant, Path::new(base)).unwrap()
}

/// The non-comment lines of a template or of its rendering.
fn body(format: Format, text: &str) -> String {
    let prefix = match format {
        Format::Sbpl => Some(';'),
        Format::Toml => Some('#'),
        Format::Json | Format::Markdown => None,
    };
    text.lines()
        .filter(|line| prefix.is_none_or(|p| !line.trim_start().starts_with(p)))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Occurrences of `needle` that end a path token (a following letter, digit,
/// `.`, `-` or `_` means the needle is only a prefix of a longer name).
fn path_occurrences(text: &str, needle: &str) -> usize {
    text.match_indices(needle)
        .filter(|(at, _)| {
            text[at + needle.len()..]
                .chars()
                .next()
                .is_none_or(|next| !(next.is_alphanumeric() || matches!(next, '.' | '-' | '_')))
        })
        .count()
}

// ---- the harness table ----

#[test]
fn profiles_are_indexed_by_harness() {
    assert_eq!(list().len(), Harness::ALL.len());
    for (index, harness) in Harness::ALL.into_iter().enumerate() {
        assert_eq!(harness as usize, index);
        assert_eq!(list()[index].harness, harness);
        assert_eq!(harness.profile().harness, harness);
    }
}

#[test]
fn names_parse_back_and_are_unique() {
    let mut seen = Vec::new();
    for harness in Harness::ALL {
        assert_eq!(Harness::parse(harness.name()), Some(harness));
        assert_eq!(
            Harness::parse(&harness.name().to_uppercase()),
            Some(harness)
        );
        assert_eq!(harness.to_string(), harness.name());
        assert!(!seen.contains(&harness.name()));
        seen.push(harness.name());
    }
    assert_eq!(
        Harness::names(),
        "claude-code|codex|gemini-cli|copilot-cli|sandbox-exec"
    );
    assert_eq!(Harness::parse("nonsense"), None);
    assert_eq!(Harness::parse(""), None);
    // Exact, not a prefix: `claude-code-extra` is not a harness.
    assert_eq!(Harness::parse("claude-code-extra"), None);
}

#[test]
fn harness_agents_are_known_agents() {
    let canonical: Vec<&str> = KNOWN_AGENTS.iter().map(|(_, name)| *name).collect();
    for harness in Harness::ALL {
        match harness.agent() {
            Some(agent) => {
                assert!(canonical.contains(&agent), "{agent} is not in KNOWN_AGENTS");
                assert_eq!(harness_for_agent(agent), Some(harness));
            }
            None => assert_eq!(harness, Harness::SandboxExec),
        }
    }
}

#[test]
fn every_known_agent_has_a_profile() {
    // A new KNOWN_AGENTS entry must be given a harness here, even if only the
    // sandbox-exec fallback.
    for (prefix, canonical) in KNOWN_AGENTS {
        assert!(
            Harness::parse(canonical).is_some(),
            "known agent {canonical} (prefix {prefix}) has no profile"
        );
        assert!(harness_for_agent(canonical).is_some());
    }
    assert_eq!(harness_for_agent("cursor"), Some(Harness::SandboxExec));
    assert_eq!(harness_for_agent("aider"), Some(Harness::SandboxExec));
    assert_eq!(harness_for_agent("unknown"), None);
    assert_eq!(harness_for_agent("relay"), None);
}

#[test]
fn profile_files_exist_under_docs_sandbox_and_match_the_embedded_text() {
    let docs = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/sandbox");
    for profile in list() {
        let on_disk = std::fs::read_to_string(docs.join(profile.file)).unwrap();
        assert_eq!(on_disk, profile.template(Variant::Standard).unwrap());
        if let Some(file) = profile.managed_file {
            let on_disk = std::fs::read_to_string(docs.join(file)).unwrap();
            assert_eq!(on_disk, profile.template(Variant::Managed).unwrap());
        }
        if let Some(file) = profile.guide_file {
            let on_disk = std::fs::read_to_string(docs.join(file)).unwrap();
            assert_eq!(on_disk, profile.guide().unwrap());
        }
        assert_eq!(
            profile.managed_file.is_some(),
            profile.template(Variant::Managed).is_some()
        );
        assert_eq!(profile.guide_file.is_some(), profile.guide().is_some());
    }
}

// ---- the preamble ----

fn preamble(profile: &Profile) -> String {
    profile
        .preamble_source()
        .lines()
        .take(45)
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn every_profile_opens_with_the_preamble() {
    for profile in list() {
        let head = preamble(profile);
        for label in [
            "Harness:",
            "Status:",
            "Sources:",
            "Verified:",
            "Base:",
            "Allow:",
            "Deny:",
            "Prove:",
        ] {
            assert!(
                head.contains(label),
                "{}: no {label} in the preamble",
                profile.harness
            );
        }
        // The verification date is an ISO date on the Verified line.
        let verified = head
            .lines()
            .find(|line| line.contains("Verified:"))
            .unwrap();
        let date = verified.split("Verified:").nth(1).unwrap();
        let date = date
            .trim_start_matches(|c: char| c.is_whitespace() || c == '*')
            .get(..10)
            .unwrap();
        let bytes = date.as_bytes();
        assert!(
            bytes[..4].iter().all(u8::is_ascii_digit)
                && bytes[4] == b'-'
                && bytes[5..7].iter().all(u8::is_ascii_digit)
                && bytes[7] == b'-'
                && bytes[8..].iter().all(u8::is_ascii_digit),
            "{}: Verified line has no ISO date: {verified}",
            profile.harness
        );
        // The base placeholder and its default are stated.
        assert!(head.contains(BASE_PLACEHOLDER), "{}", profile.harness);
        assert!(head.contains("~/.pam"), "{}", profile.harness);
        // The proving command is `pam doctor`, with the verdict to expect.
        assert!(head.contains("pam doctor"), "{}", profile.harness);
        assert!(head.contains("established"), "{}", profile.harness);
        // The preamble's Deny line says where the engine runtime lives
        // (under the denied engine tree, not inside `run`).
        assert!(head.contains("<base>/engine/run"), "{}", profile.harness);
        assert!(!head.contains("<base>/run/engine"), "{}", profile.harness);
    }
}

#[test]
fn harness_formats_cite_a_public_source() {
    for profile in list() {
        let head = preamble(profile);
        if profile.harness == Harness::SandboxExec {
            // The fallback cites the repository fixture it generalises.
            assert!(head.contains("broker-macos.sb"));
            assert!(head.contains("fallback"));
        } else {
            assert!(
                head.contains("https://"),
                "{}: no source URL",
                profile.harness
            );
        }
    }
    // Copilot has no configuration file format: its page says so and names the
    // fallback instead of inventing keys.
    let copilot = preamble(Harness::CopilotCli.profile());
    assert!(copilot.contains("no configuration file format"));
    assert!(copilot.contains("sandbox-exec"));
}

// ---- what a profile allows and denies ----

/// What a probe's denial needs the profile to name.
enum Need {
    /// A path under the base, relative to it.
    Path(&'static str),
    Keychain,
    Signal,
    LaunchServices,
    AppleEvents,
    Executable,
    Bundle,
    /// Not a deny the macOS profile expresses (a must-allow or info probe, one never
    /// probed, or a Windows-only one).
    NotApplicable,
}

/// What each probe needs of a profile. Exhaustive on purpose: a new probe id
/// does not compile until it is given a need here.
fn need(id: ProbeId) -> Need {
    match id {
        // A must-allow or info probe, one never probed, or a Windows-only one.
        ProbeId::PublicReach
        | ProbeId::RunLockProbe
        | ProbeId::PublicUnlink
        | ProbeId::AdminControlRead
        | ProbeId::DaemonProcessQuery
        | ProbeId::BrokerShellExecute => Need::NotApplicable,
        ProbeId::RunLockWrite => Need::Path("run/daemon.lock"),
        ProbeId::AdminEndpoint | ProbeId::AdminEndpointAlias => Need::Path("admin/control.sock"),
        ProbeId::AdminDir => Need::Path("admin"),
        ProbeId::StoreRead | ProbeId::StoreWrite => Need::Path("state.sqlite3"),
        ProbeId::StoreWalRead | ProbeId::StoreWalWrite => Need::Path("state.sqlite3-wal"),
        ProbeId::StoreShmRead | ProbeId::StoreShmWrite => Need::Path("state.sqlite3-shm"),
        ProbeId::BackupRead => Need::Path("backup"),
        ProbeId::ModelTrustRead => Need::Path("model-trust"),
        ProbeId::EngineRead => Need::Path("engine"),
        ProbeId::EngineRuntimeRead => Need::Path("engine/run"),
        ProbeId::EngineSocket => Need::Path("engine/run/engine.sock"),
        ProbeId::FlowsRead => Need::Path("flows"),
        ProbeId::LogRead => Need::Path("log"),
        ProbeId::KeychainSearch => Need::Keychain,
        ProbeId::DaemonSignal => Need::Signal,
        ProbeId::BrokerLaunchServices => Need::LaunchServices,
        ProbeId::BrokerAppleEvents => Need::AppleEvents,
        ProbeId::ExeWrite => Need::Executable,
        ProbeId::BundleWrite => Need::Bundle,
    }
}

/// The probe rows a macOS profile has to answer for.
fn macos_must_deny() -> Vec<ProbeId> {
    INVENTORY
        .iter()
        .filter(|row| row.class == ProbeClass::MustDeny && row.id.applies_to(Platform::Macos))
        .map(|row| row.id)
        .collect()
}

#[test]
fn needs_agree_with_the_inventory() {
    let denied = macos_must_deny();
    assert!(!denied.is_empty());
    for row in &INVENTORY {
        let applicable = row.class == ProbeClass::MustDeny && row.id.applies_to(Platform::Macos);
        assert_eq!(
            !matches!(need(row.id), Need::NotApplicable),
            applicable,
            "{}: the profile need and the inventory disagree",
            row.name
        );
    }
}

#[test]
fn every_profile_names_each_private_path_a_probe_attempts() {
    for (harness, variant, template) in all_variants() {
        let profile = harness.profile();
        let text = body(profile.format, template);
        for id in macos_must_deny() {
            if let Need::Path(path) = need(id) {
                let full = format!("{BASE_PLACEHOLDER}/{path}");
                // A sub-path is covered by naming its first component (the
                // admin directory covers the admin socket and the engine
                // directory its runtime), except under `run`, which is
                // never denied as a whole: the lock is named exactly.
                let first = path.split('/').next().unwrap();
                let named = path_occurrences(&text, &full) > 0
                    || (first != "run"
                        && path_occurrences(&text, &format!("{BASE_PLACEHOLDER}/{first}")) > 0);
                assert!(
                    named,
                    "{harness} ({variant:?}) does not name {full} (probe {})",
                    id.as_str()
                );
            }
        }
        // Nothing names the engine runtime at its old place inside `run`
        // (relocated under `engine/run`, ptrack issue 44): a stale deny
        // would read as if something still lived there.
        assert_eq!(
            path_occurrences(&text, &format!("{BASE_PLACEHOLDER}/run/engine")),
            0,
            "{harness} ({variant:?}) still names the old engine runtime inside run"
        );
    }
}

#[test]
fn the_public_socket_is_named_once_as_allowed() {
    let socket = format!("{BASE_PLACEHOLDER}/run/pam.sock");
    for (harness, variant, template) in all_variants() {
        let profile = harness.profile();
        let text = body(profile.format, template);
        assert_eq!(
            path_occurrences(&text, &socket),
            1,
            "{harness} ({variant:?}) names the public socket other than once"
        );
        // The same count holds for the Claude guide (prose around the JSON).
        if let Some(guide) = profile.guide() {
            assert_eq!(path_occurrences(guide, &socket), 1, "{harness} guide");
        }
    }
}

#[test]
fn seatbelt_profiles_allow_only_the_socket_and_the_lock_under_the_base() {
    for profile in list().iter().filter(|p| p.format == Format::Sbpl) {
        let text = body(Format::Sbpl, profile.template(Variant::Standard).unwrap());
        let allows: Vec<&str> = text
            .lines()
            .filter(|line| line.trim_start().starts_with("(allow") && line.contains("<base>"))
            .collect();
        assert_eq!(allows.len(), 2, "{}: {allows:?}", profile.harness);
        assert!(
            allows.iter().any(|line| {
                line.contains("network-outbound")
                    && line.contains("unix-socket")
                    && line.contains("(literal \"<base>/run/pam.sock\")")
            }),
            "{}: the socket allowance is not a literal unix-socket connect",
            profile.harness
        );
        assert!(
            allows.iter().any(|line| {
                line.contains("(allow file-read-data (literal \"<base>/run/daemon.lock\"))")
            }),
            "{}: the lock allowance is not a literal read",
            profile.harness
        );
        // The PAM block closes the file: nothing after it is an allow.
        let marker = text
            .find("(deny file-read-data file-write* (subpath \"<base>\"))")
            .unwrap();
        let block = &text[marker..];
        assert!(
            block.lines().all(|line| {
                !line.trim_start().starts_with("(allow")
                    || line.contains("<base>/run/pam.sock")
                    || line.contains("<base>/run/daemon.lock")
            }),
            "{}: an allow follows the PAM block's first rule",
            profile.harness
        );
        // Keychain, signals and the brokers are denied.
        for needle in [
            "/Library/Keychains",
            "(deny signal (target others))",
            "com.apple.SecurityServer",
            "com.apple.coreservices.launchservicesd",
            "com.apple.coreservices.appleevents",
            "/Applications/PAM.app",
        ] {
            assert!(block.contains(needle), "{}: no {needle}", profile.harness);
        }
    }
    // The fallback also names the trusted executable.
    let fallback = body(
        Format::Sbpl,
        Harness::SandboxExec
            .profile()
            .template(Variant::Standard)
            .unwrap(),
    );
    assert!(fallback.contains("(deny file-write* (literal (param \"PAM_EXE\")))"));
}

#[test]
fn claude_fragment_allows_one_socket_and_one_file() {
    for variant in [Variant::Standard, Variant::Managed] {
        let value: serde_json::Value =
            serde_json::from_str(&rendered(Harness::ClaudeCode, variant, BASE)).unwrap();
        let sandbox = &value["sandbox"];
        assert_eq!(sandbox["enabled"], true);
        assert_eq!(
            sandbox["network"]["allowUnixSockets"],
            serde_json::json!([format!("{BASE}/run/pam.sock")])
        );
        assert_eq!(
            sandbox["filesystem"]["allowRead"],
            serde_json::json!([format!("{BASE}/run/daemon.lock")])
        );
        let deny_read: Vec<&str> = sandbox["filesystem"]["denyRead"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(deny_read[0], BASE);
        for path in ["admin", "engine", "state.sqlite3"] {
            assert!(
                deny_read.contains(&format!("{BASE}/{path}").as_str()),
                "{path}"
            );
        }
        assert!(!deny_read.contains(&format!("{BASE}/run/pam.sock").as_str()));
        let deny_write: Vec<&str> = sandbox["filesystem"]["denyWrite"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(deny_write, [BASE, "/Applications/PAM.app"]);
        // The file tools are covered by permission rules; `//` is absolute.
        let rules: Vec<&str> = value["permissions"]["deny"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(rules.contains(&format!("Read(/{BASE}/**)").as_str()));
        assert!(rules.contains(&format!("Edit(/{BASE}/**)").as_str()));
    }
}

#[test]
fn claude_managed_variant_adds_the_locks_and_nothing_loosens() {
    let standard: serde_json::Value =
        serde_json::from_str(&rendered(Harness::ClaudeCode, Variant::Standard, BASE)).unwrap();
    let managed: serde_json::Value =
        serde_json::from_str(&rendered(Harness::ClaudeCode, Variant::Managed, BASE)).unwrap();
    assert_eq!(managed["sandbox"]["failIfUnavailable"], true);
    assert_eq!(managed["sandbox"]["allowUnsandboxedCommands"], false);
    assert_eq!(
        managed["sandbox"]["filesystem"]["allowManagedReadPathsOnly"],
        true
    );
    assert_eq!(managed["sandbox"]["network"]["allowAllUnixSockets"], false);
    // Same denies and same single allowance as the standard fragment.
    for key in ["denyRead", "allowRead", "denyWrite"] {
        assert_eq!(
            managed["sandbox"]["filesystem"][key],
            standard["sandbox"]["filesystem"][key]
        );
    }
    assert_eq!(
        managed["sandbox"]["network"]["allowUnixSockets"],
        standard["sandbox"]["network"]["allowUnixSockets"]
    );
    assert_eq!(managed["permissions"], standard["permissions"]);
    // No other harness has one.
    for harness in [
        Harness::Codex,
        Harness::GeminiCli,
        Harness::CopilotCli,
        Harness::SandboxExec,
    ] {
        assert_eq!(
            render_variant(harness, Variant::Managed, Path::new(BASE)),
            Err(RenderError::NoManagedVariant(harness))
        );
    }
}

/// One `table`, `key`, `value` triple per line of a TOML file written in the
/// subset the profile uses: `[a.b]` tables, quoted or bare keys, string and
/// boolean values.
fn parse_toml_subset(text: &str) -> Vec<(String, String, String)> {
    let mut table = String::new();
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[') {
            table = name.strip_suffix(']').expect("table header").to_owned();
            continue;
        }
        let (key, value) = if let Some(rest) = line.strip_prefix('"') {
            let (key, after) = decode_quoted(rest);
            let value = after.trim_start().strip_prefix('=').expect("equals").trim();
            (key, value)
        } else {
            let (key, value) = line.split_once('=').expect("key = value");
            (key.trim().to_owned(), value.trim())
        };
        let value = if let Some(rest) = value.strip_prefix('"') {
            let (value, after) = decode_quoted(rest);
            assert!(
                after.trim().is_empty(),
                "trailing text after a string: {line}"
            );
            value
        } else {
            assert!(
                matches!(value, "true" | "false"),
                "unsupported value: {line}"
            );
            value.to_owned()
        };
        out.push((table.clone(), key, value));
    }
    out
}

/// Decodes a quoted string whose opening quote is already consumed; returns the
/// decoded text and what follows the closing quote. Handles only the escapes a
/// path needs (`\\` and `\"`); any other escape is a failure.
fn decode_quoted(rest: &str) -> (String, &str) {
    let mut out = String::new();
    let mut chars = rest.char_indices();
    while let Some((at, ch)) = chars.next() {
        match ch {
            '"' => return (out, &rest[at + 1..]),
            '\\' => match chars.next() {
                Some((_, escaped @ ('\\' | '"'))) => out.push(escaped),
                other => panic!("unsupported escape {other:?} in {rest}"),
            },
            other => out.push(other),
        }
    }
    panic!("unterminated string: {rest}");
}

#[test]
fn codex_profile_allows_one_socket_and_one_file() {
    let rows = parse_toml_subset(&rendered(Harness::Codex, Variant::Standard, BASE));
    let get = |table: &str, key: &str| {
        rows.iter()
            .find(|(t, k, _)| t == table && k == key)
            .map(|(_, _, v)| v.as_str())
    };
    assert_eq!(get("", "default_permissions"), Some("pam"));
    assert_eq!(get("permissions.pam", "extends"), Some(":workspace"));
    let socket = format!("{BASE}/run/pam.sock");
    assert_eq!(
        get("permissions.pam.network.unix_sockets", &socket),
        Some("allow")
    );
    assert_eq!(get("permissions.pam.network", "enabled"), Some("true"));
    assert_eq!(
        get(
            "permissions.pam.filesystem",
            &format!("{BASE}/run/daemon.lock")
        ),
        Some("read")
    );
    assert_eq!(get("permissions.pam.filesystem", BASE), Some("deny"));
    for path in ["admin", "engine", "state.sqlite3-shm"] {
        assert_eq!(
            get("permissions.pam.filesystem", &format!("{BASE}/{path}")),
            Some("deny"),
            "{path}"
        );
    }
    assert_eq!(
        get(
            "permissions.pam.network.unix_sockets",
            &format!("{BASE}/admin/control.sock")
        ),
        Some("deny")
    );
    assert_eq!(
        get(
            "permissions.pam.network.unix_sockets",
            &format!("{BASE}/engine/run/engine.sock")
        ),
        Some("deny")
    );
    // Nothing else under the base is allowed, read or written.
    let grants: Vec<&(String, String, String)> = rows
        .iter()
        .filter(|(table, key, value)| {
            table.starts_with("permissions.pam.")
                && key.starts_with(BASE)
                && matches!(value.as_str(), "allow" | "read" | "write")
        })
        .collect();
    assert_eq!(grants.len(), 2, "{grants:?}");
}

#[test]
fn copilot_page_lists_every_denied_path_and_keychain_off() {
    let text = rendered(Harness::CopilotCli, Variant::Standard, BASE);
    for path in [
        "",
        "/admin",
        "/state.sqlite3",
        "/state.sqlite3-wal",
        "/state.sqlite3-shm",
        "/backup",
        "/model-trust",
        "/engine",
        "/flows",
        "/log",
    ] {
        assert!(
            text.contains(&format!("- `{BASE}{path}`\n")),
            "no denied rule for {BASE}{path}"
        );
    }
    assert!(text.contains("\"Allow keychain access\" **off**"));
    assert!(text.contains("relay"));
}

#[test]
fn relay_variant_is_documented_in_every_profile() {
    for profile in list() {
        // The prose files (Claude guide, Copilot page) describe it; the
        // fragments carry it as a commented line to swap in.
        let text = profile
            .guide()
            .unwrap_or(profile.template(Variant::Standard).unwrap());
        assert!(text.contains("PAM_SOCKET_DIR=<dir>"), "{}", profile.harness);
        if matches!(profile.format, Format::Sbpl | Format::Toml) {
            assert!(text.contains("<dir>/pam.sock"), "{}", profile.harness);
        }
    }
}

// ---- substitution ----

#[test]
fn rendering_leaves_no_placeholder_and_substitutes_the_base() {
    for (harness, variant, _) in all_variants() {
        let text = rendered(harness, variant, BASE);
        assert!(!text.contains(BASE_PLACEHOLDER), "{harness} ({variant:?})");
        assert!(text.contains(&format!("{BASE}/run/pam.sock")), "{harness}");
    }
    let guide = render_guide(Harness::ClaudeCode, Path::new(BASE))
        .unwrap()
        .unwrap();
    assert!(!guide.contains(BASE_PLACEHOLDER));
    assert_eq!(render_guide(Harness::Codex, Path::new(BASE)), Ok(None));
}

#[test]
fn a_trailing_slash_is_the_same_base() {
    for harness in Harness::ALL {
        assert_eq!(
            render(harness, Path::new("/Users/tester/.pam/")),
            render(harness, Path::new(BASE))
        );
    }
}

#[test]
fn a_base_that_is_itself_the_placeholder_is_not_expanded_again() {
    let text = render(Harness::SandboxExec, Path::new("/x/<base>/y")).unwrap();
    assert!(text.contains("/x/<base>/y/run/pam.sock"));
    assert!(!text.contains("/x//x/"));
}

/// Decodes the `(literal "…")` or `(subpath "…")` string on `line`, if any.
fn sbpl_string(line: &str) -> Option<String> {
    let start = line
        .find("(literal \"")
        .map(|at| at + 10)
        .or_else(|| line.find("(subpath \"").map(|at| at + 10))?;
    Some(decode_quoted(&line[start..]).0)
}

#[test]
fn seatbelt_paths_round_trip_an_awkward_base() {
    for harness in [Harness::GeminiCli, Harness::SandboxExec] {
        let text = rendered(harness, Variant::Standard, AWKWARD_BASE);
        let sockets: Vec<String> = body(Format::Sbpl, &text)
            .lines()
            .filter(|line| {
                line.starts_with("(allow network-outbound (remote unix-socket (literal \"")
                    && line.contains("pam.sock")
            })
            .filter_map(sbpl_string)
            .collect();
        assert_eq!(
            sockets,
            [format!("{AWKWARD_BASE}/run/pam.sock")],
            "{harness}"
        );
        // The base's own deny line decodes to exactly the base.
        let base_denies: Vec<String> = body(Format::Sbpl, &text)
            .lines()
            .filter(|line| {
                line.starts_with("(deny file-read-data file-write* (subpath \"")
                    && !line.contains("param")
            })
            .filter_map(sbpl_string)
            .collect();
        assert!(base_denies.contains(&AWKWARD_BASE.to_owned()), "{harness}");
        assert!(
            base_denies.contains(&format!("{AWKWARD_BASE}/engine")),
            "{harness}"
        );
        // Every quote in a profile line is balanced: an escaped base cannot
        // leave a string open.
        for line in body(Format::Sbpl, &text).lines() {
            assert!(
                sbpl_quotes_balanced(line),
                "{harness}: unbalanced quotes in {line}"
            );
        }
        assert!(sbpl_parens_balanced(&text), "{harness}");
    }
}

fn sbpl_quotes_balanced(line: &str) -> bool {
    let mut open = false;
    let mut chars = line.chars();
    while let Some(ch) = chars.next() {
        match ch {
            '\\' if open => {
                chars.next();
            }
            '"' => open = !open,
            _ => {}
        }
    }
    !open
}

/// Parentheses balance outside strings and comments, over the whole profile.
fn sbpl_parens_balanced(text: &str) -> bool {
    let mut depth = 0i64;
    for line in text.lines() {
        if line.trim_start().starts_with(';') {
            continue;
        }
        let mut open = false;
        let mut chars = line.chars();
        while let Some(ch) = chars.next() {
            match ch {
                '\\' if open => {
                    chars.next();
                }
                '"' => open = !open,
                '(' if !open => depth += 1,
                ')' if !open => {
                    depth -= 1;
                    if depth < 0 {
                        return false;
                    }
                }
                _ => {}
            }
        }
    }
    depth == 0
}

#[test]
fn the_shipped_seatbelt_templates_are_structurally_balanced() {
    for profile in list().iter().filter(|p| p.format == Format::Sbpl) {
        let text = profile.template(Variant::Standard).unwrap();
        assert!(sbpl_parens_balanced(text), "{}", profile.harness);
        let lines: Vec<&str> = text.lines().collect();
        let version = lines
            .iter()
            .position(|line| *line == "(version 1)")
            .unwrap();
        assert_eq!(lines[version + 1], "(deny default)", "{}", profile.harness);
    }
    assert!(sbpl_parens_balanced("(a (b \"(\"))"));
    assert!(!sbpl_parens_balanced("(a (b)"));
    assert!(!sbpl_parens_balanced(")("));
}

#[test]
fn json_and_toml_round_trip_an_awkward_base() {
    let value: serde_json::Value = serde_json::from_str(&rendered(
        Harness::ClaudeCode,
        Variant::Standard,
        AWKWARD_BASE,
    ))
    .unwrap();
    assert_eq!(
        value["sandbox"]["network"]["allowUnixSockets"][0],
        format!("{AWKWARD_BASE}/run/pam.sock")
    );
    assert_eq!(value["sandbox"]["filesystem"]["denyRead"][0], AWKWARD_BASE);
    assert_eq!(
        value["permissions"]["deny"][0],
        format!("Read(/{AWKWARD_BASE}/**)")
    );
    // The Claude guide (prose) takes the raw path.
    let guide = render_guide(Harness::ClaudeCode, Path::new(AWKWARD_BASE))
        .unwrap()
        .unwrap();
    assert!(guide.contains(&format!("{AWKWARD_BASE}/run/pam.sock")));

    let rows = parse_toml_subset(&rendered(Harness::Codex, Variant::Standard, AWKWARD_BASE));
    assert!(rows.iter().any(|(table, key, value)| {
        table == "permissions.pam.network.unix_sockets"
            && key == &format!("{AWKWARD_BASE}/run/pam.sock")
            && value == "allow"
    }));
}

#[test]
fn comments_take_the_raw_path_and_strings_the_escaped_one() {
    let text = rendered(Harness::SandboxExec, Variant::Standard, AWKWARD_BASE);
    let comment = text
        .lines()
        .find(|line| line.starts_with(";; Base:"))
        .unwrap();
    assert!(comment.contains(AWKWARD_BASE));
    assert!(text.contains(";; Allow:    connect to /Users/te ster/\"q\"/a\\b/.pam/run/pam.sock"));
    assert!(text.contains(r#"(literal "/Users/te ster/\"q\"/a\\b/.pam/run/pam.sock")"#));
}

#[test]
fn unusable_bases_are_refused_with_a_recovery() {
    let refused = |harness: Harness, base: &str| render(harness, Path::new(base)).unwrap_err();
    assert_eq!(
        refused(Harness::SandboxExec, ".pam"),
        RenderError::NotAbsolute
    );
    assert_eq!(refused(Harness::SandboxExec, ""), RenderError::NotAbsolute);
    assert_eq!(
        refused(Harness::SandboxExec, "C:\\pam"),
        RenderError::NotAbsolute
    );
    assert_eq!(refused(Harness::SandboxExec, "/"), RenderError::NotNormal);
    assert_eq!(
        refused(Harness::SandboxExec, "/a/../b"),
        RenderError::NotNormal
    );
    assert_eq!(
        refused(Harness::SandboxExec, "/a/./b"),
        RenderError::NotNormal
    );
    assert_eq!(
        refused(Harness::SandboxExec, "/a//b"),
        RenderError::NotNormal
    );
    for control in ["/a\nb", "/a\rb", "/a\tb", "/a\0b", "/a\u{7f}b", "/a\u{1b}b"] {
        assert_eq!(
            refused(Harness::SandboxExec, control),
            RenderError::ControlCharacter,
            "{control:?}"
        );
        assert_eq!(
            refused(Harness::ClaudeCode, control),
            RenderError::ControlCharacter
        );
    }
    // Pattern characters are refused only where the path entries are patterns.
    for pattern in ['*', '?', '[', ']', '{', '}', '(', ')'] {
        let base = format!("/a{pattern}b");
        assert_eq!(
            refused(Harness::ClaudeCode, &base),
            RenderError::PatternCharacter {
                harness: Harness::ClaudeCode,
                character: pattern
            }
        );
        assert_eq!(
            refused(Harness::Codex, &base),
            RenderError::PatternCharacter {
                harness: Harness::Codex,
                character: pattern
            }
        );
        assert!(
            render(Harness::SandboxExec, Path::new(&base)).is_ok(),
            "{pattern}"
        );
        assert!(
            render(Harness::GeminiCli, Path::new(&base)).is_ok(),
            "{pattern}"
        );
        assert!(
            render(Harness::CopilotCli, Path::new(&base)).is_ok(),
            "{pattern}"
        );
    }
    // A failure is not a half-rendered profile, and says how to recover.
    for error in [
        RenderError::NotAbsolute,
        RenderError::NotUtf8,
        RenderError::NotNormal,
        RenderError::ControlCharacter,
        RenderError::PatternCharacter {
            harness: Harness::Codex,
            character: '*',
        },
        RenderError::NoManagedVariant(Harness::Codex),
    ] {
        let message = error.to_string();
        assert!(!message.contains('\n'), "{message}");
        assert!(
            message.contains("--base")
                || message.contains("choose")
                || message.contains("pass")
                || message.contains("drop")
                || message.contains("use"),
            "no recovery in: {message}"
        );
    }
}

#[cfg(unix)]
#[test]
fn a_base_that_is_not_utf8_is_refused() {
    use std::os::unix::ffi::OsStrExt;
    let base = std::path::PathBuf::from(std::ffi::OsStr::from_bytes(b"/Users/te\xffster/.pam"));
    assert_eq!(
        render(Harness::SandboxExec, &base),
        Err(RenderError::NotUtf8)
    );
}

// ---- the Seatbelt files load ----

/// Runs `/usr/bin/true` under the rendered profile with the `-D` names every
/// profile might read; the exit status is the loader's verdict on the syntax.
#[cfg(target_os = "macos")]
fn sandbox_exec_true(profile: &Path) -> std::process::Output {
    let mut command = std::process::Command::new("/usr/bin/sandbox-exec");
    for (name, value) in [
        ("HOME", "/dev/null"),
        ("WORKSPACE", "/dev/null"),
        ("PAM_EXE", "/dev/null"),
        ("TARGET_DIR", "/dev/null"),
        ("TMP_DIR", "/dev/null"),
        ("HOME_DIR", "/dev/null"),
        ("CACHE_DIR", "/dev/null"),
        ("INCLUDE_DIR_0", "/dev/null"),
        ("INCLUDE_DIR_1", "/dev/null"),
        ("INCLUDE_DIR_2", "/dev/null"),
        ("INCLUDE_DIR_3", "/dev/null"),
        ("INCLUDE_DIR_4", "/dev/null"),
    ] {
        command.arg("-D").arg(format!("{name}={value}"));
    }
    command.arg("-f").arg(profile).arg("/usr/bin/true");
    command.output().unwrap()
}

#[cfg(target_os = "macos")]
#[test]
fn rendered_seatbelt_profiles_load_under_sandbox_exec() {
    let dir = tempfile::tempdir().unwrap();
    for base in [BASE, AWKWARD_BASE, "/private/tmp/plain/.pam"] {
        for profile in list().iter().filter(|p| p.format == Format::Sbpl) {
            let file = dir.path().join(format!("{}.sb", profile.harness));
            std::fs::write(&file, rendered(profile.harness, Variant::Standard, base)).unwrap();
            let output = sandbox_exec_true(&file);
            assert!(
                output.status.success(),
                "{} with base {base:?} does not load: {}",
                profile.harness,
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}

#[cfg(target_os = "macos")]
#[test]
fn the_loader_check_is_not_vacuous() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("broken.sb");
    let mut text = rendered(Harness::SandboxExec, Variant::Standard, BASE);
    text.push_str("(\n");
    std::fs::write(&file, text).unwrap();
    assert!(!sandbox_exec_true(&file).status.success());
}

#[cfg(windows)]
#[test]
fn the_windows_statement_names_the_state_the_options_and_the_page() {
    assert!(WINDOWS_STATEMENT.contains("No supported harness configuration establishes"));
    assert!(WINDOWS_STATEMENT.contains("`not_established`"));
    assert!(WINDOWS_STATEMENT.contains("VM or on a separate machine"));
    assert!(WINDOWS_STATEMENT.contains("accept the convention and record it"));
    assert!(WINDOWS_STATEMENT.contains("docs/sandbox/windows/README.md"));
    // No template placeholder or POSIX base leaks into it.
    assert!(!WINDOWS_STATEMENT.contains(BASE_PLACEHOLDER));
}
