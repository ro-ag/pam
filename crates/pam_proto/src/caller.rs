//! Agent attribution shared by the client and the daemon.
//!
//! The client stamps a self-reported [`crate::Caller`] into every envelope by
//! walking its own parent-process chain; the daemon walks the kernel peer's
//! ancestry itself when it records a request. Both classify the chain with
//! the table and the rule below so that the self-reported `agent` and the
//! daemon-resolved `peer_harness` name the same thing when they agree, and
//! visibly differ when they do not. **Not authentication**: a renamed parent
//! defeats the match; the names are attribution, filters and audit context.
//!
//! This crate owns the table because `pam_client` depends on `pam_daemon`,
//! so the daemon cannot import it from the client.

/// Known agent process-name prefixes and the canonical agent name each one
/// reports as. Matched lowercased, nearest ancestor first.
pub const KNOWN_AGENTS: &[(&str, &str)] = &[
    ("claude", "claude"),
    ("github-copilot", "copilot"),
    ("copilot", "copilot"),
    ("codex", "codex"),
    ("cursor", "cursor"),
    ("gemini", "gemini"),
    ("aider", "aider"),
];

/// Upper bound on how many ancestors a parent-process walk visits, on
/// either side of the socket.
pub const MAX_CHAIN_DEPTH: usize = 10;

/// The agent name reported when a chain has no usable name at all.
pub const UNKNOWN_AGENT: &str = "unknown";

/// The harness the daemon records for a peer that is the session relay
/// (`pam listen`): the kernel peer is the relay, not the agent behind it.
pub const RELAY_HARNESS: &str = "relay";

/// The canonical agent a single process name stands for, when its
/// lowercased form starts with a prefix in [`KNOWN_AGENTS`].
#[must_use]
pub fn canonical_agent(name: &str) -> Option<&'static str> {
    let lowered = name.to_lowercase();
    KNOWN_AGENTS
        .iter()
        .find(|(prefix, _)| lowered.starts_with(prefix))
        .map(|(_, canonical)| *canonical)
}

/// Classifies a parent-process chain (nearest ancestor first) into an agent
/// name.
///
/// Each name is lowercased and matched by prefix against the known-agent
/// table; the first (nearest) match wins. Without a match, the first
/// non-empty name in the chain — the immediate parent, typically a shell —
/// is returned verbatim, and an effectively empty chain yields
/// [`UNKNOWN_AGENT`].
#[must_use]
pub fn classify_chain(names: &[String]) -> String {
    if let Some(canonical) = names.iter().find_map(|name| canonical_agent(name)) {
        return canonical.to_owned();
    }
    names
        .iter()
        .find(|name| !name.is_empty())
        .cloned()
        .unwrap_or_else(|| UNKNOWN_AGENT.to_owned())
}
