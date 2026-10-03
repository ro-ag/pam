use crate::caller::{KNOWN_AGENTS, RELAY_HARNESS, UNKNOWN_AGENT, canonical_agent, classify_chain};

fn chain(names: &[&str]) -> Vec<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
}

#[test]
fn classify_matches_exact_agent_name() {
    assert_eq!(
        classify_chain(&chain(&["claude", "zsh", "login"])),
        "claude"
    );
}

#[test]
fn classify_nearest_ancestor_wins() {
    assert_eq!(classify_chain(&chain(&["cursor", "claude"])), "cursor");
}

#[test]
fn classify_is_case_insensitive() {
    assert_eq!(classify_chain(&chain(&["Claude"])), "claude");
}

#[test]
fn classify_matches_prefixed_variants() {
    assert_eq!(classify_chain(&chain(&["claude-code"])), "claude");
    assert_eq!(classify_chain(&chain(&["github-copilot"])), "copilot");
}

#[test]
fn classify_falls_back_to_immediate_parent() {
    assert_eq!(classify_chain(&chain(&["zsh", "login"])), "zsh");
}

#[test]
fn classify_skips_empty_names_in_fallback() {
    assert_eq!(classify_chain(&chain(&["", "bash"])), "bash");
}

#[test]
fn classify_empty_chain_is_unknown() {
    assert_eq!(classify_chain(&[]), UNKNOWN_AGENT);
    assert_eq!(classify_chain(&chain(&["", ""])), UNKNOWN_AGENT);
}

#[test]
fn canonical_agent_matches_by_prefix_or_not_at_all() {
    assert_eq!(canonical_agent("Claude-Code"), Some("claude"));
    assert_eq!(canonical_agent("github-copilot-cli"), Some("copilot"));
    assert_eq!(canonical_agent("copilot"), Some("copilot"));
    assert_eq!(canonical_agent("zsh"), None);
    assert_eq!(canonical_agent(""), None);
    // A prefix match is anchored at the start: a name that merely contains
    // an agent's name is not that agent.
    assert_eq!(canonical_agent("my-claude"), None);
}

#[test]
fn every_known_agent_classifies_to_its_canonical_name() {
    for (prefix, canonical) in KNOWN_AGENTS {
        assert_eq!(canonical_agent(prefix), Some(*canonical), "{prefix}");
        assert_eq!(classify_chain(&chain(&[prefix])), *canonical, "{prefix}");
    }
}

#[test]
fn table_prefixes_are_lowercase_and_unique() {
    let mut seen = std::collections::HashSet::new();
    for (prefix, _) in KNOWN_AGENTS {
        assert_eq!(*prefix, prefix.to_lowercase(), "{prefix}");
        assert!(seen.insert(*prefix), "duplicate prefix {prefix}");
    }
}

#[test]
fn the_reserved_names_are_not_known_agents() {
    // The daemon writes these for a peer it could not attribute to an
    // agent; neither may ever collide with a table entry.
    assert_eq!(canonical_agent(UNKNOWN_AGENT), None);
    assert_eq!(canonical_agent(RELAY_HARNESS), None);
}
