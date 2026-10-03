//! The env facts of the report: what the client already computes about its
//! own position, read through the seam and fitted to the report's bounds.

use pam_client::caller::find_repo_root;
use pam_client::transport::endpoint_label;
use pam_daemon::daemon::DAEMON_VERSION;
use pam_proto::caller::classify_chain;
use pam_proto::doctor::{EnvFacts, Frontend, MAX_PATH_BYTES, MAX_TEXT_BYTES};

use super::classify::{bounded_chain, bounded_path, bounded_text};
use super::inventory::Context;
use super::profiles::{Harness, harness_for_agent};

/// The facts for the context, with the harness chain the walk collected.
#[must_use]
pub fn facts(context: &Context, harness_chain: Vec<String>) -> EnvFacts {
    let os = context.os.as_ref();
    EnvFacts {
        socket_dir: context.session_dir.as_deref().map(bounded_path),
        base_dir_override: context
            .base_override
            .as_ref()
            .map(|value| bounded_text(&value.to_string_lossy(), MAX_PATH_BYTES)),
        resolved_base: bounded_path(&context.base),
        resolved_endpoint: bounded_text(&endpoint_label(&context.dirs), MAX_PATH_BYTES),
        client_version: bounded_text(DAEMON_VERSION, MAX_TEXT_BYTES),
        exe: os.current_exe().ok().as_deref().map(bounded_path),
        cwd_repo: os.current_dir().ok().and_then(|cwd| {
            let cwd = cwd.canonicalize().unwrap_or(cwd);
            find_repo_root(&cwd).as_deref().map(bounded_path)
        }),
        frontend: frontend(),
        harness_chain: bounded_chain(harness_chain),
    }
}

/// The frontend this binary carries: a compile-time property.
#[must_use]
pub const fn frontend() -> Frontend {
    if cfg!(feature = "gui-embed") {
        Frontend::Embedded
    } else {
        Frontend::DevelopmentServer
    }
}

/// The reference profile for the harness the chain names, when it names
/// one `pam doctor --profile` ships (`super::profiles`).
#[must_use]
pub fn profile_for_chain(chain: &[String]) -> Option<Harness> {
    harness_for_agent(&classify_chain(chain))
}
