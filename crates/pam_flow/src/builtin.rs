//! The starter flows, compiled into the binary.
//!
//! A fresh install has a working library on day one: these seven files ship
//! inside pam, are listed like any other flow, and are the templates a human
//! clones and edits. Saving a library file with the same id shadows the
//! builtin; deleting that file reveals it again, so a starter flow can never
//! be lost.

/// One embedded starter flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuiltinFlow {
    /// The flow id, equal to the file stem under `crates/pam_flow/flows/`.
    pub id: &'static str,
    /// The file's exact bytes.
    pub yaml: &'static str,
}

const BUILTINS: &[BuiltinFlow] = &[
    BuiltinFlow {
        id: "after-merge-checks",
        yaml: include_str!("../flows/after-merge-checks.yaml"),
    },
    BuiltinFlow {
        id: "ci-failure-triage",
        yaml: include_str!("../flows/ci-failure-triage.yaml"),
    },
    BuiltinFlow {
        id: "dependency-audit",
        yaml: include_str!("../flows/dependency-audit.yaml"),
    },
    BuiltinFlow {
        id: "pr-readiness",
        yaml: include_str!("../flows/pr-readiness.yaml"),
    },
    BuiltinFlow {
        id: "release-readiness",
        yaml: include_str!("../flows/release-readiness.yaml"),
    },
    BuiltinFlow {
        id: "sonar-gate-check",
        yaml: include_str!("../flows/sonar-gate-check.yaml"),
    },
    BuiltinFlow {
        id: "summarize-build-log",
        yaml: include_str!("../flows/summarize-build-log.yaml"),
    },
];

/// Every starter flow, sorted by id.
#[must_use]
pub fn builtin() -> &'static [BuiltinFlow] {
    BUILTINS
}

/// The YAML of one starter flow, if pam ships it.
#[must_use]
pub fn builtin_yaml(id: &str) -> Option<&'static str> {
    BUILTINS
        .iter()
        .find(|flow| flow.id == id)
        .map(|flow| flow.yaml)
}
