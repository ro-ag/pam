use std::path::PathBuf;

use pam_core::ProjectId;
use pam_protocol::StatusResult;

use super::control_center::{HealthState, ProjectEntry, classify_status, merge_test_projects};

fn project(name: &str, path: &str, id: Option<&str>) -> ProjectEntry {
    ProjectEntry {
        name: name.to_owned(),
        root: PathBuf::from(path),
        id: id.map(ProjectId::new),
    }
}

#[test]
fn healthy_status_remains_healthy_while_work_is_queued() {
    let state = classify_status(StatusResult {
        ready: true,
        healthy: true,
        daemon_version: "0.1.0".to_owned(),
        protocol_version: 6,
        queue_depth: 3,
    });

    assert_eq!(
        state,
        HealthState::Healthy {
            daemon_version: "0.1.0".to_owned(),
            queue_depth: 3,
        }
    );
    assert!(state.can_stop());
    assert!(!state.can_start());
}

#[test]
fn unready_status_is_degraded_without_claiming_offline() {
    let state = classify_status(StatusResult {
        ready: false,
        healthy: false,
        daemon_version: "0.1.0".to_owned(),
        protocol_version: 6,
        queue_depth: 0,
    });

    assert!(matches!(state, HealthState::Degraded { .. }));
    assert!(!state.can_start());
    assert!(!state.can_stop());
}

#[test]
fn project_catalog_keeps_current_first_and_deduplicates_canonical_roots() {
    let current = project("pam", "/projects/pam", Some("project-pam"));
    let projects = merge_test_projects(
        current,
        vec![
            project("other", "/projects/other", None),
            project("PAM renamed", "/projects/pam", None),
            project("other duplicate", "/projects/other", None),
        ],
    );

    assert_eq!(projects.len(), 2);
    assert_eq!(projects[0].root, PathBuf::from("/projects/pam"));
    assert_eq!(projects[0].id, Some(ProjectId::new("project-pam")));
    assert_eq!(projects[1].root, PathBuf::from("/projects/other"));
}
