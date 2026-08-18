use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};

use crate::ProjectId;

#[derive(Clone, Default)]
pub struct ProjectQueue {
    projects: Arc<Mutex<HashMap<ProjectId, ProjectState>>>,
}

impl ProjectQueue {
    /// Enters the ordered queue for a project.
    ///
    /// Tokio's mutex grants locks in request order, which gives each project a
    /// small in-memory FIFO without coupling the core domain to a transport.
    pub async fn enter(&self, project_id: &ProjectId) -> ProjectPermit {
        let state = {
            let mut projects = self
                .projects
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            projects.entry(project_id.clone()).or_default().clone()
        };
        state.depth.fetch_add(1, Ordering::AcqRel);
        let guard = state.gate.lock_owned().await;

        ProjectPermit {
            _guard: guard,
            depth: state.depth,
        }
    }
}

#[derive(Clone, Default)]
struct ProjectState {
    gate: Arc<AsyncMutex<()>>,
    depth: Arc<AtomicU64>,
}

pub struct ProjectPermit {
    _guard: OwnedMutexGuard<()>,
    depth: Arc<AtomicU64>,
}

impl ProjectPermit {
    #[must_use]
    pub fn queued_behind(&self) -> u64 {
        self.depth.load(Ordering::Acquire).saturating_sub(1)
    }
}

impl Drop for ProjectPermit {
    fn drop(&mut self) {
        self.depth.fetch_sub(1, Ordering::AcqRel);
    }
}
