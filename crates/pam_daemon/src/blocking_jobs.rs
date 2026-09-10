//! Process-owned limits for work that cannot be stopped by dropping its caller.
//! Permits and resource lanes travel into the blocking closure. Completion
//! observations contain fixed operation labels, never arguments or secrets.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard};

use serde::Serialize;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const CAPACITY: usize = 8;
const ADMISSION_CAPACITY: usize = 128;
const HISTORY: usize = 64;
static JOBS: LazyLock<Arc<BlockingJobs>> = LazyLock::new(|| BlockingJobs::new(CAPACITY));

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Kind {
    Keychain,
    ModelFilesystem,
    LogCompaction,
    AgentDetection,
    RepositoryIdentity,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum State {
    Waiting,
    Running,
    Returned,
    Panicked,
    CancelledBeforeStart,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct Observation {
    id: u64,
    kind: Kind,
    state: State,
}

#[derive(Debug, Serialize)]
pub(crate) struct Snapshot {
    capacity: usize,
    admission_capacity: usize,
    outstanding: Vec<Observation>,
    completed: Vec<Observation>,
}

#[derive(Clone, Copy, Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error("blocking job capacity exhausted; existing work may still be running")]
    Busy,
    #[error("blocking job did not return normally; inspect current state before retrying")]
    Join,
}

impl Error {
    pub(crate) fn cause(self) -> &'static str {
        match self {
            Self::Busy => "blocking_capacity_exhausted",
            Self::Join => "blocking_job_failed",
        }
    }
    pub(crate) fn recovery(self) -> &'static str {
        match self {
            Self::Busy => {
                "This operation did not start. Wait for outstanding work to finish before trying again."
            }
            Self::Join => {
                "The worker did not return normally. Inspect the current state before retrying."
            }
        }
    }
}

#[derive(Default)]
struct Records {
    next_id: u64,
    outstanding: BTreeMap<u64, Observation>,
    completed: VecDeque<Observation>,
}

pub(crate) struct BlockingJobs {
    capacity: usize,
    permits: Arc<Semaphore>,
    admissions: Arc<Semaphore>,
    keychain: Arc<tokio::sync::Mutex<()>>,
    models: Arc<tokio::sync::Mutex<()>>,
    records: Mutex<Records>,
}

impl BlockingJobs {
    pub(crate) fn new(capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            capacity,
            permits: Arc::new(Semaphore::new(capacity)),
            admissions: Arc::new(Semaphore::new(ADMISSION_CAPACITY)),
            keychain: Arc::new(tokio::sync::Mutex::new(())),
            models: Arc::new(tokio::sync::Mutex::new(())),
            records: Mutex::new(Records::default()),
        })
    }

    fn records(&self) -> MutexGuard<'_, Records> {
        self.records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(crate) fn snapshot(&self) -> Snapshot {
        let records = self.records();
        Snapshot {
            capacity: self.capacity,
            admission_capacity: ADMISSION_CAPACITY,
            outstanding: records.outstanding.values().cloned().collect(),
            completed: records.completed.iter().cloned().collect(),
        }
    }

    pub(crate) async fn run<F, T>(self: &Arc<Self>, kind: Kind, call: F) -> Result<T, Error>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        let permit = Arc::clone(&self.admissions)
            .try_acquire_owned()
            .map_err(|_| Error::Busy)?;
        let id = {
            let mut records = self.records();
            let id = records.next_id;
            records.next_id += 1;
            records.outstanding.insert(
                id,
                Observation {
                    id,
                    kind,
                    state: State::Waiting,
                },
            );
            id
        };
        let mut job = Job {
            owner: Arc::clone(self),
            id,
            started: false,
            _permit: permit,
        };
        let lane = match kind {
            Kind::Keychain => Some(Arc::clone(&self.keychain).lock_owned().await),
            Kind::ModelFilesystem => Some(Arc::clone(&self.models).lock_owned().await),
            Kind::LogCompaction | Kind::AgentDetection | Kind::RepositoryIdentity => None,
        };
        let execution = Arc::clone(&self.permits)
            .acquire_owned()
            .await
            .map_err(|_| Error::Join)?;
        tokio::task::spawn_blocking(move || {
            // These guards are owned by actual work, even after its waiter exits.
            let _lane = lane;
            let _execution = execution;
            job.started = true;
            if let Some(record) = job.owner.records().outstanding.get_mut(&id) {
                record.state = State::Running;
            }
            let result = call();
            drop(job);
            result
        })
        .await
        .map_err(|_| Error::Join)
    }
}

struct Job {
    owner: Arc<BlockingJobs>,
    id: u64,
    started: bool,
    _permit: OwnedSemaphorePermit,
}

impl Drop for Job {
    fn drop(&mut self) {
        let mut records = self.owner.records();
        if let Some(mut record) = records.outstanding.remove(&self.id) {
            record.state = if !self.started {
                State::CancelledBeforeStart
            } else if std::thread::panicking() {
                State::Panicked
            } else {
                State::Returned
            };
            if records.completed.len() == HISTORY {
                records.completed.pop_front();
            }
            records.completed.push_back(record);
        }
    }
}

pub(crate) async fn run<F, T>(kind: Kind, call: F) -> Result<T, Error>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    JOBS.run(kind, call).await
}

/// Bounded process-local lifetime observations; `returned` is not a business verdict.
pub(crate) fn snapshot() -> Snapshot {
    JOBS.snapshot()
}
