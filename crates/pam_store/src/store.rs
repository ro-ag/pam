use std::{path::Path, sync::mpsc, thread, time::Duration};

use pam_core::{EvidenceHandle, ProjectId, RequestId};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use tokio::sync::{mpsc as tokio_mpsc, oneshot};
use uuid::Uuid;

#[cfg(test)]
use std::path::PathBuf;

use crate::evidence::{self, EvidenceFiles};
use crate::{
    AcceptOutcome, AcceptRequest, CancelOutcome, EventRecord, EvidenceMetadata, Lease,
    LeasedRequest, PutEvidence, Replay, RequestSnapshot, RequestState, StoreError, StoredResult,
    TerminalState,
};

const COMMAND_CAPACITY: usize = 64;
const EVIDENCE_COMMAND_CAPACITY: usize = 8;
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
pub(super) const LATEST_SCHEMA_VERSION: u32 = 2;
const MIGRATIONS: &[(u32, &str)] = &[
    (1, include_str!("../migrations/0001_initial.sql")),
    (2, include_str!("../migrations/0002_evidence.sql")),
];

type Response<T> = oneshot::Sender<Result<T, StoreError>>;

#[derive(Clone)]
pub struct Store {
    commands: tokio_mpsc::Sender<Command>,
    evidence_commands: tokio_mpsc::Sender<EvidenceCommand>,
}

impl Store {
    /// Opens a file-backed store and starts isolated scheduler and evidence workers.
    ///
    /// # Errors
    ///
    /// Returns a store error when the directory, database, configuration, or
    /// embedded migrations cannot be prepared. Existing corrupt or future-version
    /// databases are left in place.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.as_ref().to_path_buf();
        let (command_tx, command_rx) = tokio_mpsc::channel(COMMAND_CAPACITY);
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let scheduler_path = path.clone();

        thread::Builder::new()
            .name("pam-sqlite-scheduler".to_owned())
            .spawn(move || match open_connection(&scheduler_path) {
                Ok(connection) => {
                    let _ = ready_tx.send(Ok(()));
                    run_worker(connection, command_rx);
                }
                Err(error) => {
                    let _ = ready_tx.send(Err(error));
                }
            })?;

        ready_rx.recv().map_err(|_| StoreError::WorkerStopped)??;
        let (evidence_tx, evidence_rx) = tokio_mpsc::channel(EVIDENCE_COMMAND_CAPACITY);
        let (evidence_ready_tx, evidence_ready_rx) = mpsc::sync_channel(1);
        thread::Builder::new()
            .name("pam-evidence".to_owned())
            .spawn(move || match open_evidence_worker(&path) {
                Ok((connection, files)) => {
                    let _ = evidence_ready_tx.send(Ok(()));
                    run_evidence_worker(connection, files, evidence_rx);
                }
                Err(error) => {
                    let _ = evidence_ready_tx.send(Err(error));
                }
            })?;
        evidence_ready_rx
            .recv()
            .map_err(|_| StoreError::WorkerStopped)??;
        Ok(Self {
            commands: command_tx,
            evidence_commands: evidence_tx,
        })
    }

    /// Durably accepts an operation or returns its canonical idempotent request.
    ///
    /// # Errors
    ///
    /// Returns an idempotency conflict when the scoped key was used for different
    /// operation bytes, or a store error when persistence fails.
    pub async fn accept(
        &self,
        request: AcceptRequest,
        now_ms: u64,
    ) -> Result<AcceptOutcome, StoreError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.send(Command::Accept {
            request,
            now_ms,
            response: response_tx,
        })
        .await?;
        receive(response_rx).await
    }

    /// Claims the oldest eligible request while preserving per-project FIFO.
    ///
    /// # Errors
    ///
    /// Returns a store error for invalid lease time or database failure.
    pub async fn claim(
        &self,
        owner: impl Into<String>,
        now_ms: u64,
        lease_duration_ms: u64,
    ) -> Result<Option<LeasedRequest>, StoreError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.send(Command::Claim {
            owner: owner.into(),
            now_ms,
            lease_duration_ms,
            response: response_tx,
        })
        .await?;
        receive(response_rx).await
    }

    /// Renews a live lease and returns its updated fencing value.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::StaleLease`] when the lease no longer owns the request.
    pub async fn renew(
        &self,
        lease: Lease,
        now_ms: u64,
        lease_duration_ms: u64,
    ) -> Result<Lease, StoreError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.send(Command::Renew {
            lease,
            now_ms,
            lease_duration_ms,
            response: response_tx,
        })
        .await?;
        receive(response_rx).await
    }

    /// Recovers expired leases without releasing cancellation-requested work early.
    ///
    /// Ordinary leases return to their original FIFO positions. Cancellation-requested
    /// leases become terminally cancelled with their persisted result.
    ///
    /// # Errors
    ///
    /// Returns a store error when recovery cannot be committed atomically.
    pub async fn recover_expired(&self, now_ms: u64) -> Result<u64, StoreError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.send(Command::RecoverExpired {
            now_ms,
            response: response_tx,
        })
        .await?;
        receive(response_rx).await
    }

    /// Recovers expired leases and returns every transitioned request in order.
    ///
    /// Ordinary leases are returned after being requeued; cancellation-requested
    /// leases are returned after becoming terminally cancelled. Repeating the call
    /// returns an empty vector and creates no duplicate events.
    ///
    /// # Errors
    ///
    /// Returns a store error when recovery cannot be committed atomically.
    pub async fn recover_expired_requests(
        &self,
        now_ms: u64,
    ) -> Result<Vec<RequestId>, StoreError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.send(Command::RecoverExpiredRequests {
            now_ms,
            response: response_tx,
        })
        .await?;
        receive(response_rx).await
    }

    /// Resolves every active lease at daemon startup.
    ///
    /// This operation is intended to run only after the daemon has acquired
    /// exclusive process ownership. Ordinary leases return to their original FIFO
    /// positions, while cancellation-requested leases become terminally cancelled.
    /// Repeating it is safe and adds no duplicate recovery events.
    ///
    /// # Errors
    ///
    /// Returns a store error when recovery cannot be committed atomically.
    pub async fn recover_all_leases(&self, now_ms: u64) -> Result<u64, StoreError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.send(Command::RecoverAllLeases {
            now_ms,
            response: response_tx,
        })
        .await?;
        receive(response_rx).await
    }

    /// Appends a durable event while the supplied lease remains live.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::StaleLease`] when the lease is expired or fenced out.
    pub async fn append_event(
        &self,
        lease: Lease,
        now_ms: u64,
        kind: impl Into<String>,
        payload: Vec<u8>,
    ) -> Result<EventRecord, StoreError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.send(Command::AppendEvent {
            lease,
            now_ms,
            kind: kind.into(),
            payload,
            response: response_tx,
        })
        .await?;
        receive(response_rx).await
    }

    /// Commits a worker acknowledgement and its terminal event together.
    ///
    /// A cancellation request always becomes cancelled with its previously persisted
    /// result; the supplied success or failure cannot override it.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::StaleLease`] when another terminal transition or
    /// lease recovery won the race.
    pub async fn finish(
        &self,
        lease: Lease,
        now_ms: u64,
        terminal_state: TerminalState,
        result: Vec<u8>,
    ) -> Result<StoredResult, StoreError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.send(Command::Finish {
            lease,
            now_ms,
            terminal_state,
            result,
            response: response_tx,
        })
        .await?;
        receive(response_rx).await
    }

    /// Cancels queued work or durably requests cancellation of leased work.
    ///
    /// A leased request retains its fencing token and project gate until `finish` or
    /// lease recovery acknowledges the cancellation.
    ///
    /// # Errors
    ///
    /// Returns a store error if the request is absent or the transition fails.
    pub async fn cancel(
        &self,
        request_id: RequestId,
        now_ms: u64,
        result: Vec<u8>,
    ) -> Result<CancelOutcome, StoreError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.send(Command::Cancel {
            request_id,
            now_ms,
            result,
            response: response_tx,
        })
        .await?;
        receive(response_rx).await
    }

    /// Replays events strictly after `after_sequence` and includes a terminal result.
    ///
    /// # Errors
    ///
    /// Returns a store error when the request is absent or stored data is invalid.
    pub async fn replay(
        &self,
        request_id: RequestId,
        after_sequence: u64,
    ) -> Result<Replay, StoreError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.send(Command::Replay {
            request_id,
            after_sequence,
            response: response_tx,
        })
        .await?;
        receive(response_rx).await
    }

    /// Loads scheduler metadata for one request.
    ///
    /// # Errors
    ///
    /// Returns a store error when the request is absent or stored data is invalid.
    pub async fn snapshot(&self, request_id: RequestId) -> Result<RequestSnapshot, StoreError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.send(Command::Snapshot {
            request_id,
            response: response_tx,
        })
        .await?;
        receive(response_rx).await
    }

    /// Counts later, nonterminal queued requests for the same project.
    ///
    /// # Errors
    ///
    /// Returns a store error when the request is absent or the count cannot be read.
    pub async fn queued_behind(&self, request_id: RequestId) -> Result<u64, StoreError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.send(Command::QueuedBehind {
            request_id,
            response: response_tx,
        })
        .await?;
        receive(response_rx).await
    }

    /// Stores exact evidence bytes behind an immutable semantic handle.
    ///
    /// Exact content is globally deduplicated by SHA-256 while handle lookup remains
    /// project-scoped. Repeating an identical put is idempotent; reusing a handle for
    /// different bytes or metadata is rejected.
    ///
    /// # Errors
    ///
    /// Returns a store error for invalid or oversized metadata/content, an existing
    /// conflicting handle, an unsafe evidence path, or a persistence failure.
    pub async fn put_evidence(
        &self,
        evidence: PutEvidence,
        now_ms: u64,
    ) -> Result<EvidenceMetadata, StoreError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.send_evidence(EvidenceCommand::Put {
            evidence,
            now_ms,
            response: response_tx,
        })
        .await?;
        receive(response_rx).await
    }

    /// Inspects a project-scoped evidence handle and verifies its exact blob.
    ///
    /// # Errors
    ///
    /// Returns a store error when the handle is absent from the project or its blob
    /// is missing, corrupt, unsafe, or unreadable.
    pub async fn inspect_evidence(
        &self,
        project_id: ProjectId,
        handle: EvidenceHandle,
    ) -> Result<EvidenceMetadata, StoreError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.send_evidence(EvidenceCommand::Inspect {
            project_id,
            handle,
            response: response_tx,
        })
        .await?;
        receive(response_rx).await
    }

    /// Reads at most the requested bounded range from verified exact evidence.
    ///
    /// A range ending beyond the content is truncated at EOF. An offset beyond EOF
    /// or a range above [`crate::MAX_EVIDENCE_RANGE_BYTES`] is rejected.
    ///
    /// # Errors
    ///
    /// Returns a store error when the handle is absent from the project, the range
    /// is invalid, or the exact blob fails verification.
    pub async fn read_evidence_range(
        &self,
        project_id: ProjectId,
        handle: EvidenceHandle,
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>, StoreError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.send_evidence(EvidenceCommand::ReadRange {
            project_id,
            handle,
            offset,
            length,
            response: response_tx,
        })
        .await?;
        receive(response_rx).await
    }

    /// Stops both workers after all previously accepted commands have completed.
    ///
    /// # Errors
    ///
    /// Returns a store error when the worker has already stopped.
    pub async fn shutdown(self) -> Result<(), StoreError> {
        let (scheduler_tx, scheduler_rx) = oneshot::channel();
        let scheduler_result = match self.send(Command::Shutdown(scheduler_tx)).await {
            Ok(()) => receive(scheduler_rx).await,
            Err(error) => Err(error),
        };
        let (evidence_tx, evidence_rx) = oneshot::channel();
        let evidence_result = match self
            .send_evidence(EvidenceCommand::Shutdown(evidence_tx))
            .await
        {
            Ok(()) => receive(evidence_rx).await,
            Err(error) => Err(error),
        };
        scheduler_result?;
        evidence_result
    }

    async fn send(&self, command: Command) -> Result<(), StoreError> {
        self.commands
            .send(command)
            .await
            .map_err(|_| StoreError::WorkerStopped)
    }

    async fn send_evidence(&self, command: EvidenceCommand) -> Result<(), StoreError> {
        self.evidence_commands
            .send(command)
            .await
            .map_err(|_| StoreError::WorkerStopped)
    }

    #[cfg(test)]
    pub(super) async fn hold_evidence_worker(
        &self,
        entered: mpsc::SyncSender<()>,
        release: mpsc::Receiver<()>,
    ) -> Result<(), StoreError> {
        self.send_evidence(EvidenceCommand::Hold { entered, release })
            .await
    }
}

async fn receive<T>(response: oneshot::Receiver<Result<T, StoreError>>) -> Result<T, StoreError> {
    response.await.map_err(|_| StoreError::WorkerStopped)?
}

enum Command {
    Accept {
        request: AcceptRequest,
        now_ms: u64,
        response: Response<AcceptOutcome>,
    },
    Claim {
        owner: String,
        now_ms: u64,
        lease_duration_ms: u64,
        response: Response<Option<LeasedRequest>>,
    },
    Renew {
        lease: Lease,
        now_ms: u64,
        lease_duration_ms: u64,
        response: Response<Lease>,
    },
    RecoverExpired {
        now_ms: u64,
        response: Response<u64>,
    },
    RecoverExpiredRequests {
        now_ms: u64,
        response: Response<Vec<RequestId>>,
    },
    RecoverAllLeases {
        now_ms: u64,
        response: Response<u64>,
    },
    AppendEvent {
        lease: Lease,
        now_ms: u64,
        kind: String,
        payload: Vec<u8>,
        response: Response<EventRecord>,
    },
    Finish {
        lease: Lease,
        now_ms: u64,
        terminal_state: TerminalState,
        result: Vec<u8>,
        response: Response<StoredResult>,
    },
    Cancel {
        request_id: RequestId,
        now_ms: u64,
        result: Vec<u8>,
        response: Response<CancelOutcome>,
    },
    Replay {
        request_id: RequestId,
        after_sequence: u64,
        response: Response<Replay>,
    },
    Snapshot {
        request_id: RequestId,
        response: Response<RequestSnapshot>,
    },
    QueuedBehind {
        request_id: RequestId,
        response: Response<u64>,
    },
    Shutdown(Response<()>),
}

enum EvidenceCommand {
    Put {
        evidence: PutEvidence,
        now_ms: u64,
        response: Response<EvidenceMetadata>,
    },
    Inspect {
        project_id: ProjectId,
        handle: EvidenceHandle,
        response: Response<EvidenceMetadata>,
    },
    ReadRange {
        project_id: ProjectId,
        handle: EvidenceHandle,
        offset: u64,
        length: u64,
        response: Response<Vec<u8>>,
    },
    #[cfg(test)]
    Hold {
        entered: mpsc::SyncSender<()>,
        release: mpsc::Receiver<()>,
    },
    Shutdown(Response<()>),
}

fn run_worker(mut connection: Connection, mut commands: tokio_mpsc::Receiver<Command>) {
    while let Some(command) = commands.blocking_recv() {
        match command {
            Command::Accept {
                request,
                now_ms,
                response,
            } => respond(response, accept(&mut connection, request, now_ms)),
            Command::Claim {
                owner,
                now_ms,
                lease_duration_ms,
                response,
            } => respond(
                response,
                claim(&mut connection, owner, now_ms, lease_duration_ms),
            ),
            Command::Renew {
                lease,
                now_ms,
                lease_duration_ms,
                response,
            } => respond(
                response,
                renew(&mut connection, lease, now_ms, lease_duration_ms),
            ),
            Command::RecoverExpired { now_ms, response } => {
                respond(response, recover_expired(&mut connection, now_ms));
            }
            Command::RecoverExpiredRequests { now_ms, response } => {
                respond(response, recover_expired_requests(&mut connection, now_ms));
            }
            Command::RecoverAllLeases { now_ms, response } => {
                respond(response, recover_all_leases(&mut connection, now_ms));
            }
            Command::AppendEvent {
                lease,
                now_ms,
                kind,
                payload,
                response,
            } => respond(
                response,
                append_leased_event(&mut connection, &lease, now_ms, &kind, &payload),
            ),
            Command::Finish {
                lease,
                now_ms,
                terminal_state,
                result,
                response,
            } => respond(
                response,
                finish(&mut connection, &lease, now_ms, terminal_state, &result),
            ),
            Command::Cancel {
                request_id,
                now_ms,
                result,
                response,
            } => respond(
                response,
                cancel(&mut connection, &request_id, now_ms, &result),
            ),
            Command::Replay {
                request_id,
                after_sequence,
                response,
            } => respond(response, replay(&connection, &request_id, after_sequence)),
            Command::Snapshot {
                request_id,
                response,
            } => respond(response, snapshot(&connection, &request_id)),
            Command::QueuedBehind {
                request_id,
                response,
            } => respond(response, queued_behind(&mut connection, &request_id)),
            Command::Shutdown(response) => {
                drop(connection);
                respond(response, Ok(()));
                return;
            }
        }
    }
}

fn open_evidence_worker(path: &Path) -> Result<(Connection, EvidenceFiles), StoreError> {
    let connection = open_connection(path)?;
    let files = EvidenceFiles::open(path)?;
    Ok((connection, files))
}

fn run_evidence_worker(
    mut connection: Connection,
    files: EvidenceFiles,
    mut commands: tokio_mpsc::Receiver<EvidenceCommand>,
) {
    while let Some(command) = commands.blocking_recv() {
        match command {
            EvidenceCommand::Put {
                evidence,
                now_ms,
                response,
            } => respond(
                response,
                evidence::put(&mut connection, &files, evidence, now_ms),
            ),
            EvidenceCommand::Inspect {
                project_id,
                handle,
                response,
            } => respond(
                response,
                evidence::inspect(&connection, &files, &project_id, &handle),
            ),
            EvidenceCommand::ReadRange {
                project_id,
                handle,
                offset,
                length,
                response,
            } => respond(
                response,
                evidence::read_range(&connection, &files, &project_id, &handle, offset, length),
            ),
            #[cfg(test)]
            EvidenceCommand::Hold { entered, release } => {
                let _ = entered.send(());
                let _ = release.recv();
            }
            EvidenceCommand::Shutdown(response) => {
                drop(connection);
                drop(files);
                respond(response, Ok(()));
                return;
            }
        }
    }
}

fn respond<T>(response: Response<T>, result: Result<T, StoreError>) {
    let _ = response.send(result);
}

pub(super) fn open_connection(path: &Path) -> Result<Connection, StoreError> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
    }

    let mut connection = Connection::open(path)?;
    connection.busy_timeout(BUSY_TIMEOUT)?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    ensure_integrity(&connection)?;
    let journal_mode: String =
        connection.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
    if !journal_mode.eq_ignore_ascii_case("wal") {
        return Err(StoreError::InvalidState(format!(
            "journal mode {journal_mode}"
        )));
    }
    apply_migrations(&mut connection)?;
    ensure_integrity(&connection)?;
    ensure_foreign_keys(&connection)?;
    Ok(connection)
}

fn ensure_integrity(connection: &Connection) -> Result<(), StoreError> {
    let result: String = connection.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
    if result == "ok" {
        Ok(())
    } else {
        Err(StoreError::IntegrityCheckFailed(result))
    }
}

fn ensure_foreign_keys(connection: &Connection) -> Result<(), StoreError> {
    let violation = connection
        .query_row("PRAGMA foreign_key_check", [], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<i64>>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .optional()?;
    if let Some((table, row_id, parent)) = violation {
        Err(StoreError::ForeignKeyCheckFailed(format!(
            "table={table} row_id={row_id:?} parent={parent}"
        )))
    } else {
        Ok(())
    }
}

fn apply_migrations(connection: &mut Connection) -> Result<(), StoreError> {
    let found: u32 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if found > LATEST_SCHEMA_VERSION {
        return Err(StoreError::FutureSchema {
            found,
            supported: LATEST_SCHEMA_VERSION,
        });
    }

    for &(version, sql) in MIGRATIONS.iter().filter(|(version, _)| *version > found) {
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(sql)?;
        transaction.pragma_update(None, "user_version", version)?;
        transaction.commit()?;
    }
    Ok(())
}

fn accept(
    connection: &mut Connection,
    request: AcceptRequest,
    now_ms: u64,
) -> Result<AcceptOutcome, StoreError> {
    let now = sql_integer(now_ms)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let existing = transaction
        .query_row(
            "SELECT request_id, operation_kind, operation, state
             FROM requests
             WHERE caller_id = ?1 AND project_id = ?2 AND idempotency_key = ?3",
            params![
                request.caller_id.as_str(),
                request.project_id.as_str(),
                request.idempotency_key.as_str()
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .optional()?;

    if let Some((request_id, operation_kind, operation, state)) = existing {
        let canonical_request_id = RequestId::from(request_id);
        if operation_kind == request.operation_kind && operation == request.operation {
            return Ok(AcceptOutcome::Existing {
                request_id: canonical_request_id,
                state: parse_state(&state)?,
            });
        }
        return Err(StoreError::IdempotencyConflict {
            canonical_request_id,
        });
    }

    let request_id_exists = transaction
        .query_row(
            "SELECT 1 FROM requests WHERE request_id = ?1",
            [request.request_id.as_str()],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if request_id_exists {
        return Err(StoreError::RequestIdConflict(request.request_id));
    }

    transaction.execute(
        "INSERT OR IGNORE INTO projects(project_id) VALUES (?1)",
        [request.project_id.as_str()],
    )?;
    transaction.execute(
        "UPDATE projects
         SET next_queue_sequence = next_queue_sequence + 1
         WHERE project_id = ?1",
        [request.project_id.as_str()],
    )?;
    let queue_sequence: i64 = transaction.query_row(
        "SELECT next_queue_sequence - 1 FROM projects WHERE project_id = ?1",
        [request.project_id.as_str()],
        |row| row.get(0),
    )?;

    transaction.execute(
        "INSERT INTO requests(
            request_id, caller_id, project_id, idempotency_key,
            operation_kind, operation, queue_sequence, state, accepted_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'queued', ?8)",
        params![
            request.request_id.as_str(),
            request.caller_id.as_str(),
            request.project_id.as_str(),
            request.idempotency_key.as_str(),
            request.operation_kind,
            request.operation,
            queue_sequence,
            now
        ],
    )?;
    append_event_tx(&transaction, &request.request_id, now, "accepted", &[])?;
    transaction.commit()?;

    Ok(AcceptOutcome::Created {
        request_id: request.request_id,
        queue_sequence: unsigned_integer(queue_sequence)?,
    })
}

struct ClaimCandidate {
    request_id: String,
    project_id: String,
    operation_kind: String,
    operation: Vec<u8>,
    queue_sequence: i64,
    attempt: i64,
}

fn claim(
    connection: &mut Connection,
    owner: String,
    now_ms: u64,
    lease_duration_ms: u64,
) -> Result<Option<LeasedRequest>, StoreError> {
    let now = sql_integer(now_ms)?;
    let expires_at_ms = lease_expiry(now_ms, lease_duration_ms)?;
    let expires_at = sql_integer(expires_at_ms)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let candidate = transaction
        .query_row(
            "SELECT
                queued.request_id,
                queued.project_id,
                queued.operation_kind,
                queued.operation,
                queued.queue_sequence,
                queued.attempt
             FROM requests AS queued
             WHERE queued.state = 'queued'
               AND NOT EXISTS (
                   SELECT 1
                   FROM requests AS earlier
                   WHERE earlier.project_id = queued.project_id
                     AND earlier.state IN ('queued', 'leased', 'cancellation_requested')
                     AND earlier.queue_sequence < queued.queue_sequence
               )
               AND NOT EXISTS (
                   SELECT 1
                   FROM requests AS active
                   WHERE active.project_id = queued.project_id
                     AND active.state IN ('leased', 'cancellation_requested')
               )
             ORDER BY queued.accepted_at_ms, queued.rowid
             LIMIT 1",
            [],
            |row| {
                Ok(ClaimCandidate {
                    request_id: row.get(0)?,
                    project_id: row.get(1)?,
                    operation_kind: row.get(2)?,
                    operation: row.get(3)?,
                    queue_sequence: row.get(4)?,
                    attempt: row.get(5)?,
                })
            },
        )
        .optional()?;
    let Some(candidate) = candidate else {
        transaction.commit()?;
        return Ok(None);
    };

    let attempt = candidate
        .attempt
        .checked_add(1)
        .ok_or(StoreError::InvalidState("attempt overflow".to_owned()))?;
    let token = Uuid::new_v4().to_string();
    let changed = transaction.execute(
        "UPDATE requests
         SET state = 'leased', attempt = ?2, lease_owner = ?3,
             lease_token = ?4, lease_expires_at_ms = ?5
         WHERE request_id = ?1 AND state = 'queued'",
        params![candidate.request_id, attempt, owner, token, expires_at],
    )?;
    if changed != 1 {
        return Err(StoreError::InvalidState(
            "claim candidate changed state".to_owned(),
        ));
    }
    let request_id = RequestId::from(candidate.request_id);
    append_event_tx(&transaction, &request_id, now, "started", &[])?;
    transaction.commit()?;

    Ok(Some(LeasedRequest {
        lease: Lease {
            request_id,
            project_id: ProjectId::from(candidate.project_id),
            owner,
            token,
            attempt: unsigned_integer(attempt)?,
            expires_at_ms,
        },
        queue_sequence: unsigned_integer(candidate.queue_sequence)?,
        operation_kind: candidate.operation_kind,
        operation: candidate.operation,
    }))
}

fn renew(
    connection: &mut Connection,
    mut lease: Lease,
    now_ms: u64,
    lease_duration_ms: u64,
) -> Result<Lease, StoreError> {
    let now = sql_integer(now_ms)?;
    let expires_at_ms = lease_expiry(now_ms, lease_duration_ms)?;
    let expires_at = sql_integer(expires_at_ms)?;
    let changed = connection.execute(
        "UPDATE requests
         SET lease_expires_at_ms = ?5
         WHERE request_id = ?1 AND state IN ('leased', 'cancellation_requested')
           AND lease_owner = ?2 AND lease_token = ?3
           AND lease_expires_at_ms > ?4",
        params![
            lease.request_id.as_str(),
            lease.owner,
            lease.token,
            now,
            expires_at
        ],
    )?;
    if changed != 1 {
        return Err(StoreError::StaleLease(lease.request_id));
    }
    lease.expires_at_ms = expires_at_ms;
    Ok(lease)
}

fn recover_expired(connection: &mut Connection, now_ms: u64) -> Result<u64, StoreError> {
    let recovered = recover_expired_requests(connection, now_ms)?;
    u64::try_from(recovered.len())
        .map_err(|_| StoreError::InvalidState("recovery count overflow".to_owned()))
}

fn recover_expired_requests(
    connection: &mut Connection,
    now_ms: u64,
) -> Result<Vec<RequestId>, StoreError> {
    recover_leases(connection, now_ms, LeaseRecovery::Expired)
}

fn recover_all_leases(connection: &mut Connection, now_ms: u64) -> Result<u64, StoreError> {
    let recovered = recover_leases(connection, now_ms, LeaseRecovery::All)?;
    u64::try_from(recovered.len())
        .map_err(|_| StoreError::InvalidState("recovery count overflow".to_owned()))
}

#[derive(Clone, Copy)]
enum LeaseRecovery {
    Expired,
    All,
}

fn recover_leases(
    connection: &mut Connection,
    now_ms: u64,
    recovery: LeaseRecovery,
) -> Result<Vec<RequestId>, StoreError> {
    let now = sql_integer(now_ms)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let active_leases = active_leases(&transaction, now, recovery)?;

    let mut recovered = Vec::with_capacity(active_leases.len());
    for active in active_leases {
        let changed = match active.state {
            RequestState::Leased => {
                let changed = release_lease(&transaction, &active.request_id, now, recovery)?;
                if changed == 1 {
                    append_event_tx(
                        &transaction,
                        &RequestId::from(active.request_id.clone()),
                        now,
                        "lease_expired",
                        &[],
                    )?;
                }
                changed
            }
            RequestState::CancellationRequested => {
                let changed = finalize_recovered_cancellation(
                    &transaction,
                    &active.request_id,
                    now,
                    recovery,
                )?;
                if changed == 1 {
                    append_event_tx(
                        &transaction,
                        &RequestId::from(active.request_id.clone()),
                        now,
                        "cancelled",
                        &[],
                    )?;
                }
                changed
            }
            state => {
                return Err(StoreError::InvalidState(format!(
                    "recovery selected {}",
                    state.as_str()
                )));
            }
        };
        if changed == 1 {
            recovered.push(RequestId::from(active.request_id));
        }
    }
    transaction.commit()?;
    Ok(recovered)
}

struct ActiveLease {
    request_id: String,
    state: RequestState,
}

fn active_leases(
    transaction: &Transaction<'_>,
    now: i64,
    recovery: LeaseRecovery,
) -> Result<Vec<ActiveLease>, StoreError> {
    let stored = match recovery {
        LeaseRecovery::Expired => {
            let mut statement = transaction.prepare(
                "SELECT request_id, state
                 FROM requests
                 WHERE state IN ('leased', 'cancellation_requested')
                   AND lease_expires_at_ms <= ?1
                 ORDER BY accepted_at_ms, rowid",
            )?;
            statement
                .query_map([now], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })?
                .collect::<Result<Vec<_>, _>>()?
        }
        LeaseRecovery::All => {
            let mut statement = transaction.prepare(
                "SELECT request_id, state
                 FROM requests
                 WHERE state IN ('leased', 'cancellation_requested')
                 ORDER BY accepted_at_ms, rowid",
            )?;
            statement
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })?
                .collect::<Result<Vec<_>, _>>()?
        }
    };
    stored
        .into_iter()
        .map(|(request_id, state)| {
            Ok(ActiveLease {
                request_id,
                state: parse_state(&state)?,
            })
        })
        .collect()
}

fn finalize_recovered_cancellation(
    transaction: &Transaction<'_>,
    request_id: &str,
    now: i64,
    recovery: LeaseRecovery,
) -> Result<usize, StoreError> {
    let changed = match recovery {
        LeaseRecovery::Expired => transaction.execute(
            "UPDATE requests
             SET state = 'cancelled', lease_owner = NULL, lease_token = NULL,
                 lease_expires_at_ms = NULL, completed_at_ms = ?2
             WHERE request_id = ?1 AND state = 'cancellation_requested'
               AND lease_expires_at_ms <= ?2",
            params![request_id, now],
        )?,
        LeaseRecovery::All => transaction.execute(
            "UPDATE requests
             SET state = 'cancelled', lease_owner = NULL, lease_token = NULL,
                 lease_expires_at_ms = NULL, completed_at_ms = ?2
             WHERE request_id = ?1 AND state = 'cancellation_requested'",
            params![request_id, now],
        )?,
    };
    Ok(changed)
}

fn release_lease(
    transaction: &Transaction<'_>,
    request_id: &str,
    now: i64,
    recovery: LeaseRecovery,
) -> Result<usize, StoreError> {
    let changed = match recovery {
        LeaseRecovery::Expired => transaction.execute(
            "UPDATE requests
             SET state = 'queued', lease_owner = NULL, lease_token = NULL,
                 lease_expires_at_ms = NULL
             WHERE request_id = ?1 AND state = 'leased'
               AND lease_expires_at_ms <= ?2",
            params![request_id, now],
        )?,
        LeaseRecovery::All => transaction.execute(
            "UPDATE requests
             SET state = 'queued', lease_owner = NULL, lease_token = NULL,
                 lease_expires_at_ms = NULL
             WHERE request_id = ?1 AND state = 'leased'",
            [request_id],
        )?,
    };
    Ok(changed)
}

fn append_leased_event(
    connection: &mut Connection,
    lease: &Lease,
    now_ms: u64,
    kind: &str,
    payload: &[u8],
) -> Result<EventRecord, StoreError> {
    let now = sql_integer(now_ms)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    ensure_live_lease(&transaction, lease, now)?;
    let sequence = append_event_tx(&transaction, &lease.request_id, now, kind, payload)?;
    transaction.commit()?;
    Ok(EventRecord {
        sequence,
        kind: kind.to_owned(),
        payload: payload.to_vec(),
        recorded_at_ms: now_ms,
    })
}

fn finish(
    connection: &mut Connection,
    lease: &Lease,
    now_ms: u64,
    terminal_state: TerminalState,
    result: &[u8],
) -> Result<StoredResult, StoreError> {
    let now = sql_integer(now_ms)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let live = transaction
        .query_row(
            "SELECT state, result
             FROM requests
             WHERE request_id = ?1
               AND state IN ('leased', 'cancellation_requested')
               AND lease_owner = ?2 AND lease_token = ?3
               AND lease_expires_at_ms > ?4",
            params![lease.request_id.as_str(), lease.owner, lease.token, now],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<Vec<u8>>>(1)?)),
        )
        .optional()?
        .ok_or_else(|| StoreError::StaleLease(lease.request_id.clone()))?;
    let active_state = parse_state(&live.0)?;
    let (state, payload, event_kind, changed) = match (active_state, live.1) {
        (RequestState::Leased, None) => {
            let state = terminal_state.request_state();
            let changed = transaction.execute(
                "UPDATE requests
                 SET state = ?5, lease_owner = NULL, lease_token = NULL,
                     lease_expires_at_ms = NULL, completed_at_ms = ?4, result = ?6
                 WHERE request_id = ?1 AND state = 'leased'
                   AND lease_owner = ?2 AND lease_token = ?3
                   AND lease_expires_at_ms > ?4",
                params![
                    lease.request_id.as_str(),
                    lease.owner,
                    lease.token,
                    now,
                    state.as_str(),
                    result
                ],
            )?;
            (state, result.to_vec(), terminal_state.event_kind(), changed)
        }
        (RequestState::CancellationRequested, Some(cancellation_result)) => {
            let changed = transaction.execute(
                "UPDATE requests
                 SET state = 'cancelled', lease_owner = NULL, lease_token = NULL,
                     lease_expires_at_ms = NULL, completed_at_ms = ?4
                 WHERE request_id = ?1 AND state = 'cancellation_requested'
                   AND lease_owner = ?2 AND lease_token = ?3
                   AND lease_expires_at_ms > ?4",
                params![lease.request_id.as_str(), lease.owner, lease.token, now],
            )?;
            (
                RequestState::Cancelled,
                cancellation_result,
                "cancelled",
                changed,
            )
        }
        (state, _) => {
            return Err(StoreError::InvalidState(format!(
                "active request has {} result shape",
                state.as_str()
            )));
        }
    };
    if changed != 1 {
        return Err(StoreError::StaleLease(lease.request_id.clone()));
    }
    append_event_tx(&transaction, &lease.request_id, now, event_kind, &[])?;
    transaction.commit()?;

    Ok(StoredResult {
        state,
        payload,
        completed_at_ms: now_ms,
    })
}

fn cancel(
    connection: &mut Connection,
    request_id: &RequestId,
    now_ms: u64,
    result: &[u8],
) -> Result<CancelOutcome, StoreError> {
    let now = sql_integer(now_ms)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let stored_state = transaction
        .query_row(
            "SELECT state FROM requests WHERE request_id = ?1",
            [request_id.as_str()],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or_else(|| StoreError::RequestNotFound(request_id.clone()))?;
    let state = parse_state(&stored_state)?;
    let (changed, event_kind, outcome) = match state {
        RequestState::Queued => (
            transaction.execute(
                "UPDATE requests
                 SET state = 'cancelled', completed_at_ms = ?2, result = ?3
                 WHERE request_id = ?1 AND state = 'queued'",
                params![request_id.as_str(), now, result],
            )?,
            "cancelled",
            CancelOutcome::Cancelled,
        ),
        RequestState::Leased => (
            transaction.execute(
                "UPDATE requests
                 SET state = 'cancellation_requested', result = ?2
                 WHERE request_id = ?1 AND state = 'leased'",
                params![request_id.as_str(), result],
            )?,
            "cancellation_requested",
            CancelOutcome::CancellationRequested,
        ),
        RequestState::CancellationRequested => {
            return Ok(CancelOutcome::CancellationRequested);
        }
        RequestState::Succeeded | RequestState::Failed | RequestState::Cancelled => {
            return Ok(CancelOutcome::AlreadyTerminal(state));
        }
    };
    if changed != 1 {
        return Err(StoreError::InvalidState(
            "cancellation transition changed no request".to_owned(),
        ));
    }
    append_event_tx(&transaction, request_id, now, event_kind, &[])?;
    transaction.commit()?;
    Ok(outcome)
}

fn replay(
    connection: &Connection,
    request_id: &RequestId,
    after_sequence: u64,
) -> Result<Replay, StoreError> {
    let stored = connection
        .query_row(
            "SELECT state, result, completed_at_ms
             FROM requests WHERE request_id = ?1",
            [request_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<Vec<u8>>>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| StoreError::RequestNotFound(request_id.clone()))?;
    let state = parse_state(&stored.0)?;
    let result = match (state, stored.1, stored.2) {
        (
            RequestState::Succeeded | RequestState::Failed | RequestState::Cancelled,
            Some(payload),
            Some(completed_at_ms),
        ) => Some(StoredResult {
            state,
            payload,
            completed_at_ms: unsigned_integer(completed_at_ms)?,
        }),
        (RequestState::Queued | RequestState::Leased, None, None)
        | (RequestState::CancellationRequested, Some(_), None) => None,
        _ => {
            return Err(StoreError::InvalidState(
                "result does not match request state".to_owned(),
            ));
        }
    };

    let after = sql_integer(after_sequence)?;
    let mut statement = connection.prepare(
        "SELECT sequence, kind, payload, recorded_at_ms
         FROM events
         WHERE request_id = ?1 AND sequence > ?2
         ORDER BY sequence",
    )?;
    let events = statement
        .query_map(params![request_id.as_str(), after], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })?
        .map(|event| {
            let (sequence, kind, payload, recorded_at_ms) = event?;
            Ok(EventRecord {
                sequence: unsigned_integer(sequence)?,
                kind,
                payload,
                recorded_at_ms: unsigned_integer(recorded_at_ms)?,
            })
        })
        .collect::<Result<Vec<_>, StoreError>>()?;

    Ok(Replay { events, result })
}

fn snapshot(
    connection: &Connection,
    request_id: &RequestId,
) -> Result<RequestSnapshot, StoreError> {
    let stored = connection
        .query_row(
            "SELECT project_id, queue_sequence, state, attempt, lease_expires_at_ms
             FROM requests WHERE request_id = ?1",
            [request_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| StoreError::RequestNotFound(request_id.clone()))?;

    Ok(RequestSnapshot {
        request_id: request_id.clone(),
        project_id: ProjectId::from(stored.0),
        queue_sequence: unsigned_integer(stored.1)?,
        state: parse_state(&stored.2)?,
        attempt: unsigned_integer(stored.3)?,
        lease_expires_at_ms: stored.4.map(unsigned_integer).transpose()?,
    })
}

fn queued_behind(connection: &mut Connection, request_id: &RequestId) -> Result<u64, StoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    let position = transaction
        .query_row(
            "SELECT project_id, queue_sequence
             FROM requests WHERE request_id = ?1",
            [request_id.as_str()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()?
        .ok_or_else(|| StoreError::RequestNotFound(request_id.clone()))?;
    let count: i64 = transaction.query_row(
        "SELECT COUNT(*)
         FROM requests
         WHERE project_id = ?1 AND queue_sequence > ?2 AND state = 'queued'",
        params![position.0, position.1],
        |row| row.get(0),
    )?;
    transaction.commit()?;
    unsigned_integer(count)
}

fn ensure_live_lease(
    transaction: &Transaction<'_>,
    lease: &Lease,
    now: i64,
) -> Result<(), StoreError> {
    let live = transaction.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM requests
            WHERE request_id = ?1 AND state IN ('leased', 'cancellation_requested')
              AND lease_owner = ?2 AND lease_token = ?3
              AND lease_expires_at_ms > ?4
         )",
        params![lease.request_id.as_str(), lease.owner, lease.token, now],
        |row| row.get::<_, bool>(0),
    )?;
    if live {
        Ok(())
    } else {
        Err(StoreError::StaleLease(lease.request_id.clone()))
    }
}

fn append_event_tx(
    transaction: &Transaction<'_>,
    request_id: &RequestId,
    recorded_at_ms: i64,
    kind: &str,
    payload: &[u8],
) -> Result<u64, StoreError> {
    let sequence: i64 = transaction.query_row(
        "SELECT COALESCE(MAX(sequence), 0) + 1
         FROM events WHERE request_id = ?1",
        [request_id.as_str()],
        |row| row.get(0),
    )?;
    transaction.execute(
        "INSERT INTO events(request_id, sequence, kind, payload, recorded_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![request_id.as_str(), sequence, kind, payload, recorded_at_ms],
    )?;
    unsigned_integer(sequence)
}

fn parse_state(state: &str) -> Result<RequestState, StoreError> {
    match state {
        "queued" => Ok(RequestState::Queued),
        "leased" => Ok(RequestState::Leased),
        "cancellation_requested" => Ok(RequestState::CancellationRequested),
        "succeeded" => Ok(RequestState::Succeeded),
        "failed" => Ok(RequestState::Failed),
        "cancelled" => Ok(RequestState::Cancelled),
        _ => Err(StoreError::InvalidState(state.to_owned())),
    }
}

pub(super) fn sql_integer(value: u64) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| StoreError::TimestampOutOfRange(value))
}

pub(super) fn unsigned_integer(value: i64) -> Result<u64, StoreError> {
    u64::try_from(value).map_err(|_| StoreError::InvalidState(format!("negative integer {value}")))
}

fn lease_expiry(now_ms: u64, duration_ms: u64) -> Result<u64, StoreError> {
    if duration_ms == 0 {
        return Err(StoreError::LeaseDurationZero);
    }
    now_ms
        .checked_add(duration_ms)
        .ok_or(StoreError::LeaseExpiryOverflow)
}

#[cfg(test)]
pub(super) fn migration_versions() -> Vec<u32> {
    MIGRATIONS.iter().map(|(version, _)| *version).collect()
}

#[cfg(test)]
pub(super) fn busy_timeout_ms() -> u64 {
    u64::try_from(BUSY_TIMEOUT.as_millis()).expect("busy timeout fits u64")
}

#[cfg(test)]
pub(super) fn database_path(name: &str) -> (PathBuf, PathBuf) {
    use std::{
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    static NONCE: AtomicU64 = AtomicU64::new(0);
    let clock = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "pam-store-{name}-{}-{clock}-{}",
        std::process::id(),
        NONCE.fetch_add(1, Ordering::Relaxed)
    ));
    let path = directory.join("pam.sqlite3");
    (directory, path)
}
