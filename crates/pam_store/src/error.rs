use std::fmt;
use std::path::PathBuf;

/// Primary result codes of the engine this crate classifies. The values are
/// part of `SQLite`'s stable C interface.
const PRIMARY_BUSY: i32 = 5;
const PRIMARY_LOCKED: i32 = 6;
const PRIMARY_CORRUPT: i32 = 11;
const PRIMARY_CONSTRAINT: i32 = 19;
const PRIMARY_NOT_A_DATABASE: i32 = 26;

/// Longest engine message kept on an error.
const MESSAGE_LIMIT: usize = 512;

/// Everything that can go wrong while opening or using the store.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The parent directory for the database file could not be created.
    #[error("failed to create store directory {path:?}: {source}")]
    CreateDir {
        /// Directory that could not be created.
        path: PathBuf,
        /// Underlying filesystem error.
        source: std::io::Error,
    },

    /// The database path is not valid UTF-8, which the engine requires.
    #[error("database path {path:?} is not valid UTF-8")]
    NonUtf8Path {
        /// The offending path.
        path: PathBuf,
    },

    /// The database was written by a newer `pam` than this binary.
    #[error(
        "database schema version {found} is newer than this binary supports \
         (max {supported}); upgrade pam instead of downgrading the database"
    )]
    VersionTooNew {
        /// Schema version recorded in the database.
        found: i64,
        /// Highest schema version this binary knows.
        supported: i64,
    },

    /// A terminal-only operation was handed a non-terminal state.
    #[error(
        "request state {state:?} is not terminal; only done, refused or \
         failed may be recorded as a final state"
    )]
    NotTerminal {
        /// The offending state's column value.
        state: &'static str,
    },

    /// A terminal state was handed to the non-terminal state helper;
    /// terminal transitions go through `Store::finish_request`, which
    /// writes the audit row in the same transaction.
    #[error(
        "request state {state:?} is terminal; record it through finish_request \
         so its audit row lands in the same transaction"
    )]
    TerminalTransition {
        /// The offending state's column value.
        state: &'static str,
    },

    /// A row referenced by id does not exist.
    #[error("no {table} row with id {id}")]
    NotFound {
        /// Table that was queried.
        table: &'static str,
        /// Id that was looked up.
        id: String,
    },

    /// A stored value does not match any variant this binary knows.
    #[error("unrecognized {column} value {value:?} in store")]
    UnexpectedValue {
        /// Column the value came from.
        column: &'static str,
        /// The offending stored value.
        value: String,
    },

    /// A request already reached `done`, `refused` or `failed`; those states
    /// are absorbing, so a later non-terminal transition is refused rather
    /// than written over the recorded verdict.
    #[error(
        "request {id} is already terminal; a finished request never returns \
         to an in-flight state"
    )]
    AlreadyTerminal {
        /// The request that had already finished.
        id: String,
    },

    /// A store call ended with its transaction still open and the rollback
    /// that should have cleared it failed; the connection is refused from
    /// then on rather than reused inside that transaction.
    #[error(
        "the store connection is stuck inside an abandoned transaction; \
         restart the pam daemon to recover it"
    )]
    AbandonedTransaction,

    /// The database file failed the engine's own consistency check, or the
    /// engine could not read its structure at all.
    #[error(
        "database integrity check failed: {detail}; stop the daemon and keep a \
         copy of the state file before repairing it or restoring a backup"
    )]
    Corrupt {
        /// What the engine reported, bounded.
        detail: String,
    },

    /// The call did not run to an answer: its work panicked, or the runtime
    /// that carries the store's blocking work is shutting down. A write the
    /// call was making either committed whole or not at all.
    #[error(
        "the store could not complete the call: {detail}; retry it, and \
         restart the pam daemon if it keeps failing"
    )]
    Unavailable {
        /// What stopped the call, bounded.
        detail: String,
    },

    /// Any underlying database engine failure.
    #[error("database error: {0}")]
    Database(#[source] EngineError),
}

/// A failure reported by the database engine, without naming the engine's
/// own types: its result code, the message it gave, and the two questions a
/// caller may reasonably ask of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineError {
    code: i32,
    message: String,
}

impl EngineError {
    pub(crate) fn new(code: i32, message: &str) -> Self {
        Self {
            code,
            message: message.chars().take(MESSAGE_LIMIT).collect(),
        }
    }

    /// The engine's extended result code (`SQLite`'s numbering), or `0` when
    /// the failure came from the client layer rather than the engine: a
    /// column read as the wrong type, a wrong number of bound values.
    #[must_use]
    pub fn code(&self) -> i32 {
        self.code
    }

    /// The engine's own words for the failure.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// A constraint refused the write: a primary key or unique index, a
    /// foreign key, a `CHECK`, a `NOT NULL`, or a trigger's `RAISE(ABORT)`.
    #[must_use]
    pub fn is_constraint(&self) -> bool {
        self.code & 0xff == PRIMARY_CONSTRAINT
    }

    /// Another connection held the database for longer than the busy
    /// timeout. Nothing was written; the call can be repeated.
    #[must_use]
    pub fn is_busy(&self) -> bool {
        matches!(self.code & 0xff, PRIMARY_BUSY | PRIMARY_LOCKED)
    }
}

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_busy() {
            // The engine's "database is locked" does not say who or what to do.
            write!(
                f,
                "{} (another process held the database file past the busy timeout; \
                 nothing was written, retry the call)",
                self.message
            )
        } else {
            f.write_str(&self.message)
        }
    }
}

impl std::error::Error for EngineError {}

/// Turns an engine failure into the store's own error.
///
/// The engine's corruption verdicts become [`StoreError::Corrupt`] wherever
/// they surface, so a damaged file reads the same at open, in the boot check,
/// and half-way through a request; every other failure is a
/// [`StoreError::Database`] carrying the engine's code and message. A plain
/// function, not a `From` impl: the conversion would put the engine's error
/// type into this crate's public interface.
pub(crate) fn engine(error: rusqlite::Error) -> StoreError {
    match error {
        rusqlite::Error::SqliteFailure(failure, message) => {
            let message = message.unwrap_or_else(|| failure.to_string());
            if matches!(
                failure.extended_code & 0xff,
                PRIMARY_CORRUPT | PRIMARY_NOT_A_DATABASE
            ) {
                StoreError::Corrupt {
                    detail: message.chars().take(200).collect(),
                }
            } else {
                StoreError::Database(EngineError::new(failure.extended_code, &message))
            }
        }
        other => StoreError::Database(EngineError::new(0, &other.to_string())),
    }
}
