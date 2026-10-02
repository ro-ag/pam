use std::path::PathBuf;

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

    /// A store call was dropped inside a transaction and the rollback that
    /// should have cleared it failed; the connection is refused rather than
    /// reused inside somebody else's transaction.
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

    /// Any underlying database engine failure.
    #[error("database error: {0}")]
    Database(#[source] turso::Error),
}

impl From<turso::Error> for StoreError {
    /// The engine's own corruption verdicts become [`StoreError::Corrupt`]
    /// wherever they surface, so a damaged file reads the same at open, in
    /// the boot check, and half-way through a request; every other engine
    /// failure stays [`StoreError::Database`].
    fn from(error: turso::Error) -> Self {
        match error {
            turso::Error::Corrupt(detail) | turso::Error::NotAdb(detail) => Self::Corrupt {
                detail: detail.chars().take(200).collect(),
            },
            other => Self::Database(other),
        }
    }
}
