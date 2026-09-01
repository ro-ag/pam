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

    /// Any underlying database engine failure.
    #[error("database error: {0}")]
    Database(#[from] turso::Error),
}
