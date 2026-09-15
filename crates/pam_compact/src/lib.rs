//! Deterministic, provenance-preserving log reduction.
//!
//! Takes the exact bytes of a log and returns a smaller rendering plus a byte-range map of
//! where every source byte went; byte-based, locale-independent, deterministic — nothing
//! here interprets the log, calls a model, or knows the daemon. In order: (1) **Records**
//! split on `\r\n`, `\n`, bare `\r`; an unterminated tail counts as a line. (2) **Display
//! form** strips escapes, lossy UTF-8, control chars as `\t`/`\xNN`/`\u{...}`. (3)
//! **Omissions** drop progress frames a later record overwrites, then identical adjacent
//! forms. (4) **Retention** keeps first/last `boundary_records` plus any failure-keyword
//! record and neighbours. (5) **Fragments** render retained records, merge same-reason
//! omissions into `[... N ...]`; fragments stay contiguous and ordered, so replaying byte
//! ranges rebuilds the source exactly.
//! ```
//! use pam_compact::{Policy, compact};
//!
//! let report = compact(b"building\nerror: boom\n", Some(1), &Policy::default())?;
//! assert!(report.rendered_text.ends_with("[exit status: 1]\n"));
//! # Ok::<(), pam_compact::CompactError>(())
//! ```

#![forbid(unsafe_code)]

pub mod compact;

pub use compact::{
    ALGORITHM_VERSION, CompactError, Compacted, DEFAULT_BOUNDARY_RECORDS,
    DEFAULT_FAILURE_CONTEXT_RECORDS, FailureKeyword, Fragment, FragmentKind,
    MAX_FAILURE_CONTEXT_RECORDS, MAX_SOURCE_BYTES, MAX_SOURCE_RECORDS, OmissionReason, Policy,
    RetentionReason, compact, estimate_tokens, sha256_hex,
};

#[cfg(test)]
mod compact_test;
