//! Deterministic, provenance-preserving log reduction.
//!
//! `pam_compact` takes the exact bytes of a build or test log and returns a
//! smaller rendering of it plus a complete map of where every source byte
//! went. Nothing here interprets the log, calls a model, or knows about the
//! daemon: parsing and rendering are byte-based, locale-independent, and the
//! same input always produces the same output.
//!
//! The reduction is structural, in the order the algorithm applies it:
//!
//! 1. **Records** — split on `\r\n`, `\n` (lines) and bare `\r` (progress
//!    frames); an unterminated tail is a line.
//! 2. **Display form** — terminal escape sequences stripped, lossy UTF-8,
//!    control characters rendered as `\t`, `\xNN` or `\u{...}`.
//! 3. **Omissions** — all but the last frame of a progress run, then
//!    adjacent records with an identical display form.
//! 4. **Retention** — the first and last `boundary_records` of what
//!    survived, plus every record containing a failure keyword and its
//!    neighbours.
//! 5. **Fragments** — retained records render themselves; consecutive
//!    omissions with the same reason merge into one `[... N ... ]` marker.
//!    Fragments are contiguous and ordered, so reading their byte ranges
//!    from the source in order rebuilds the original exactly.
//!
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
