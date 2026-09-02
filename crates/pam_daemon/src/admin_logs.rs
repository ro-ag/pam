//! The log half of the admin surface: `admin.log.compress` and
//! `admin.evidence.*`.
//!
//! These are ordinary admin ops in every way that matters — read
//! [`crate::admin`]'s module docs for the security model, because every
//! word of it applies here. The tripwire, the request row, the single
//! terminal audit row, the deadline, and the structural guard (no
//! [`crate::policy::classify`] entry, never a capability, never grantable)
//! are the same ones.
//!
//! # Why these exist at all
//!
//! Log compression is daemon-internal: flows and connector diagnoses will
//! call [`crate::log_service::LogService`] directly, and no agent ever
//! names it. What these four ops give a human is the observatory — drive a
//! log through the pipeline by hand, read every evidence row it left, and
//! watch the tokens-avoided odometer move. That is a GUI act, so it is an
//! `admin.*` op and nothing else.
//!
//! # The daemon reads the file, the human names it
//!
//! [`OP_LOG_COMPRESS`] takes an absolute path and reads it as the daemon's
//! own user. There is no sandbox here and none is claimed: the GUI runs as
//! that same user (see [`crate::admin`]'s wall-is-filesystem-permissions
//! note), so this reads exactly what the person at the keyboard could read
//! anyway. Relative paths are refused rather than resolved, because the
//! daemon's working directory is not a thing a human can reason about.
//!
//! # The evidence rows belong to the op's own request
//!
//! Evidence has a foreign key onto `request(id)`, and the request row a
//! compress writes under is the admin envelope's own. So the rows are
//! findable exactly where the GUI already looks: expand the request in
//! Activity and the strip is there.

use std::time::{SystemTime, UNIX_EPOCH};

use pam_compact::{Compacted, MAX_SOURCE_BYTES};
use pam_proto::Outcome;
use pam_store::{EVIDENCE_KIND_LOG_COMPACT, EvidenceMeta, EvidenceRow};
use serde_json::{Value, json};

use crate::admin::{
    AdminOk, AdminRefusal, AdminService, CAUSE_INVALID_ADMIN_ARGS, RECOVERY_FIX_ARGS,
    RECOVERY_INTERNAL, required_str,
};
use crate::daemon::CAUSE_INTERNAL_ERROR;
use crate::log_service::CompressInput;

/// `admin.log.compress { path, exit_status?, model? }` → a
/// [`crate::log_service::CompressReport`].
pub const OP_LOG_COMPRESS: &str = "admin.log.compress";

/// `admin.evidence.list { request_id }` → the request's rows, no blobs.
pub const OP_EVIDENCE_LIST: &str = "admin.evidence.list";

/// `admin.evidence.get { id, max_bytes? }` → one row, readable.
pub const OP_EVIDENCE_GET: &str = "admin.evidence.get";

/// `admin.evidence.stats { since_ts? }` → the odometer's figures.
pub const OP_EVIDENCE_STATS: &str = "admin.evidence.stats";

/// Every op this module answers — the GUI bridge's whitelist reads it so
/// the two can never drift.
pub const LOG_ADMIN_OPS: &[&str] = &[
    OP_LOG_COMPRESS,
    OP_EVIDENCE_LIST,
    OP_EVIDENCE_GET,
    OP_EVIDENCE_STATS,
];

/// Refusal cause: the named file could not be measured or read.
pub const CAUSE_SOURCE_UNREADABLE: &str = "source_unreadable";

/// Refusal cause: the file is larger than [`MAX_SOURCE_BYTES`].
pub const CAUSE_SOURCE_TOO_LARGE: &str = "source_too_large";

/// Refusal cause: no evidence row carries that id.
pub const CAUSE_EVIDENCE_NOT_FOUND: &str = "not_found";

/// Bytes [`OP_EVIDENCE_GET`] returns when the caller names no budget.
pub const EVIDENCE_GET_DEFAULT_MAX_BYTES: u64 = 262_144;

/// Hard ceiling on [`OP_EVIDENCE_GET`]'s `max_bytes`.
pub const EVIDENCE_GET_MAX_BYTES: u64 = 4 * 1024 * 1024;

/// How far back [`OP_EVIDENCE_STATS`] looks when the caller names no
/// window: seven days.
pub const STATS_WINDOW_SECS: i64 = 7 * 24 * 60 * 60;

/// Recovery line for a path the daemon cannot read.
const RECOVERY_SOURCE_UNREADABLE: &str = "Check the path and that the daemon's user can read it.";

/// Recovery line for a log over the compaction bound.
const RECOVERY_SOURCE_TOO_LARGE: &str = "Split the log or trim it below 64 MiB before compressing.";

/// Recovery line for an evidence id that is not there.
const RECOVERY_EVIDENCE_PICK: &str =
    "Pick an evidence handle from the request's row in the PAM GUI Activity screen.";

impl AdminService {
    /// Answers one `admin.log.*` / `admin.evidence.*` op, or `None` when
    /// the capability belongs to another part of the admin surface.
    ///
    /// `envelope_id` is the admin request's own id: a compress files its
    /// evidence under it, which is what puts the rows on the request the
    /// GUI is already looking at.
    pub(crate) async fn dispatch_logs(
        &self,
        envelope_id: &str,
        op: &str,
        args: &Value,
    ) -> Option<Result<AdminOk, AdminRefusal>> {
        Some(match op {
            OP_LOG_COMPRESS => self.log_compress(envelope_id, args).await,
            OP_EVIDENCE_LIST => self.evidence_list(args).await,
            OP_EVIDENCE_GET => self.evidence_get(args).await,
            OP_EVIDENCE_STATS => self.evidence_stats(args).await,
            _ => return None,
        })
    }

    /// Reads the named log and runs it through the compression pipeline.
    async fn log_compress(&self, envelope_id: &str, args: &Value) -> Result<AdminOk, AdminRefusal> {
        let path = required_str(args, "path", OP_LOG_COMPRESS)?;
        let path = std::path::Path::new(path);
        if !path.is_absolute() {
            return Err(AdminRefusal {
                cause: CAUSE_INVALID_ADMIN_ARGS,
                detail: format!(
                    "{} is not an absolute path; the daemon's working directory is not yours",
                    path.display()
                ),
                recovery: RECOVERY_FIX_ARGS,
            });
        }
        let exit_status = match args.get("exit_status") {
            None | Some(Value::Null) => None,
            Some(value) => Some(
                value
                    .as_i64()
                    .and_then(|raw| i32::try_from(raw).ok())
                    .ok_or_else(|| AdminRefusal {
                        cause: CAUSE_INVALID_ADMIN_ARGS,
                        detail: format!("{value} is not an exit status; expected a 32-bit integer"),
                        recovery: RECOVERY_FIX_ARGS,
                    })?,
            ),
        };
        let use_model = args.get("model").and_then(Value::as_bool).unwrap_or(true);

        // Size first, from the metadata: an oversized log is refused
        // without ever pulling 64 MiB into the daemon's memory.
        let metadata = tokio::fs::metadata(path)
            .await
            .map_err(|err| unreadable(path, &err))?;
        let maximum = u64::try_from(MAX_SOURCE_BYTES).unwrap_or(u64::MAX);
        if metadata.len() > maximum {
            return Err(AdminRefusal {
                cause: CAUSE_SOURCE_TOO_LARGE,
                detail: format!(
                    "{} is {} bytes; the maximum is {MAX_SOURCE_BYTES}",
                    path.display(),
                    metadata.len()
                ),
                recovery: RECOVERY_SOURCE_TOO_LARGE,
            });
        }
        let bytes = tokio::fs::read(path)
            .await
            .map_err(|err| unreadable(path, &err))?;
        let name = path.file_name().map_or_else(
            || path.display().to_string(),
            |name| name.to_string_lossy().into_owned(),
        );

        let report = self
            .logs
            .compress(
                envelope_id,
                CompressInput {
                    name: name.clone(),
                    bytes,
                    exit_status,
                    use_model,
                },
            )
            .await
            .map_err(|err| AdminRefusal {
                cause: err.cause(),
                detail: err.to_string(),
                recovery: RECOVERY_INTERNAL,
            })?;

        let audit = json!({
            "op": OP_LOG_COMPRESS,
            "name": name,
            "source_bytes": report.stats.source_bytes,
            "compact_bytes": report.stats.compact_bytes,
            "tokens_avoided_est": report.stats.tokens_avoided_est,
            "summarized": report.summary.is_some(),
            "model_skipped": report.model_skipped.as_ref().map(|skip| skip.cause.clone()),
        });
        let body = serde_json::to_value(&report).map_err(|err| AdminRefusal {
            cause: CAUSE_INTERNAL_ERROR,
            detail: format!("the compression report did not serialize: {err}"),
            recovery: RECOVERY_INTERNAL,
        })?;
        Ok(AdminOk {
            outcome: Outcome::Solved,
            body,
            audit,
        })
    }

    /// Every evidence row of one request, blobs left in the database.
    ///
    /// A request with no evidence is an empty list, not a refusal: most
    /// requests have none, and the GUI asks for every row it expands.
    async fn evidence_list(&self, args: &Value) -> Result<AdminOk, AdminRefusal> {
        let request_id = required_str(args, "request_id", OP_EVIDENCE_LIST)?;
        let rows = self.store.list_evidence(request_id).await?;
        let evidence: Vec<Value> = rows.iter().map(meta_value).collect();
        Ok(AdminOk {
            outcome: Outcome::Verified,
            body: json!({ "evidence": evidence }),
            audit: json!({
                "op": OP_EVIDENCE_LIST,
                "request_id": request_id,
                "count": rows.len(),
            }),
        })
    }

    /// One evidence row, rendered for a reader and bounded in size.
    async fn evidence_get(&self, args: &Value) -> Result<AdminOk, AdminRefusal> {
        let id = required_str(args, "id", OP_EVIDENCE_GET)?;
        let max_bytes = args
            .get("max_bytes")
            .and_then(Value::as_u64)
            .unwrap_or(EVIDENCE_GET_DEFAULT_MAX_BYTES)
            .clamp(1, EVIDENCE_GET_MAX_BYTES);
        let row = self
            .store
            .get_evidence(id)
            .await?
            .ok_or_else(|| AdminRefusal {
                cause: CAUSE_EVIDENCE_NOT_FOUND,
                detail: format!("no evidence row carries the id {id:?}"),
                recovery: RECOVERY_EVIDENCE_PICK,
            })?;

        let (text, text_bytes, truncated) = readable_text(&row, max_bytes);
        // `bytes` is the blob length, exactly as `admin.evidence.list`
        // reports it, so one handle never shows two sizes across the two
        // ops. `text_bytes` is the length of what `text` is a prefix of —
        // for a `log.compact` row the rendered text, everywhere else the
        // blob again — which is what makes `truncated` mean something.
        let mut body = meta_value(&EvidenceMeta {
            id: row.id.clone(),
            request_id: row.request_id.clone(),
            kind: row.kind.clone(),
            bytes: u64::try_from(row.content.len()).unwrap_or(u64::MAX),
            content_hash: row.content_hash.clone(),
            meta_json: row.meta_json.clone(),
            ts: row.ts,
        });
        if let Some(object) = body.as_object_mut() {
            object.insert("text".to_owned(), json!(text));
            object.insert("text_bytes".to_owned(), json!(text_bytes));
            object.insert("truncated".to_owned(), json!(truncated));
        }
        Ok(AdminOk {
            outcome: Outcome::Verified,
            body,
            audit: json!({
                "op": OP_EVIDENCE_GET,
                "id": row.id,
                "kind": row.kind,
                "truncated": truncated,
            }),
        })
    }

    /// The tokens-avoided odometer's figures over a window.
    async fn evidence_stats(&self, args: &Value) -> Result<AdminOk, AdminRefusal> {
        let since_ts = match args.get("since_ts") {
            None | Some(Value::Null) => now_ts().saturating_sub(STATS_WINDOW_SECS),
            Some(value) => value.as_i64().ok_or_else(|| AdminRefusal {
                cause: CAUSE_INVALID_ADMIN_ARGS,
                detail: format!("{value} is not a unix timestamp in seconds"),
                recovery: RECOVERY_FIX_ARGS,
            })?,
        };
        let stats = self.store.compression_stats(since_ts).await?;
        Ok(AdminOk {
            outcome: Outcome::Verified,
            body: json!({
                "since_ts": since_ts,
                "compressions": stats.compressions,
                "source_bytes": stats.source_bytes,
                "compact_bytes": stats.compact_bytes,
                "tokens_avoided_est": stats.tokens_avoided_est,
            }),
            audit: json!({ "op": OP_EVIDENCE_STATS, "since_ts": since_ts }),
        })
    }
}

/// One listing entry: the row's identity and figures, its `meta_json`
/// parsed back into JSON so the GUI reads an object rather than a string.
fn meta_value(row: &EvidenceMeta) -> Value {
    json!({
        "id": row.id,
        "request_id": row.request_id,
        "kind": row.kind,
        "bytes": row.bytes,
        "sha256": row.content_hash,
        "meta": row
            .meta_json
            .as_deref()
            .and_then(|raw| serde_json::from_str::<Value>(raw).ok()),
        "ts": row.ts,
    })
}

/// What a reader wants out of one evidence row: the text, its **full**
/// length in bytes, and whether the text is only a prefix of it.
///
/// A `log.compact` row stores the JSON report — that is the provenance
/// map, not something anyone reads — so what comes back is its
/// `rendered_text`, and the length returned is that text's, not the
/// blob's. Everything else is its own bytes, where the two agree. The cut
/// is by byte count and the conversion is lossy, so a cut through a
/// multi-byte character costs one replacement character, which is the
/// honest thing for a bounded preview to do.
fn readable_text(row: &EvidenceRow, max_bytes: u64) -> (String, u64, bool) {
    let rendered;
    let source: &[u8] = if row.kind == EVIDENCE_KIND_LOG_COMPACT {
        match serde_json::from_slice::<Compacted>(&row.content) {
            Ok(report) => {
                rendered = report.rendered_text;
                rendered.as_bytes()
            }
            Err(error) => {
                tracing::warn!(evidence_id = %row.id, %error, "unreadable compaction report");
                &row.content
            }
        }
    } else {
        &row.content
    };
    let text_bytes = u64::try_from(source.len()).unwrap_or(u64::MAX);
    let cut = usize::try_from(max_bytes)
        .unwrap_or(usize::MAX)
        .min(source.len());
    (
        String::from_utf8_lossy(&source[..cut]).into_owned(),
        text_bytes,
        text_bytes > max_bytes,
    )
}

/// The refusal a file the daemon cannot measure or read earns.
fn unreadable(path: &std::path::Path, err: &std::io::Error) -> AdminRefusal {
    AdminRefusal {
        cause: CAUSE_SOURCE_UNREADABLE,
        detail: format!("cannot read {}: {err}", path.display()),
        recovery: RECOVERY_SOURCE_UNREADABLE,
    }
}

/// Current time as unix seconds.
fn now_ts() -> i64 {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    i64::try_from(secs).unwrap_or(i64::MAX)
}
