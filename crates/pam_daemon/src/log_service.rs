//! Log compression: a deterministic reduction that always succeeds, and a
//! local-model summary that is allowed to fail.
//!
//! # The shape of the pipeline
//!
//! One call to [`LogService::compress`] leaves up to three evidence rows
//! under the caller's request id:
//!
//! 1. [`EVIDENCE_KIND_LOG_SOURCE`] — the exact bytes that came in. Nothing
//!    is normalized, trimmed or re-encoded: this row is what makes every
//!    later claim checkable, and what the fragment offsets in the compact
//!    report index into.
//! 2. [`pam_store::EVIDENCE_KIND_LOG_COMPACT`] — the [`pam_compact`]
//!    report serialized as JSON, fragments included. The fragments are the
//!    provenance map (every source byte belongs to exactly one), so the
//!    original is rebuilt by reading the ranges back from the source row
//!    in order. Its `meta_json` carries [`CompressStats`], which is what
//!    the tokens-avoided odometer aggregates without touching a blob.
//! 3. [`EVIDENCE_KIND_LOG_SUMMARY`] — the model's plain-text answer, when
//!    a model was asked and answered.
//!
//! # A model failure is never a compress failure
//!
//! The deterministic half is the product; the summary is a bonus. Every
//! way the model layer can decline — no tier default, the configured
//! weights missing, the runtime busy, a prompt over the context, a crash —
//! comes back as [`ModelSkipped`] with a cause the GUI can render, and the
//! compact result stands unchanged. A store failure on the *summary*
//! insert is downgraded the same way (cause [`CAUSE_STORE_ERROR`]): losing
//! a summary row must not throw away a compaction that already happened.
//! Only the bound check, the compaction itself, and the two evidence
//! writes that carry the deterministic result can fail the call.
//!
//! # Why the prompt is fitted, not truncated
//!
//! A reduced log is still allowed to be megabytes. The summary runs on the
//! heavy tier under an 8192-token context, so [`fit_prompt`] keeps the
//! head and the tail — where a build log puts its invocation and its
//! verdict — and says in the middle how many bytes it dropped. Cutting at
//! line boundaries keeps the model from reading half a line as a whole
//! one.
//!
//! # Who calls this
//!
//! Today: [`crate::admin_logs`], a GUI-only admin op, so a human can drive
//! a log through the pipeline and inspect every row it left. Later: flow
//! steps and connector diagnoses, which call the service directly. There
//! is deliberately no `pam` subcommand and no agent capability.

use std::sync::{Arc, LazyLock, Mutex};

use pam_compact::{CompactError, Compacted, MAX_SOURCE_BYTES, Policy, compact, estimate_tokens};
use pam_model::runtime::GenerateRequest;
use pam_store::{EVIDENCE_KIND_LOG_COMPACT, Store, StoreError};
use serde::Serialize;
use serde_json::json;

use crate::model_service::{ModelService, ModelUnavailable, Tier};

/// Evidence kind holding the exact source bytes of a compressed log.
pub const EVIDENCE_KIND_LOG_SOURCE: &str = "log.source";

/// Evidence kind holding the model's plain-text summary of a compact log.
pub const EVIDENCE_KIND_LOG_SUMMARY: &str = "log.summary";

/// Largest prompt [`fit_prompt`] hands the model, in bytes.
///
/// Roughly 6k tokens: comfortably under the 8192-token context with the
/// system turn framed in and [`SUMMARY_MAX_TOKENS`] left to answer with.
pub const PROMPT_BUDGET_BYTES: usize = 24_000;

/// Bytes of the reduced log kept from the front when it does not fit.
pub const PROMPT_HEAD_BYTES: usize = 16_000;

/// Bytes of the reduced log kept from the end when it does not fit.
pub const PROMPT_TAIL_BYTES: usize = 8_000;

/// Hard ceiling on the summary's length, in tokens.
pub const SUMMARY_MAX_TOKENS: usize = 400;

/// Greedy decoding: the summary of a given log should not vary run to run.
pub const SUMMARY_TEMPERATURE: f64 = 0.0;

/// The system turn framing every summary generation.
pub const SUMMARY_SYSTEM: &str = "You are PAM's log summarizer. You receive a build or test log that was already reduced \
     deterministically; bracketed markers say how many records were omitted and why. Answer in \
     plain text, at most eight lines: the outcome first (pass, fail, or unknown), then the failing \
     step and the exact error lines that explain it, quoted verbatim, then what a developer must \
     fix. Never invent lines that are not in the log.";

/// [`ModelSkipped::cause`] when no model is configured for the tier.
pub const CAUSE_NO_DEFAULT: &str = "no_default";

/// [`ModelSkipped::cause`] when the configured model is not installed.
pub const CAUSE_MODEL_MISSING: &str = "model_missing";

/// [`ModelSkipped::cause`] when a store write cost us the summary row.
pub const CAUSE_STORE_ERROR: &str = "store_error";

/// The daemon's log compression service (see the module docs).
#[derive(Debug)]
pub struct LogService {
    store: Arc<Store>,
    models: Arc<ModelService>,
}

/// One log offered for compression.
#[derive(Debug, Clone)]
pub struct CompressInput {
    /// Human-facing name of the log — a file name, a step name. Recorded
    /// in both evidence rows' metadata; never interpreted.
    pub name: String,
    /// The exact bytes of the log.
    pub bytes: Vec<u8>,
    /// Exit status of the process that wrote it, when it is known.
    pub exit_status: Option<i32>,
    /// Whether to ask the heavy tier for a summary. A `true` here is a
    /// request, not a promise: see [`ModelSkipped`].
    pub use_model: bool,
}

/// A handle to one evidence row and how big its blob is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EvidenceRef {
    /// Evidence id, `ev_<ulid>`.
    pub id: String,
    /// Length of the stored blob in bytes.
    pub bytes: u64,
}

/// What one compaction saved, in bytes, records and estimated tokens.
///
/// `compact_bytes` is the size of the *reduced text* — the form a reader
/// or a model consumes — not of the JSON report that stores it. The JSON
/// carries the provenance map on top of the text and would make the
/// odometer lie about what a diagnosis costs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct CompressStats {
    /// Size of the source log in bytes.
    pub source_bytes: u64,
    /// Size of the reduced text in bytes.
    pub compact_bytes: u64,
    /// Records the source framed.
    pub source_records: u64,
    /// Records that survived the reduction.
    pub retained_records: u64,
    /// Estimated input tokens the source would have cost.
    pub tokens_source_est: u64,
    /// Estimated input tokens the reduction costs.
    pub tokens_compact_est: u64,
    /// Estimated input tokens avoided, saturating at zero.
    pub tokens_avoided_est: u64,
}

/// The model that wrote a summary, and what the generation cost.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ModelUse {
    /// Registry id of the model that answered.
    pub id: String,
    /// Tier the generation ran on.
    pub tier: &'static str,
    /// Tokens in the framed prompt.
    pub prompt_tokens: usize,
    /// Tokens generated.
    pub completion_tokens: usize,
    /// Generation rate.
    pub tokens_per_sec: f64,
}

/// Why there is no summary, in terms the GUI can render.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ModelSkipped {
    /// Machine-readable reason: [`CAUSE_NO_DEFAULT`],
    /// [`CAUSE_MODEL_MISSING`], [`CAUSE_STORE_ERROR`], or a
    /// [`pam_model::RuntimeError::cause`] verbatim.
    pub cause: String,
    /// The failure in words.
    pub detail: String,
}

/// Everything one compression produced.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CompressReport {
    /// The row holding the exact source bytes.
    pub source: EvidenceRef,
    /// The row holding the JSON compaction report.
    pub compact: EvidenceRef,
    /// The row holding the model's summary, when there is one.
    pub summary: Option<EvidenceRef>,
    /// The reduced text, ready to read.
    pub compact_text: String,
    /// The summary text, when there is one.
    pub summary_text: Option<String>,
    /// What the compaction saved.
    pub stats: CompressStats,
    /// Which model answered, when one did.
    pub model: Option<ModelUse>,
    /// Why none did, when none did.
    pub model_skipped: Option<ModelSkipped>,
}

/// Why a compression could not produce its deterministic result.
///
/// Everything the model layer can do wrong is a [`ModelSkipped`], not one
/// of these: these are the failures that leave the caller with nothing.
#[derive(Debug, thiserror::Error)]
pub enum LogError {
    /// The source is larger than [`MAX_SOURCE_BYTES`].
    #[error("log source is {actual_bytes} bytes; the maximum is {maximum_bytes}")]
    SourceTooLarge {
        /// Size of the source that was offered.
        actual_bytes: u64,
        /// [`MAX_SOURCE_BYTES`], as a `u64`.
        maximum_bytes: u64,
    },
    /// The reduction itself refused the input.
    #[error(transparent)]
    Compact(#[from] CompactError),
    /// An evidence row carrying the deterministic result could not be
    /// written.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The blocking compaction task did not come back.
    #[error("the compaction task did not finish: {0}")]
    Join(String),
}

impl LogError {
    /// The machine-readable cause a refusal carries.
    #[must_use]
    pub fn cause(&self) -> &'static str {
        match self {
            Self::SourceTooLarge { .. } => "source_too_large",
            Self::Compact(err) => err.cause(),
            Self::Store(_) => CAUSE_STORE_ERROR,
            Self::Join(_) => "internal_error",
        }
    }
}

impl LogService {
    /// Builds the service over the daemon's store and model layer.
    #[must_use]
    pub fn new(store: Arc<Store>, models: Arc<ModelService>) -> Arc<Self> {
        Arc::new(Self { store, models })
    }

    /// Compresses one log under `request_id`, leaving its evidence rows.
    ///
    /// The caller owns the request row the evidence references (evidence
    /// has a foreign key onto `request(id)`), so this is called from
    /// something that already inserted one — an admin op today.
    pub async fn compress(
        &self,
        request_id: &str,
        input: CompressInput,
    ) -> Result<CompressReport, LogError> {
        let CompressInput {
            name,
            bytes,
            exit_status,
            use_model,
        } = input;

        // Bounded before anything is spawned, read or written: an
        // oversized log leaves no rows at all.
        if bytes.len() > MAX_SOURCE_BYTES {
            return Err(LogError::SourceTooLarge {
                actual_bytes: as_u64(bytes.len()),
                maximum_bytes: as_u64(MAX_SOURCE_BYTES),
            });
        }

        // The reduction is pure CPU over up to 64 MiB; it does not belong
        // on a runtime thread that is also serving the socket. The bytes
        // travel with the closure and come back so the source row can be
        // written from them without a second copy.
        let (bytes, compacted) = tokio::task::spawn_blocking(move || {
            let compacted = compact(&bytes, exit_status, &Policy::default());
            (bytes, compacted)
        })
        .await
        .map_err(|err| LogError::Join(err.to_string()))?;
        let compacted = compacted?;

        let stats = CompressStats::of(&compacted);

        let source_id = new_evidence_id();
        self.store
            .insert_evidence(
                &source_id,
                request_id,
                EVIDENCE_KIND_LOG_SOURCE,
                &bytes,
                Some(&json!({ "name": name, "exit_status": exit_status }).to_string()),
            )
            .await?;

        let compact_json = serde_json::to_vec(&compacted).map_err(|err| {
            LogError::Join(format!("the compaction report did not serialize: {err}"))
        })?;
        let compact_id = new_evidence_id();
        self.store
            .insert_evidence(
                &compact_id,
                request_id,
                EVIDENCE_KIND_LOG_COMPACT,
                &compact_json,
                Some(&compact_meta(&name, &compacted, stats, &source_id).to_string()),
            )
            .await?;

        let mut report = CompressReport {
            source: EvidenceRef {
                id: source_id.clone(),
                bytes: stats.source_bytes,
            },
            compact: EvidenceRef {
                id: compact_id.clone(),
                bytes: as_u64(compact_json.len()),
            },
            summary: None,
            compact_text: compacted.rendered_text,
            summary_text: None,
            stats,
            model: None,
            model_skipped: None,
        };

        if use_model {
            self.summarize(request_id, &name, &source_id, &compact_id, &mut report)
                .await;
        }

        tracing::info!(
            request_id,
            name,
            source_bytes = stats.source_bytes,
            compact_bytes = stats.compact_bytes,
            tokens_avoided_est = stats.tokens_avoided_est,
            summarized = report.summary.is_some(),
            model_skipped = report
                .model_skipped
                .as_ref()
                .map(|skip| skip.cause.as_str()),
            "compressed a log"
        );
        Ok(report)
    }

    /// Asks the heavy tier for a summary and files it, or records why it
    /// could not. Never fails the compression (see the module docs).
    async fn summarize(
        &self,
        request_id: &str,
        name: &str,
        source_id: &str,
        compact_id: &str,
        report: &mut CompressReport,
    ) {
        // Resolved once, up front: `generate` resolves for itself, but the
        // report has to name the model that answered and the entry is the
        // only place that id lives.
        let entry = match self.models.resolve(Tier::Heavy).await {
            Ok(entry) => entry,
            Err(err) => {
                report.model_skipped = Some(skipped(&err));
                return;
            }
        };
        let request = GenerateRequest {
            system: Some(SUMMARY_SYSTEM.to_owned()),
            prompt: fit_prompt(&report.compact_text),
            max_tokens: SUMMARY_MAX_TOKENS,
            temperature: SUMMARY_TEMPERATURE,
            stop: Vec::new(),
        };
        let result = match self.models.generate(Tier::Heavy, request).await {
            Ok(result) => result,
            Err(err) => {
                report.model_skipped = Some(skipped(&err));
                return;
            }
        };

        let summary_id = new_evidence_id();
        let meta = json!({
            "name": name,
            "model_id": entry.id,
            "tier": Tier::Heavy.as_str(),
            "prompt_tokens": result.prompt_tokens,
            "completion_tokens": result.completion_tokens,
            "tokens_per_sec": result.tokens_per_sec,
            "source_evidence": source_id,
            "compact_evidence": compact_id,
        });
        if let Err(err) = self
            .store
            .insert_evidence(
                &summary_id,
                request_id,
                EVIDENCE_KIND_LOG_SUMMARY,
                result.text.as_bytes(),
                Some(&meta.to_string()),
            )
            .await
        {
            // The compaction already happened and is already stored; a
            // lost summary row is a skip, not a failure.
            tracing::warn!(request_id, %err, "the log summary row could not be written");
            report.model_skipped = Some(ModelSkipped {
                cause: CAUSE_STORE_ERROR.to_owned(),
                detail: format!("the summary row could not be written: {err}"),
            });
            return;
        }

        report.summary = Some(EvidenceRef {
            id: summary_id,
            bytes: as_u64(result.text.len()),
        });
        report.model = Some(ModelUse {
            id: entry.id,
            tier: Tier::Heavy.as_str(),
            prompt_tokens: result.prompt_tokens,
            completion_tokens: result.completion_tokens,
            tokens_per_sec: result.tokens_per_sec,
        });
        report.summary_text = Some(result.text);
    }
}

impl CompressStats {
    /// The figures a finished reduction implies.
    fn of(compacted: &Compacted) -> Self {
        let source_bytes = compacted.source_bytes;
        let compact_bytes = as_u64(compacted.rendered_text.len());
        let tokens_source_est = estimate_tokens(source_bytes);
        let tokens_compact_est = estimate_tokens(compact_bytes);
        Self {
            source_bytes,
            compact_bytes,
            source_records: compacted.source_records,
            retained_records: compacted.retained_records,
            tokens_source_est,
            tokens_compact_est,
            tokens_avoided_est: tokens_source_est.saturating_sub(tokens_compact_est),
        }
    }
}

/// The `meta_json` of a [`EVIDENCE_KIND_LOG_COMPACT`] row: the odometer's
/// figures plus enough provenance to find the source row again.
fn compact_meta(
    name: &str,
    compacted: &Compacted,
    stats: CompressStats,
    source_id: &str,
) -> serde_json::Value {
    json!({
        "name": name,
        "algorithm_version": compacted.algorithm_version,
        "exit_status": compacted.exit_status,
        "source_evidence": source_id,
        "source_bytes": stats.source_bytes,
        "compact_bytes": stats.compact_bytes,
        "source_records": stats.source_records,
        "retained_records": stats.retained_records,
        "tokens_source_est": stats.tokens_source_est,
        "tokens_compact_est": stats.tokens_compact_est,
        "tokens_avoided_est": stats.tokens_avoided_est,
    })
}

/// Turns a model-layer refusal into the skip the report carries.
fn skipped(err: &ModelUnavailable) -> ModelSkipped {
    let cause = match err {
        ModelUnavailable::NoDefault(_) => CAUSE_NO_DEFAULT,
        ModelUnavailable::Missing(_) => CAUSE_MODEL_MISSING,
        ModelUnavailable::Runtime(runtime) => runtime.cause(),
        ModelUnavailable::Store(_) => CAUSE_STORE_ERROR,
    };
    ModelSkipped {
        cause: cause.to_owned(),
        detail: err.to_string(),
    }
}

/// Fits a reduced log to [`PROMPT_BUDGET_BYTES`].
///
/// Short enough, and the text goes through untouched. Otherwise the head
/// and the tail are kept — where a build log puts its invocation and its
/// verdict — with one marker between them saying how much went. Both cuts
/// land on line boundaries so the model never reads half a line as a whole
/// one, and the marker sits on its own line.
#[must_use]
pub fn fit_prompt(text: &str) -> String {
    if text.len() <= PROMPT_BUDGET_BYTES {
        return text.to_owned();
    }
    // Cut back to the last newline inside the head window; if the window
    // holds no newline at all (one enormous line), the char boundary is
    // the best cut available.
    let head_cut = text.floor_char_boundary(PROMPT_HEAD_BYTES);
    let head_end = text[..head_cut].rfind('\n').map_or(head_cut, |at| at + 1);
    // Forward to the first newline at or after the tail window's start,
    // for the same reason in the other direction.
    let tail_cut = text.ceil_char_boundary(text.len() - PROMPT_TAIL_BYTES);
    let tail_start = text[tail_cut..]
        .find('\n')
        .map_or(tail_cut, |at| tail_cut + at + 1);
    if tail_start <= head_end {
        // The two windows met: nothing was actually elided.
        return text.to_owned();
    }
    let head = &text[..head_end];
    let tail = &text[tail_start..];
    let elided = text.len() - head.len() - tail.len();
    format!("{head}[... {elided} bytes elided for the model prompt ...]\n{tail}")
}

/// A fresh `ev_<ulid>` evidence id.
///
/// Minted from one monotonic generator rather than from `Ulid::new`,
/// because the store orders a request's evidence by `(ts, id)` and `ts` is
/// unix *seconds*: three rows written inside one second must still list in
/// the order they were written. On the generator's only failure mode (the
/// random bits overflowing inside a single millisecond) a plain ulid is
/// good enough — the ordering is a nicety, the uniqueness is not.
#[must_use]
pub fn new_evidence_id() -> String {
    static IDS: LazyLock<Mutex<ulid::Generator>> =
        LazyLock::new(|| Mutex::new(ulid::Generator::new()));
    let id = {
        let mut generator = IDS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        generator.generate().unwrap_or_else(|_| ulid::Ulid::new())
    };
    format!("ev_{}", id.to_string().to_lowercase())
}

/// A byte count as a `u64`, saturating rather than wrapping.
fn as_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}
