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
//! # Bounded summaries
//!
//! Oversized evidence is refused before generation, never head/tail
//! truncated. Flow steps and the GUI log observatory both call this service.

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

/// Conservative byte ceiling before the exact 2,048-token summary preflight.
pub const PROMPT_BUDGET_BYTES: usize = 6_000;

/// Hard ceiling on the summary's length, in tokens.
pub const SUMMARY_MAX_TOKENS: usize = 400;

/// Greedy decoding: the summary of a given log should not vary run to run.
pub const SUMMARY_TEMPERATURE: f64 = 0.0;

/// The system turn framing every summary generation.
pub const SUMMARY_SYSTEM: &str = "You receive selected build evidence. Report observations in at most eight lines, \
    quoting exact diagnostics. The supplied exit status is authoritative; error text alone is not a final failure. \
    Errors may be retried, caught, or followed by cleanup. Selected evidence may omit decisive context. \
    Say unknown when the failed stage or cause cannot be established. Do not invent fixes or override the reported status.";

/// [`ModelSkipped::cause`] when no model is configured for the tier.
pub const CAUSE_NO_DEFAULT: &str = "no_default";

/// [`ModelSkipped::cause`] when the configured model is not installed.
pub const CAUSE_MODEL_MISSING: &str = "model_missing";

/// [`ModelSkipped::cause`] when a store write cost us the summary row.
pub const CAUSE_STORE_ERROR: &str = "store_error";

/// The daemon's log compression service (see the module docs).
#[derive(Debug)]
pub struct LogService {
    pub(crate) store: Arc<Store>,
    pub(crate) models: Arc<ModelService>,
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
    /// Optional source/compact views unavailable for bounded agent retrieval.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub view_skipped: Vec<ModelSkipped>,
}

/// Why a compression could not produce its deterministic result.
///
/// Everything the model layer can do wrong is a [`ModelSkipped`], not one
/// of these: these are the failures that leave the caller with nothing.
#[derive(Debug, thiserror::Error)]
pub enum LogError {
    /// A bounded worker admission or completion failure.
    #[error("{detail}")]
    Blocking {
        /// Stable worker refusal cause.
        cause: &'static str,
        /// Sanitized worker failure detail.
        detail: String,
    },
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
            Self::Blocking { cause, .. } => cause,
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
        self.compress_scoped(request_id, input, None).await
    }

    pub(crate) async fn compress_scoped(
        &self,
        request_id: &str,
        input: CompressInput,
        capture: Option<&crate::evidence_service::CaptureScope>,
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

        let source_bytes = as_u64(bytes.len());
        // Pure CPU preparation stays on the bounded blocking worker.
        let (safe, compacted, compact_view) =
            crate::blocking_jobs::run(crate::blocking_jobs::Kind::LogCompaction, move || {
                prepare_compaction(&bytes, exit_status)
            })
            .await
            .map_err(|err| LogError::Blocking {
                cause: err.cause(),
                detail: err.to_string(),
            })?
            .map_err(LogError::Join)?;
        let compact_text = String::from_utf8(compact_view.bytes.clone())
            .map_err(|error| LogError::Join(error.to_string()))?;

        let stats = CompressStats::of(&compacted);

        let source_view_skip = self
            .publish_optional_view(
                request_id,
                &source_id,
                safe,
                json!({"kind": "protected_source"}),
                capture,
            )
            .await;

        let (compact_ref, compact_view_skip) = self
            .file_compact(
                request_id,
                &name,
                &source_id,
                &compacted,
                compact_view,
                capture,
            )
            .await?;
        let compact_id = compact_ref.id.clone();

        let mut report = CompressReport {
            source: EvidenceRef {
                id: source_id.clone(),
                bytes: source_bytes,
            },
            compact: compact_ref,
            summary: None,
            compact_text,
            summary_text: None,
            stats,
            model: None,
            model_skipped: None,
            view_skipped: source_view_skip
                .into_iter()
                .chain(compact_view_skip)
                .collect(),
        };

        if use_model {
            self.summarize(
                request_id,
                &name,
                &source_id,
                &compact_id,
                &mut report,
                capture,
            )
            .await;
        }

        trace_compression(request_id, &name, &report);
        Ok(report)
    }

    async fn file_compact(
        &self,
        request_id: &str,
        name: &str,
        source_id: &str,
        compacted: &Compacted,
        compact_view: crate::evidence_view::RedactedView,
        capture: Option<&crate::evidence_service::CaptureScope>,
    ) -> Result<(EvidenceRef, Option<ModelSkipped>), LogError> {
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
                Some(
                    &compact_meta(name, compacted, CompressStats::of(compacted), source_id)
                        .to_string(),
                ),
            )
            .await?;

        let view_skip = self
            .publish_optional_view(
                request_id,
                &compact_id,
                compact_view,
                json!({"evidence_id": source_id, "source_sha256": compacted.source_sha256,
                "offset_basis": "redacted_source_bytes", "relation": "covering_record"}),
                capture,
            )
            .await;

        Ok((
            EvidenceRef {
                id: compact_id,
                bytes: as_u64(compact_json.len()),
            },
            view_skip,
        ))
    }

    /// Optional retrieval views never change the underlying step outcome.
    async fn publish_optional_view(
        &self,
        request_id: &str,
        evidence_id: &str,
        view: crate::evidence_view::RedactedView,
        parent: serde_json::Value,
        capture: Option<&crate::evidence_service::CaptureScope>,
    ) -> Option<ModelSkipped> {
        if let Some(capture) = capture
            && let Err(error) = crate::evidence_service::publish(
                &self.store,
                capture,
                request_id,
                evidence_id,
                view,
                parent,
            )
            .await
        {
            tracing::warn!(request_id, evidence_id, %error, "the optional log evidence view could not be filed");
            return Some(ModelSkipped {
                cause: "evidence_view_unavailable".to_owned(),
                detail: evidence_id.to_owned(),
            });
        }
        None
    }

    async fn file_summary(
        &self,
        request_id: &str,
        summary_id: &str,
        text: &str,
        meta: &serde_json::Value,
    ) -> Result<(), ModelSkipped> {
        self.store
            .insert_evidence(
                summary_id,
                request_id,
                EVIDENCE_KIND_LOG_SUMMARY,
                text.as_bytes(),
                Some(&meta.to_string()),
            )
            .await
            .map_err(|err| {
                tracing::warn!(request_id, %err, "the log summary row could not be written");
                ModelSkipped {
                    cause: CAUSE_STORE_ERROR.to_owned(),
                    detail: format!("the summary row could not be written: {err}"),
                }
            })
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
        capture: Option<&crate::evidence_service::CaptureScope>,
    ) {
        let (prompt, input) = summary_input(&report.compact_text, compact_id);
        if prompt.len() > PROMPT_BUDGET_BYTES {
            report.model_skipped = Some(ModelSkipped {
                cause: "evidence_exceeds_budget".to_owned(),
                detail: "The evidence exceeds the bounded summary input; inspect a specific stage or node. No head/tail truncation was sent to the model.".to_owned(),
            });
            return;
        }
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
            prompt,
            max_tokens: SUMMARY_MAX_TOKENS,
            temperature: SUMMARY_TEMPERATURE,
            stop: Vec::new(),
        };
        let result = match self
            .models
            .generate_bounded(Tier::Heavy, request, 2048)
            .await
        {
            Ok(result) => result,
            Err(err) => {
                report.model_skipped = Some(skipped(&err));
                return;
            }
        };

        let summary_id = new_evidence_id();
        let (view, safe_text) = match safe_summary(&result.text) {
            Ok(prepared) => prepared,
            Err(skip) => {
                report.model_skipped = Some(skip);
                return;
            }
        };
        let meta = json!({
            "name": name,
            "model_id": entry.id,
            "tier": Tier::Heavy.as_str(),
            "prompt_tokens": result.prompt_tokens,
            "completion_tokens": result.completion_tokens,
            "tokens_per_sec": result.tokens_per_sec,
            "source_evidence": source_id,
            "compact_evidence": compact_id,
            "input": input,
        });
        if let Err(skip) = self
            .file_summary(request_id, &summary_id, &result.text, &meta)
            .await
        {
            report.model_skipped = Some(skip);
            return;
        }

        if let Some(capture) = capture
            && let Err(error) = crate::evidence_service::publish(
                &self.store,
                capture,
                request_id,
                &summary_id,
                view,
                json!({"kind": "untrusted_model_output", "input_evidence_id": input["evidence_id"],
                    "input_sha256": input["sha256"], "offset_basis": input["offset_basis"],
                    "quotation_support": "not_asserted"}),
            )
            .await
        {
            report.model_skipped = Some(ModelSkipped {
                cause: "evidence_view_unavailable".to_owned(),
                detail: error,
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
        report.summary_text = Some(safe_text);
    }
}

fn trace_compression(request_id: &str, name: &str, report: &CompressReport) {
    tracing::info!(
        request_id,
        name,
        source_bytes = report.stats.source_bytes,
        compact_bytes = report.stats.compact_bytes,
        tokens_avoided_est = report.stats.tokens_avoided_est,
        summarized = report.summary.is_some(),
        model_skipped = report
            .model_skipped
            .as_ref()
            .map(|skip| skip.cause.as_str()),
        "compressed a log"
    );
}

/// Build safe model input and explicitly covering provenance outside Tokio workers.
fn prepare_compaction(
    bytes: &[u8],
    exit_status: Option<i32>,
) -> Result<
    (
        crate::evidence_view::RedactedView,
        Compacted,
        crate::evidence_view::RedactedView,
    ),
    String,
> {
    let safe = crate::evidence_view::redact(bytes).map_err(|error| error.to_string())?;
    let compacted =
        compact(&safe.bytes, exit_status, &Policy::default()).map_err(|error| error.to_string())?;
    let compact_map = crate::evidence_view::compact_segments(&compacted, &safe.bytes)
        .map_err(|error| error.to_string())?;
    let mut view = crate::evidence_view::redact(compacted.rendered_text.as_bytes())
        .map_err(|error| error.to_string())?;
    view.segments = crate::evidence_view::compose_segments(&view.segments, &compact_map)
        .map_err(|error| error.to_string())?;
    Ok((safe, compacted, view))
}

fn safe_summary(text: &str) -> Result<(crate::evidence_view::RedactedView, String), ModelSkipped> {
    let view = crate::evidence_view::redact(text.as_bytes()).map_err(|error| ModelSkipped {
        cause: "redaction_unavailable".to_owned(),
        detail: error.to_string(),
    })?;
    let safe_text = String::from_utf8(view.bytes.clone()).map_err(|_| ModelSkipped {
        cause: "redaction_unavailable".to_owned(),
        detail: "The safe summary is not UTF-8.".to_owned(),
    })?;
    Ok((view, safe_text))
}

pub(crate) fn summary_input(compact_text: &str, compact_id: &str) -> (String, serde_json::Value) {
    (
        compact_text.to_owned(),
        json!({"evidence_id": compact_id,
        "sha256": pam_compact::sha256_hex(compact_text.as_bytes()), "offset_basis": "view_bytes"}),
    )
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
        ModelUnavailable::Service(crate::model_service::ModelServiceError::Blocking {
            cause,
            ..
        }) => cause,
        ModelUnavailable::Service(_) => "model_registry_failed",
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
