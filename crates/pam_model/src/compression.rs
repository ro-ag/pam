//! Microsoft LLMLingua-2 token scores with PAM's whole-record retention policy.
//!
//! Model: Apache-2.0, <https://huggingface.co/microsoft/llmlingua-2-bert-base-multilingual-cased-meetingbank>
//! Scoring follows Microsoft's `LLMLingua` implementation (MIT): class 1 is preserve,
//! `WordPiece` scores are averaged. Selection deliberately differs: original lines,
//! not reconstructed words, retain byte-exact provenance and diagnostic syntax.
use std::{fs::File, io::Read, path::Path};

use candle_core::{DType, Device, Tensor};
use candle_nn::{Module, VarBuilder};
use candle_transformers::models::bert::{BertModel, Config};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::sync::watch;

pub const MODEL_SUBDIR: &str = "microsoft/llmlingua-2";
pub const MODEL_ID: &str = "microsoft/llmlingua-2-bert-base-multilingual-cased-meetingbank@5f0c82792b7ea14c6484e015b6a072009496b7f2";
pub const MAX_INPUT_BYTES: usize = 64 * 1024;
pub const MAX_INPUT_TOKENS: usize = 8192;
const WINDOW: usize = 510;
const OMITTED: &str = "[... omitted ...]\n";

pub struct Asset {
    pub name: &'static str,
    pub url: &'static str,
    pub size: u64,
    pub sha256: &'static str,
}

pub const ASSETS: &[Asset] = &[
    Asset {
        name: "config.json",
        url: "https://huggingface.co/microsoft/llmlingua-2-bert-base-multilingual-cased-meetingbank/resolve/5f0c82792b7ea14c6484e015b6a072009496b7f2/config.json",
        size: 875,
        sha256: "e6c33ec2f099e659e125efaa8b7bb07a6e65b7d9fc36211c6fa3206e1c399085",
    },
    Asset {
        name: "tokenizer.json",
        url: "https://huggingface.co/microsoft/llmlingua-2-bert-base-multilingual-cased-meetingbank/resolve/5f0c82792b7ea14c6484e015b6a072009496b7f2/tokenizer.json",
        size: 2_919_362,
        sha256: "bf1b59b7b11c95f194f51708d918eea378e09d05f84c0e1656dc5180e8117088",
    },
    Asset {
        name: "model.safetensors",
        url: "https://huggingface.co/microsoft/llmlingua-2-bert-base-multilingual-cased-meetingbank/resolve/5f0c82792b7ea14c6484e015b6a072009496b7f2/model.safetensors",
        size: 709_388_104,
        sha256: "22b9ecde52fec5c97e8c54a293be768727df95a81c6c8dccb03f262a50c58324",
    },
];

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SourceSpan {
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Serialize)]
pub struct CompressionReport {
    pub text: String,
    pub source_sha256: String,
    pub source_bytes: usize,
    pub retained: Vec<SourceSpan>,
    pub input_tokens: usize,
    pub output_tokens: usize,
    pub model_id: String,
}

#[derive(Debug, thiserror::Error)]
pub enum CompressionError {
    #[error("compression cancelled")]
    Cancelled,
    #[error("compression input exceeds byte or token limit")]
    InputLimit,
    #[error("required source records cannot fit the output budget")]
    Budget,
    #[error("compressor assets unavailable: {0}")]
    Unavailable(String),
    #[error("compressor asset integrity check failed: {0}")]
    Integrity(String),
    #[error("compressor configuration is unsupported")]
    Configuration,
    #[error("invalid tokenizer offsets or model scores")]
    InvalidScores,
    #[error("compressor inference failed: {0}")]
    Inference(String),
}

impl CompressionError {
    #[must_use]
    pub fn cause(&self) -> &'static str {
        match self {
            Self::Cancelled => "cancelled",
            Self::InputLimit => "input_limit",
            Self::Budget => "budget",
            Self::Unavailable(_) => "unavailable",
            Self::Integrity(_) => "integrity",
            Self::Configuration => "configuration",
            Self::InvalidScores => "invalid_scores",
            Self::Inference(_) => "inference",
        }
    }
}

/// `directory` is the asset directory, not the model registry root.
/// This cheap probe is not integrity verification; `compress` verifies every asset.
#[must_use]
pub fn installed(directory: &Path) -> bool {
    ASSETS.iter().all(|asset| {
        directory
            .join(asset.name)
            .metadata()
            .is_ok_and(|m| m.is_file() && m.len() == asset.size)
    })
}

fn check_cancel(cancel: &watch::Receiver<bool>) -> Result<(), CompressionError> {
    if *cancel.borrow() {
        Err(CompressionError::Cancelled)
    } else {
        Ok(())
    }
}

fn read_asset(
    directory: &Path,
    asset: &Asset,
    cancel: &watch::Receiver<bool>,
) -> Result<Vec<u8>, CompressionError> {
    check_cancel(cancel)?;
    let mut file = File::open(directory.join(asset.name))
        .map_err(|e| CompressionError::Unavailable(e.to_string()))?;
    let metadata = file
        .metadata()
        .map_err(|e| CompressionError::Unavailable(e.to_string()))?;
    if !metadata.is_file() || metadata.len() != asset.size {
        return Err(CompressionError::Integrity(asset.name.into()));
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(asset.size).map_err(|_| CompressionError::Configuration)?,
    );
    let mut hash = Sha256::new();
    let mut block = vec![0u8; 64 * 1024];
    loop {
        check_cancel(cancel)?;
        let read = file
            .read(&mut block)
            .map_err(|e| CompressionError::Unavailable(e.to_string()))?;
        if read == 0 {
            break;
        }
        if bytes.len() as u64 + read as u64 > asset.size {
            return Err(CompressionError::Integrity(asset.name.into()));
        }
        hash.update(&block[..read]);
        bytes.extend_from_slice(&block[..read]);
    }
    if bytes.len() as u64 != asset.size || hex::encode(hash.finalize()) != asset.sha256 {
        return Err(CompressionError::Integrity(asset.name.into()));
    }
    Ok(bytes)
}

fn inference(error: impl std::fmt::Display) -> CompressionError {
    CompressionError::Inference(error.to_string())
}

fn tokenizer(bytes: &[u8]) -> Result<tokenizers::Tokenizer, CompressionError> {
    let mut tokenizer = tokenizers::Tokenizer::from_bytes(bytes).map_err(inference)?;
    tokenizer.with_truncation(None).map_err(inference)?;
    tokenizer.with_padding(None);
    Ok(tokenizer)
}

fn config(bytes: &[u8]) -> Result<Config, CompressionError> {
    let raw: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| CompressionError::Configuration)?;
    if raw["architectures"] != serde_json::json!(["BertForTokenClassification"])
        || raw["hidden_size"] != 768
        || raw["num_hidden_layers"] != 12
        || raw["num_attention_heads"] != 12
        || raw["vocab_size"] != 119_647
        || raw["max_position_embeddings"] != 512
        || raw["model_type"] != "bert"
    {
        return Err(CompressionError::Configuration);
    }
    serde_json::from_value(raw).map_err(|_| CompressionError::Configuration)
}

/// Synchronous CPU inference. Caller serializes residency and runs this off async workers.
/// Cancellation is observed during loading and between bounded BERT windows.
pub fn compress(
    directory: &Path,
    text: &str,
    target_bytes: usize,
    cancel: &watch::Receiver<bool>,
) -> Result<CompressionReport, CompressionError> {
    check_cancel(cancel)?;
    if text.len() > MAX_INPUT_BYTES {
        return Err(CompressionError::InputLimit);
    }
    let cfg = config(&read_asset(directory, &ASSETS[0], cancel)?)?;
    let tokenizer = tokenizer(&read_asset(directory, &ASSETS[1], cancel)?)?;
    let encoding = tokenizer.encode(text, false).map_err(inference)?;
    if encoding.len() > MAX_INPUT_TOKENS {
        return Err(CompressionError::InputLimit);
    }
    validate_offsets(text, encoding.get_offsets())?;
    let weights = read_asset(directory, &ASSETS[2], cancel)?;
    let device = Device::Cpu;
    let vb =
        VarBuilder::from_buffered_safetensors(weights, DType::F32, &device).map_err(inference)?;
    let model = BertModel::load(vb.clone(), &cfg).map_err(inference)?;
    let classifier = candle_nn::linear(768, 2, vb.pp("classifier")).map_err(inference)?;
    drop(vb);
    let mut probabilities = Vec::with_capacity(encoding.len());
    for chunk in encoding.get_ids().chunks(WINDOW) {
        check_cancel(cancel)?;
        let mut ids = Vec::with_capacity(chunk.len() + 2);
        ids.push(101u32);
        ids.extend_from_slice(chunk);
        ids.push(102);
        let ids = Tensor::new(ids.as_slice(), &device)
            .and_then(|v| v.unsqueeze(0))
            .map_err(inference)?;
        let types = ids.zeros_like().map_err(inference)?;
        let hidden = model.forward(&ids, &types, None).map_err(inference)?;
        let logits = classifier.forward(&hidden).map_err(inference)?;
        let scores = candle_nn::ops::softmax(&logits, 2)
            .and_then(|v| v.squeeze(0))
            .and_then(|v| v.to_vec2::<f32>())
            .map_err(inference)?;
        for row in scores.iter().skip(1).take(chunk.len()) {
            probabilities.push(*row.get(1).ok_or(CompressionError::InvalidScores)?);
        }
    }
    check_cancel(cancel)?;
    // Release all owned model tensors before returning to the investigator.
    drop(classifier);
    drop(model);
    let line_scores = score_lines(
        text,
        encoding.get_offsets(),
        encoding.get_tokens(),
        &probabilities,
    )?;
    let (compressed, retained) = select_lines(text, &line_scores, target_bytes)?;
    let output_tokens = tokenizer
        .encode(compressed.as_str(), false)
        .map_err(inference)?
        .len();
    Ok(CompressionReport {
        text: compressed,
        source_sha256: hex::encode(Sha256::digest(text.as_bytes())),
        source_bytes: text.len(),
        retained,
        input_tokens: encoding.len(),
        output_tokens,
        model_id: MODEL_ID.into(),
    })
}

pub(crate) fn validate_offsets(
    text: &str,
    offsets: &[(usize, usize)],
) -> Result<(), CompressionError> {
    let mut previous_end = 0;
    for &(start, end) in offsets {
        if start >= end
            || end > text.len()
            || start < previous_end
            || !text.is_char_boundary(start)
            || !text.is_char_boundary(end)
        {
            return Err(CompressionError::InvalidScores);
        }
        previous_end = end;
    }
    Ok(())
}

fn lines(text: &str) -> Vec<SourceSpan> {
    let mut start = 0;
    text.split_inclusive('\n')
        .map(|line| {
            let span = SourceSpan {
                start,
                end: start + line.len(),
            };
            start = span.end;
            span
        })
        .collect()
}

pub(crate) fn score_lines(
    text: &str,
    offsets: &[(usize, usize)],
    tokens: &[String],
    scores: &[f32],
) -> Result<Vec<f32>, CompressionError> {
    validate_offsets(text, offsets)?;
    if offsets.len() != scores.len()
        || tokens.len() != scores.len()
        || scores
            .iter()
            .any(|p| !p.is_finite() || !(0.0..=1.0).contains(p))
    {
        return Err(CompressionError::InvalidScores);
    }
    let spans = lines(text);
    let mut words = vec![Vec::<f32>::new(); spans.len()];
    let mut i = 0;
    while i < scores.len() {
        let start = i;
        let line = spans.partition_point(|s| s.end <= offsets[i].0);
        i += 1;
        while i < scores.len() && tokens[i].starts_with("##") && offsets[i].0 < spans[line].end {
            i += 1;
        }
        if offsets[i - 1].1 > spans[line].end {
            return Err(CompressionError::InvalidScores);
        }
        words[line].push(mean(&scores[start..i]));
    }
    Ok(words
        .into_iter()
        .map(|w| if w.is_empty() { 0.0 } else { mean(&w) })
        .collect())
}

fn mean(scores: &[f32]) -> f32 {
    let (total, count) = scores
        .iter()
        .fold((0.0, 0.0), |(total, count), p| (total + p, count + 1.0));
    total / count
}

fn required(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    [
        "[pipeline]",
        "error",
        "failed",
        "failure",
        "exception",
        "caused by",
        "traceback",
        "panic",
        "retry",
        "catch",
        "timeout",
        "aborted",
        "finished:",
        "exit code",
        "exit status",
        "build success",
        "build unstable",
        "suppressed:",
        "... ",
    ]
    .iter()
    .any(|m| lower.contains(m))
        || lower.trim_start().starts_with("at ")
}

fn render(text: &str, spans: &[SourceSpan], keep: &[bool]) -> (String, Vec<SourceSpan>) {
    let mut result = String::new();
    let mut retained: Vec<SourceSpan> = Vec::new();
    let mut omitted = false;
    for (span, &selected) in spans.iter().zip(keep) {
        if !selected {
            omitted = true;
            continue;
        }
        if omitted {
            result.push_str(OMITTED);
            omitted = false;
        }
        result.push_str(&text[span.start..span.end]);
        if let Some(previous) = retained.last_mut().filter(|p| p.end == span.start) {
            previous.end = span.end;
        } else {
            retained.push(span.clone());
        }
    }
    if omitted {
        result.push_str(OMITTED);
    }
    (result, retained)
}

pub(crate) fn select_lines(
    text: &str,
    scores: &[f32],
    budget: usize,
) -> Result<(String, Vec<SourceSpan>), CompressionError> {
    let spans = lines(text);
    if scores.len() != spans.len() || scores.iter().any(|p| !p.is_finite()) {
        return Err(CompressionError::InvalidScores);
    }
    if spans.is_empty() {
        return Ok((String::new(), Vec::new()));
    }
    let mut keep = vec![false; spans.len()];
    keep[0] = true;
    keep[spans.len() - 1] = true;
    for (i, span) in spans.iter().enumerate() {
        if required(&text[span.start..span.end]) {
            for selected in &mut keep[i.saturating_sub(2)..(i + 3).min(spans.len())] {
                *selected = true;
            }
        }
    }
    if text.len() <= budget {
        return Ok((
            text.into(),
            vec![SourceSpan {
                start: 0,
                end: text.len(),
            }],
        ));
    }
    if render(text, &spans, &keep).0.len() > budget {
        return Err(CompressionError::Budget);
    }
    let mut order: Vec<usize> = (0..spans.len()).filter(|&i| !keep[i]).collect();
    order.sort_by(|&a, &b| scores[b].total_cmp(&scores[a]).then(a.cmp(&b)));
    for i in order {
        keep[i] = true;
        if render(text, &spans, &keep).0.len() > budget {
            keep[i] = false;
        }
    }
    Ok(render(text, &spans, &keep))
}
