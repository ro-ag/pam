//! Byte-level BPE rebuilt from GGUF metadata, so a model stays one file.
//!
//! A GGUF carries its own vocabulary: `tokenizer.ggml.tokens`,
//! `tokenizer.ggml.merges`, `tokenizer.ggml.token_type`, and the special
//! token ids. Reconstructing a [`tokenizers::Tokenizer`] from those keys is
//! what lets PAM download exactly one file per model. The alternative —
//! fetching `tokenizer.json` alongside the weights — doubles the number of
//! things that can be missing, stale, or mismatched on the human's disk, and
//! there is no honest way to tell them apart afterwards.
//!
//! Ported from candle-core 0.11 `quantized/tokenizer.rs`, Apache-2.0, Hugging
//! Face. Our tree pins candle `=0.9.2` (the release that carries
//! `quantized_qwen3` without dragging in the Oniguruma C build), and that
//! release has no such module, so the code lives here instead. The port is
//! narrowed to what PAM actually loads: `gpt2`-style byte-level BPE with the
//! Qwen pre-tokenizer. Other tokenizer models are refused rather than
//! guessed at.
//!
//! # Special tokens
//!
//! `tokenizer.ggml.token_type` classifies every token; type 3 is *control*
//! (`<|im_start|>`, `<|im_end|>`, `<|endoftext|>`) and type 4 is
//! *user-defined*. Both are registered as special added tokens, which is
//! what makes them survive a round trip as single ids and what lets
//! `decode(skip_special_tokens = true)` drop them from generated text.
//!
//! # Chat format
//!
//! [`chatml`] hard-codes the Qwen3 `ChatML` template rather than reading
//! `tokenizer.chat_template` and rendering Jinja. The runtime only ever
//! loads `qwen3` and `qwen3moe` — every other architecture is refused before
//! candle is touched — so there is exactly one template to get right, and
//! hard-coding it means a malformed template string in a downloaded file
//! cannot change how PAM frames a prompt.

use candle_core::quantized::gguf_file;
use tokenizers::{
    AddedToken, Tokenizer,
    decoders::byte_level::ByteLevel as ByteLevelDecoder,
    models::bpe::{BPE, Vocab},
    normalizers::unicode::NFC,
    pre_tokenizers::{
        byte_level::ByteLevel as ByteLevelPre,
        sequence::Sequence,
        split::{Split, SplitPattern},
    },
    processors::byte_level::ByteLevel as ByteLevelProcessor,
    tokenizer::SplitDelimiterBehavior,
};

/// The Qwen2/Qwen3 pre-tokenizer split pattern, the same one
/// `tokenizer.json` carries for these models.
///
/// It has to match byte for byte in behaviour: a different split produces a
/// different token stream, which produces different logits, which is a model
/// that quietly answers worse rather than one that fails.
const QWEN_SPLIT_PATTERN: &str = r"(?i:'s|'t|'re|'ve|'m|'ll|'d)|[^\r\n\p{L}\p{N}]?\p{L}+|\p{N}| ?[^\s\p{L}\p{N}]+[\r\n]*|\s*[\r\n]+|\s+(?!\S)|\s+";

/// GGUF token type for a control token (`<|im_start|>` and friends).
const TOKEN_TYPE_CONTROL: u32 = 3;

/// GGUF token type for a user-defined token.
const TOKEN_TYPE_USER_DEFINED: u32 = 4;

/// A tokenizer rebuilt from a model file, with the ids generation needs.
///
/// `eos_id` is not optional: a model that cannot say when it is finished is
/// a model that generates until `max_tokens` every time, and that is a
/// failure worth refusing at load rather than discovering at the first
/// prompt.
pub struct GgufTokenizer {
    /// The reconstructed tokenizer. Public because the runtime encodes and
    /// decodes directly against it and wrapping every method would buy
    /// nothing.
    pub inner: Tokenizer,
    /// `tokenizer.ggml.bos_token_id`, when the file carries one. Qwen3 does
    /// not use a BOS token.
    pub bos_id: Option<u32>,
    /// `tokenizer.ggml.eos_token_id` — the stop signal.
    pub eos_id: u32,
    /// `tokenizer.ggml.add_bos_token`, defaulting to false, which is what
    /// the Qwen files say.
    pub add_bos: bool,
}

/// Everything rebuilding a tokenizer from GGUF metadata can fail on.
#[derive(Debug, thiserror::Error)]
pub enum TokenizerError {
    /// A metadata key the vocabulary cannot be rebuilt without is absent.
    #[error("the model file has no `{0}` metadata key")]
    MissingKey(&'static str),
    /// `tokenizer.ggml.model` names something other than `gpt2`.
    #[error("tokenizer model {0:?} is not supported (gpt2)")]
    UnsupportedModel(String),
    /// The metadata was present but did not assemble into a tokenizer.
    #[error("could not build the tokenizer: {0}")]
    Build(String),
}

/// Reads a metadata key, or names it in a [`TokenizerError::MissingKey`].
fn metadata<'a>(
    content: &'a gguf_file::Content,
    key: &'static str,
) -> Result<&'a gguf_file::Value, TokenizerError> {
    content
        .metadata
        .get(key)
        .ok_or(TokenizerError::MissingKey(key))
}

/// Coerces any GGUF integer to `u32`.
///
/// Token ids are written as `u32` by every exporter worth naming, but the
/// format allows any width and a file that used `i32` is not wrong — it is
/// just written by a different tool.
fn to_u32(value: &gguf_file::Value) -> Option<u32> {
    match value {
        gguf_file::Value::U8(v) => Some(u32::from(*v)),
        gguf_file::Value::I8(v) => u32::try_from(*v).ok(),
        gguf_file::Value::U16(v) => Some(u32::from(*v)),
        gguf_file::Value::I16(v) => u32::try_from(*v).ok(),
        gguf_file::Value::U32(v) => Some(*v),
        gguf_file::Value::I32(v) => u32::try_from(*v).ok(),
        gguf_file::Value::U64(v) => u32::try_from(*v).ok(),
        gguf_file::Value::I64(v) => u32::try_from(*v).ok(),
        _ => None,
    }
}

/// Reads a string array metadata value.
fn string_array(
    value: &gguf_file::Value,
    key: &'static str,
) -> Result<Vec<String>, TokenizerError> {
    let items = value
        .to_vec()
        .map_err(|_| TokenizerError::Build(format!("`{key}` is not an array")))?;
    items
        .iter()
        .map(|item| {
            item.to_string()
                .cloned()
                .map_err(|_| TokenizerError::Build(format!("`{key}` holds a non-string element")))
        })
        .collect()
}

/// Splits `"a b"` merge entries into the pairs the BPE builder wants.
fn merges(value: &gguf_file::Value) -> Result<Vec<(String, String)>, TokenizerError> {
    string_array(value, "tokenizer.ggml.merges")?
        .into_iter()
        .map(|entry| {
            entry
                .split_once(' ')
                .map(|(left, right)| (left.to_string(), right.to_string()))
                .ok_or_else(|| TokenizerError::Build(format!("invalid merge entry `{entry}`")))
        })
        .collect()
}

/// Rebuilds a tokenizer from a model file's metadata.
///
/// Only `tokenizer.ggml.model = "gpt2"` is accepted. The pipeline is the
/// Qwen one: NFC normalizer, the [`QWEN_SPLIT_PATTERN`] split followed by a
/// byte-level pre-tokenizer, and a byte-level decoder and post-processor —
/// all three constructed with `add_prefix_space = false`, `trim_offsets =
/// false`, `use_regex = false`, because the split above has already done the
/// segmenting the byte-level stage would otherwise redo.
pub fn from_gguf(content: &gguf_file::Content) -> Result<GgufTokenizer, TokenizerError> {
    let model = metadata(content, "tokenizer.ggml.model")?
        .to_string()
        .map_err(|_| TokenizerError::Build("`tokenizer.ggml.model` is not a string".into()))?
        .to_lowercase();
    if model != "gpt2" {
        return Err(TokenizerError::UnsupportedModel(model));
    }

    let tokens = string_array(
        metadata(content, "tokenizer.ggml.tokens")?,
        "tokenizer.ggml.tokens",
    )?;
    let vocab: Vocab = tokens
        .iter()
        .enumerate()
        .map(|(index, token)| (token.clone(), u32::try_from(index).unwrap_or(u32::MAX)))
        .collect();
    let merges = merges(metadata(content, "tokenizer.ggml.merges")?)?;

    let bpe = BPE::builder()
        .vocab_and_merges(vocab, merges)
        .build()
        .map_err(|err| TokenizerError::Build(err.to_string()))?;
    let mut inner = Tokenizer::new(bpe);

    let split = Split::new(
        SplitPattern::Regex(QWEN_SPLIT_PATTERN.to_string()),
        SplitDelimiterBehavior::Isolated,
        false,
    )
    .map_err(|err| TokenizerError::Build(err.to_string()))?;
    let byte_level = ByteLevelPre::new(false, false, false);
    inner.with_normalizer(Some(NFC));
    inner.with_pre_tokenizer(Some(Sequence::new(vec![split.into(), byte_level.into()])));
    inner.with_decoder(Some(ByteLevelDecoder::new(false, false, false)));
    inner.with_post_processor(Some(ByteLevelProcessor::new(false, false, false)));

    // Control (3) and user-defined (4) tokens become special added tokens so
    // they encode as one id and drop back out on a skip-specials decode.
    if let Ok(types) = metadata(content, "tokenizer.ggml.token_type")
        && let Ok(items) = types.to_vec()
    {
        let specials: Vec<AddedToken> = items
            .iter()
            .enumerate()
            .filter_map(|(index, value)| {
                let kind = to_u32(value)?;
                if kind == TOKEN_TYPE_CONTROL || kind == TOKEN_TYPE_USER_DEFINED {
                    tokens
                        .get(index)
                        .map(|token| AddedToken::from(token.clone(), true))
                } else {
                    None
                }
            })
            .collect();
        if !specials.is_empty() {
            inner.add_special_tokens(&specials);
        }
    }

    let eos_id = to_u32(metadata(content, "tokenizer.ggml.eos_token_id")?)
        .ok_or(TokenizerError::MissingKey("tokenizer.ggml.eos_token_id"))?;
    let bos_id = content
        .metadata
        .get("tokenizer.ggml.bos_token_id")
        .and_then(to_u32);
    let add_bos = content
        .metadata
        .get("tokenizer.ggml.add_bos_token")
        .and_then(|value| value.to_bool().ok())
        .unwrap_or(false);

    Ok(GgufTokenizer {
        inner,
        bos_id,
        eos_id,
        add_bos,
    })
}

/// Frames a prompt in the Qwen3 `ChatML` template.
///
/// The system turn is emitted only when there is a system prompt: Qwen's own
/// template omits it rather than sending an empty one, and an empty system
/// turn measurably shifts short answers.
///
/// The trailing `<|im_start|>assistant\n` is the handoff — the model
/// continues from there, which is why nothing follows it.
#[must_use]
pub fn chatml(system: Option<&str>, user: &str) -> String {
    let mut out = String::new();
    if let Some(system) = system {
        out.push_str("<|im_start|>system\n");
        out.push_str(system);
        out.push_str("<|im_end|>\n");
    }
    out.push_str("<|im_start|>user\n");
    out.push_str(user);
    out.push_str("<|im_end|>\n<|im_start|>assistant\n");
    out
}
