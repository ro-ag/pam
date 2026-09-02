//! Tokenizer tests against a GGUF synthesized in memory.
//!
//! No weights and no fixture file: the header these tests build is a real
//! one — `gguf_file::Content::read` parses it — carrying a forty-token
//! byte-level vocabulary and the handful of merges needed to spell one
//! sentence. That is enough to prove the pipeline is wired the way Qwen
//! expects, which is the only thing this module can be wrong about.

use std::io::Cursor;

use candle_core::quantized::gguf_file;

use crate::tokenizer::{TokenizerError, chatml, from_gguf};

/// GGUF metadata value types, by their wire ids.
const TYPE_U32: u32 = 4;
const TYPE_BOOL: u32 = 7;
const TYPE_STRING: u32 = 8;
const TYPE_ARRAY: u32 = 9;

/// A metadata value the fixtures need.
enum Value {
    U32(u32),
    Bool(bool),
    Str(&'static str),
    StrArray(Vec<String>),
    U32Array(Vec<u32>),
}

/// Little-endian GGUF writer, just enough for a header with no tensors.
#[derive(Default)]
struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    fn u32(&mut self, value: u32) {
        self.buf.extend_from_slice(&value.to_le_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.buf.extend_from_slice(&value.to_le_bytes());
    }

    fn string(&mut self, value: &str) {
        self.u64(value.len() as u64);
        self.buf.extend_from_slice(value.as_bytes());
    }

    fn value(&mut self, value: &Value) {
        match value {
            Value::U32(v) => {
                self.u32(TYPE_U32);
                self.u32(*v);
            }
            Value::Bool(v) => {
                self.u32(TYPE_BOOL);
                self.buf.push(u8::from(*v));
            }
            Value::Str(v) => {
                self.u32(TYPE_STRING);
                self.string(v);
            }
            Value::StrArray(items) => {
                self.u32(TYPE_ARRAY);
                self.u32(TYPE_STRING);
                self.u64(items.len() as u64);
                for item in items {
                    self.string(item);
                }
            }
            Value::U32Array(items) => {
                self.u32(TYPE_ARRAY);
                self.u32(TYPE_U32);
                self.u64(items.len() as u64);
                for item in items {
                    self.u32(*item);
                }
            }
        }
    }
}

/// Builds a tensor-less GGUF v3 header carrying exactly `kv`.
fn synth(kv: &[(&str, Value)]) -> Vec<u8> {
    let mut writer = Writer::default();
    writer.buf.extend_from_slice(b"GGUF");
    writer.u32(3);
    writer.u64(0);
    writer.u64(kv.len() as u64);
    for (key, value) in kv {
        writer.string(key);
        writer.value(value);
    }
    // A little slack past the header so the alignment pad has somewhere to go.
    writer.buf.extend_from_slice(&[0u8; 64]);
    writer.buf
}

/// The vocabulary: three control tokens, the byte-level characters the
/// fixture sentence needs, then the merged pieces.
fn vocabulary() -> Vec<String> {
    let mut tokens: Vec<String> = vec![
        "<|endoftext|>".to_string(),
        "<|im_start|>".to_string(),
        "<|im_end|>".to_string(),
    ];
    for ch in [
        'h', 'i', 'Ġ', 't', 'e', 'r', 'a', 's', 'y', 'n', 'm', 'o', 'u', 'w', 'd', 'l', 'c', 'p',
        'g', 'b', 'f', 'k', 'v', 'x', 'z', 'q', 'j', 'Ċ',
    ] {
        tokens.push(ch.to_string());
    }
    for piece in ["hi", "Ġt", "Ġth", "Ġthe", "Ġther", "Ġthere"] {
        tokens.push(piece.to_string());
    }
    tokens
}

/// The merges that build those pieces, in application order.
fn merge_rules() -> Vec<String> {
    ["h i", "Ġ t", "Ġt h", "Ġth e", "Ġthe r", "Ġther e"]
        .iter()
        .map(|rule| (*rule).to_string())
        .collect()
}

/// Token types: 3 (control) for the three specials, 1 (normal) for the rest.
fn token_types(len: usize) -> Vec<u32> {
    (0..len)
        .map(|index| if index < 3 { 3 } else { 1 })
        .collect()
}

/// The default fixture: `gpt2` model, `<|im_end|>` as EOS.
fn fixture_bytes() -> Vec<u8> {
    let tokens = vocabulary();
    let types = token_types(tokens.len());
    synth(&[
        ("general.architecture", Value::Str("qwen3")),
        ("tokenizer.ggml.model", Value::Str("gpt2")),
        ("tokenizer.ggml.tokens", Value::StrArray(tokens)),
        ("tokenizer.ggml.merges", Value::StrArray(merge_rules())),
        ("tokenizer.ggml.token_type", Value::U32Array(types)),
        ("tokenizer.ggml.eos_token_id", Value::U32(2)),
        ("tokenizer.ggml.add_bos_token", Value::Bool(false)),
    ])
}

/// Parses fixture bytes into the content `from_gguf` consumes.
fn content(bytes: &[u8]) -> gguf_file::Content {
    let mut cursor = Cursor::new(bytes);
    gguf_file::Content::read(&mut cursor).expect("the fixture is a readable GGUF header")
}

#[test]
fn round_trips_a_sentence() {
    let bytes = fixture_bytes();
    let tokenizer = from_gguf(&content(&bytes)).expect("the fixture builds a tokenizer");

    let encoding = tokenizer
        .inner
        .encode("hi there", true)
        .expect("the fixture vocabulary covers the sentence");
    let ids = encoding.get_ids();
    assert_eq!(
        ids.len(),
        2,
        "one piece per word, got {:?}",
        encoding.get_tokens()
    );

    let decoded = tokenizer
        .inner
        .decode(ids, true)
        .expect("ids decode back to text");
    assert_eq!(decoded, "hi there");
}

#[test]
fn control_tokens_encode_as_single_ids() {
    let bytes = fixture_bytes();
    let tokenizer = from_gguf(&content(&bytes)).expect("the fixture builds a tokenizer");

    let encoding = tokenizer
        .inner
        .encode("<|im_start|>hi<|im_end|>", true)
        .expect("control tokens are registered");
    assert_eq!(encoding.get_ids(), &[1, 31, 2]);

    let visible = tokenizer
        .inner
        .decode(encoding.get_ids(), true)
        .expect("specials decode away");
    assert_eq!(visible, "hi");
}

#[test]
fn reads_the_special_ids() {
    let bytes = fixture_bytes();
    let tokenizer = from_gguf(&content(&bytes)).expect("the fixture builds a tokenizer");

    assert_eq!(tokenizer.eos_id, 2, "eos_token_id names <|im_end|>");
    assert_eq!(tokenizer.bos_id, None, "qwen files carry no BOS");
    assert!(!tokenizer.add_bos, "and do not ask for one");
}

#[test]
fn refuses_a_tokenizer_model_it_does_not_implement() {
    let tokens = vocabulary();
    let types = token_types(tokens.len());
    let bytes = synth(&[
        ("tokenizer.ggml.model", Value::Str("llama")),
        ("tokenizer.ggml.tokens", Value::StrArray(tokens)),
        ("tokenizer.ggml.merges", Value::StrArray(merge_rules())),
        ("tokenizer.ggml.token_type", Value::U32Array(types)),
        ("tokenizer.ggml.eos_token_id", Value::U32(2)),
    ]);

    match from_gguf(&content(&bytes)) {
        Err(TokenizerError::UnsupportedModel(model)) => assert_eq!(model, "llama"),
        Err(other) => panic!("expected UnsupportedModel, got {other:?}"),
        Ok(_) => panic!("expected UnsupportedModel, got a tokenizer"),
    }
}

#[test]
fn names_the_missing_key() {
    let tokens = vocabulary();
    let bytes = synth(&[
        ("tokenizer.ggml.model", Value::Str("gpt2")),
        ("tokenizer.ggml.tokens", Value::StrArray(tokens)),
        ("tokenizer.ggml.merges", Value::StrArray(merge_rules())),
    ]);

    match from_gguf(&content(&bytes)) {
        Err(TokenizerError::MissingKey(key)) => {
            assert_eq!(key, "tokenizer.ggml.eos_token_id");
        }
        Err(other) => panic!("expected MissingKey, got {other:?}"),
        Ok(_) => panic!("expected MissingKey, got a tokenizer"),
    }
}

#[test]
fn chatml_is_byte_exact_with_a_system_prompt() {
    assert_eq!(
        chatml(Some("You are Pam."), "hi there"),
        "<|im_start|>system\nYou are Pam.<|im_end|>\n\
         <|im_start|>user\nhi there<|im_end|>\n\
         <|im_start|>assistant\n"
    );
}

#[test]
fn chatml_omits_the_system_turn_when_there_is_none() {
    assert_eq!(
        chatml(None, "hi there"),
        "<|im_start|>user\nhi there<|im_end|>\n<|im_start|>assistant\n"
    );
}

#[test]
fn debug_prints_the_error_cases() {
    let err = TokenizerError::Build("no merges".to_string());
    assert_eq!(err.to_string(), "could not build the tokenizer: no merges");
    assert_eq!(
        TokenizerError::MissingKey("tokenizer.ggml.tokens").to_string(),
        "the model file has no `tokenizer.ggml.tokens` metadata key"
    );
}
