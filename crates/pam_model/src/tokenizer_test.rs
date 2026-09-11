//! Tokenizer tests against a GGUF synthesized in memory.
//!
//! No weights and no fixture file: the header these tests build is a real
//! one — `gguf_file::Content::read` parses it — carrying a forty-token
//! byte-level vocabulary and the handful of merges needed to spell one
//! sentence. That is enough to prove the pipeline is wired the way Qwen
//! expects, which is the only thing this module can be wrong about.

use std::io::Cursor;

use candle_core::quantized::gguf_file;

use crate::tokenizer::{ChatFraming, TokenizerError, chatml, framing_from_declared, from_gguf};

/// GGUF metadata value types, by their wire ids.
const TYPE_U32: u32 = 4;
const TYPE_BOOL: u32 = 7;
const TYPE_STRING: u32 = 8;
const TYPE_ARRAY: u32 = 9;

/// A metadata value the fixtures need.
#[derive(Clone)]
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
        chatml(Some("You are Pam."), "hi there", ChatFraming::Qwen3Plain),
        "<|im_start|>system\nYou are Pam.<|im_end|>\n\
         <|im_start|>user\nhi there<|im_end|>\n\
         <|im_start|>assistant\n"
    );
}

#[test]
fn chatml_omits_the_system_turn_when_there_is_none() {
    assert_eq!(
        chatml(None, "hi there", ChatFraming::Qwen3Plain),
        "<|im_start|>user\nhi there<|im_end|>\n<|im_start|>assistant\n"
    );
}

#[test]
fn chatml_appends_the_empty_think_block_when_thinking_is_disabled() {
    assert_eq!(
        chatml(None, "hi there", ChatFraming::Qwen3ThinkingDisabled),
        "<|im_start|>user\nhi there<|im_end|>\n\
         <|im_start|>assistant\n<think>\n\n</think>\n\n"
    );
}

#[test]
fn undeclared_framing_is_generic_chatml_and_never_qualified() {
    assert_eq!(ChatFraming::Undeclared.assistant_suffix(), "");
    assert!(!ChatFraming::Undeclared.template_qualified());
    assert!(ChatFraming::Qwen3Plain.template_qualified());
    assert!(ChatFraming::Qwen3ThinkingDisabled.template_qualified());
}

// --- Frozen framing bytes ------------------------------------------------------
//
// The generation-prompt tails that decide framing, byte-exact from the pinned
// upstream tokenizer_config files. The `\n` sequences inside the Jinja string
// literals are backslash-n in the template SOURCE — the classifier matches
// these source bytes, and `chatml` renders the real-newline form.
//
// The classification of the FULL pinned templates was verified against the
// upstream files themselves (task #108, note 417 hashes): dense upstream
// tokenizer_config template string SHA-256 a55ee1b1660128b7098723e0abcd92caa0
// 788061051c62d51cbe87d9cf1974d8 and the older revision embedded in the pinned
// Qwen3-14B-Q5_K_M.gguf (57f1fd00f0013a2be96aa79b857391f27e23df5b5f847072b524c
// 897e24d0361) both carry this exact dense tail; the Coder upstream template
// (5a38bfa05833266240066aedc497decc9b00cc0d3e3b8cceea98cf530196ab06) carries
// the exact plain tail below.
const DENSE_GENERATION_TAIL: &str = r"{%- if add_generation_prompt %}
    {{- '<|im_start|>assistant\n' }}
    {%- if enable_thinking is defined and enable_thinking is false %}
        {{- '<think>\n\n</think>\n\n' }}
    {%- endif %}
{%- endif %}";

const CODER_GENERATION_TAIL: &str = r"{%- if add_generation_prompt %}
    {{- '<|im_start|>assistant\n' }}
{%- endif %}
";

#[test]
fn classifies_the_dense_generation_tail_as_thinking_disabled() {
    assert_eq!(
        framing_from_declared(DENSE_GENERATION_TAIL).expect("the dense tail is classifiable"),
        ChatFraming::Qwen3ThinkingDisabled
    );
}

#[test]
fn classifies_the_coder_generation_tail_as_plain() {
    assert_eq!(
        framing_from_declared(CODER_GENERATION_TAIL).expect("the Coder tail is classifiable"),
        ChatFraming::Qwen3Plain
    );
}

#[test]
fn refuses_a_template_that_thinks_unconditionally() {
    let template = concat!(
        "{%- if add_generation_prompt %}",
        "{{- '<|im_start|>assistant\\n<think>\\n' }}",
        "{%- endif %}"
    );
    match framing_from_declared(template) {
        Err(TokenizerError::UnsupportedChatTemplate(reason)) => {
            assert_eq!(reason, "emits a think block unconditionally");
        }
        other => panic!("expected UnsupportedChatTemplate, got {other:?}"),
    }
}

#[test]
fn refuses_a_template_that_is_not_chatml() {
    match framing_from_declared("[INST] {Messages} [/INST]") {
        Err(TokenizerError::UnsupportedChatTemplate(reason)) => {
            assert_eq!(reason, "not a ChatML template");
        }
        other => panic!("expected UnsupportedChatTemplate, got {other:?}"),
    }
}

#[test]
fn refuses_a_template_that_declares_thinking_without_the_empty_block() {
    let template = concat!(
        "{%- if add_generation_prompt %}",
        "{{- '<|im_start|>assistant\\n' }}",
        "{%- if enable_thinking %}{{- '<think>\\n' }}{%- endif %}",
        "{%- endif %}"
    );
    match framing_from_declared(template) {
        Err(TokenizerError::UnsupportedChatTemplate(reason)) => assert_eq!(
            reason,
            "declares enable_thinking but not the empty think block PAM renders"
        ),
        other => panic!("expected UnsupportedChatTemplate, got {other:?}"),
    }
}

#[test]
fn declares_generic_chatml_when_the_file_declares_none() {
    let bytes = fixture_bytes();
    let tokenizer = from_gguf(&content(&bytes)).expect("the fixture builds a tokenizer");
    assert_eq!(tokenizer.framing, ChatFraming::Undeclared);
    assert!(!tokenizer.framing.template_qualified());
}

#[test]
fn derives_the_framing_from_the_declared_template_at_load() {
    let tokens = vocabulary();
    let types = token_types(tokens.len());
    let base = [
        ("general.architecture", Value::Str("qwen3")),
        ("tokenizer.ggml.model", Value::Str("gpt2")),
        ("tokenizer.ggml.tokens", Value::StrArray(tokens.clone())),
        ("tokenizer.ggml.merges", Value::StrArray(merge_rules())),
        ("tokenizer.ggml.token_type", Value::U32Array(types.clone())),
        ("tokenizer.ggml.eos_token_id", Value::U32(2)),
        ("tokenizer.ggml.add_bos_token", Value::Bool(false)),
    ];

    let mut dense_kv = base.to_vec();
    dense_kv.push(("tokenizer.chat_template", Value::Str(DENSE_GENERATION_TAIL)));
    let tokenizer = from_gguf(&content(&synth(&dense_kv))).expect("dense fixture builds");
    assert_eq!(tokenizer.framing, ChatFraming::Qwen3ThinkingDisabled);
    assert!(tokenizer.framing.template_qualified());

    let mut coder_kv = base.to_vec();
    coder_kv.push(("tokenizer.chat_template", Value::Str(CODER_GENERATION_TAIL)));
    let tokenizer = from_gguf(&content(&synth(&coder_kv))).expect("coder fixture builds");
    assert_eq!(tokenizer.framing, ChatFraming::Qwen3Plain);

    let bytes = synth(&base);
    let tokenizer = from_gguf(&content(&bytes)).expect("bare fixture builds");
    assert_eq!(tokenizer.framing, ChatFraming::Undeclared);
}

#[test]
fn debug_prints_the_error_cases() {
    let err = TokenizerError::Build("no merges".to_string());
    assert_eq!(err.to_string(), "could not build the tokenizer: no merges");
    assert_eq!(
        TokenizerError::MissingKey("tokenizer.ggml.tokens").to_string(),
        "the model file has no `tokenizer.ggml.tokens` metadata key"
    );
    assert_eq!(
        TokenizerError::UnsupportedChatTemplate("emits a think block unconditionally".into())
            .to_string(),
        "the declared chat template is not one PAM can frame: emits a think block unconditionally"
    );
}
