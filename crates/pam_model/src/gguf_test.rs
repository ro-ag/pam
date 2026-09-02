use std::io::Cursor;

use crate::gguf::{
    GGUF_MAX_METADATA_KV, GGUF_MAX_TENSORS, GgufError, parse_info, quant_label_for, read_info,
};

// ggml dtype ids the fixtures use.
pub(crate) const GGML_F32: u32 = 0;
pub(crate) const GGML_Q8_0: u32 = 8;
pub(crate) const GGML_Q4_K: u32 = 12;
pub(crate) const GGML_Q6_K: u32 = 14;

/// A metadata value a fixture can carry. Deliberately a small subset — the
/// parser's job here is to walk past what it does not need, and these are the
/// types real Qwen GGUFs use for the keys [`GgufInfo`] reads.
#[derive(Debug, Clone)]
pub(crate) enum GgufValue {
    U32(u32),
    U64(u64),
    F32(f32),
    Bool(bool),
    Str(String),
    StrArray(Vec<String>),
    U32Array(Vec<u32>),
}

/// A tensor description for the fixture builder: name, dims, ggml dtype.
type TensorSpec<'a> = (&'a str, &'a [u64], u32);

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

    fn value(&mut self, value: &GgufValue) {
        match value {
            GgufValue::U32(v) => {
                self.u32(4);
                self.u32(*v);
            }
            GgufValue::U64(v) => {
                self.u32(10);
                self.u64(*v);
            }
            GgufValue::F32(v) => {
                self.u32(6);
                self.buf.extend_from_slice(&v.to_le_bytes());
            }
            GgufValue::Bool(v) => {
                self.u32(7);
                self.buf.push(u8::from(*v));
            }
            GgufValue::Str(v) => {
                self.u32(8);
                self.string(v);
            }
            GgufValue::StrArray(items) => {
                self.u32(9);
                self.u32(8);
                self.u64(items.len() as u64);
                for item in items {
                    self.string(item);
                }
            }
            GgufValue::U32Array(items) => {
                self.u32(9);
                self.u32(4);
                self.u64(items.len() as u64);
                for item in items {
                    self.u32(*item);
                }
            }
        }
    }
}

/// Bytes a tensor of `dims` in `dtype` occupies, mirroring ggml's block
/// layout. Only the dtypes the fixtures use.
pub(crate) fn tensor_bytes(dims: &[u64], dtype: u32) -> u64 {
    let elements: u64 = dims.iter().product();
    let (block, size) = match dtype {
        GGML_F32 => (1, 4),
        GGML_Q8_0 => (32, 34),
        GGML_Q4_K => (256, 144),
        GGML_Q6_K => (256, 210),
        other => panic!("fixture used an unmodelled dtype {other}"),
    };
    elements.div_ceil(block) * size
}

/// Builds a real little-endian GGUF header with tensor offsets laid out
/// sequentially at 32-byte alignment.
///
/// `general.architecture` and `general.file_type` are always written;
/// `extra_kv` is appended after them, so a fixture can override alignment or
/// add architecture-scoped keys.
pub(crate) fn synth_gguf(
    version: u32,
    arch: &str,
    file_type: u32,
    tensors: &[TensorSpec<'_>],
    extra_kv: &[(&str, GgufValue)],
) -> Vec<u8> {
    let alignment = extra_kv
        .iter()
        .find_map(|(key, value)| match (*key, value) {
            ("general.alignment", GgufValue::U32(v)) => Some(u64::from(*v)),
            _ => None,
        })
        .unwrap_or(32);

    let mut offset = 0u64;
    let placed: Vec<(&str, &[u64], u32, u64)> = tensors
        .iter()
        .map(|(name, dims, dtype)| {
            let at = offset;
            offset += tensor_bytes(dims, *dtype);
            offset = offset.div_ceil(alignment.max(1)) * alignment.max(1);
            (*name, *dims, *dtype, at)
        })
        .collect();

    synth_gguf_raw(version, *b"GGUF", arch, file_type, &placed, extra_kv)
}

/// The builder underneath [`synth_gguf`], with the magic and every tensor
/// offset spelled out — how a fixture forges an overlap or a bad magic.
pub(crate) fn synth_gguf_raw(
    version: u32,
    magic: [u8; 4],
    arch: &str,
    file_type: u32,
    tensors: &[(&str, &[u64], u32, u64)],
    extra_kv: &[(&str, GgufValue)],
) -> Vec<u8> {
    let mut kv: Vec<(&str, GgufValue)> = Vec::new();
    if !arch.is_empty() {
        kv.push(("general.architecture", GgufValue::Str(arch.to_owned())));
    }
    kv.push(("general.file_type", GgufValue::U32(file_type)));
    kv.extend(extra_kv.iter().map(|(k, v)| (*k, v.clone())));

    let mut w = Writer::default();
    w.buf.extend_from_slice(&magic);
    w.u32(version);
    w.u64(tensors.len() as u64);
    w.u64(kv.len() as u64);
    for (key, value) in &kv {
        w.string(key);
        w.value(value);
    }
    for (name, dims, dtype, offset) in tensors {
        w.string(name);
        w.u32(u32::try_from(dims.len()).unwrap());
        for dim in *dims {
            w.u64(*dim);
        }
        w.u32(*dtype);
        w.u64(*offset);
    }
    w.buf
}

/// A minimal valid mixture-of-experts fixture: two tensors, one expert
/// count.
pub(crate) fn tiny_moe_gguf() -> Vec<u8> {
    synth_gguf(
        3,
        "qwen3moe",
        15,
        &[
            ("token_embd.weight", &[512, 256], GGML_Q4_K),
            ("output_norm.weight", &[512], GGML_F32),
        ],
        &[
            ("general.name", GgufValue::Str("Qwen3 Coder tiny".into())),
            ("qwen3moe.context_length", GgufValue::U32(262_144)),
            ("qwen3moe.expert_count", GgufValue::U32(128)),
        ],
    )
}

#[test]
fn parses_a_v3_moe_header() {
    let info = parse_info(Cursor::new(tiny_moe_gguf())).unwrap();

    assert_eq!(info.version, 3);
    assert_eq!(info.architecture, "qwen3moe");
    assert_eq!(info.name.as_deref(), Some("Qwen3 Coder tiny"));
    assert_eq!(info.quant_label, "Q4_K_M");
    assert_eq!(info.context_length, Some(262_144));
    assert_eq!(info.expert_count, Some(128));
    assert_eq!(info.tensor_count, 2);
    assert_eq!(info.parameter_count, 512 * 256 + 512);
}

#[test]
fn parses_a_v2_dense_header() {
    let bytes = synth_gguf(
        2,
        "qwen3",
        7,
        &[("blk.0.attn_q.weight", &[128, 128], GGML_Q8_0)],
        &[("qwen3.context_length", GgufValue::U64(32_768))],
    );
    let info = parse_info(Cursor::new(bytes)).unwrap();

    assert_eq!(info.version, 2);
    assert_eq!(info.architecture, "qwen3");
    assert_eq!(info.name, None);
    assert_eq!(info.quant_label, "Q8_0");
    assert_eq!(info.context_length, Some(32_768));
    assert_eq!(info.expert_count, None);
    assert_eq!(info.parameter_count, 128 * 128);
}

#[test]
fn walks_past_metadata_it_does_not_need() {
    // Real GGUFs carry the whole tokenizer in metadata. The parser must skip
    // arrays and exotic scalars without tripping over them.
    let bytes = synth_gguf(
        3,
        "qwen3",
        18,
        &[("output.weight", &[64, 64], GGML_Q6_K)],
        &[
            (
                "tokenizer.ggml.tokens",
                GgufValue::StrArray(vec!["<|im_start|>".into(), "hello".into(), "!".into()]),
            ),
            (
                "tokenizer.ggml.token_type",
                GgufValue::U32Array(vec![3, 1, 1]),
            ),
            ("qwen3.rope.freq_base", GgufValue::F32(1_000_000.0)),
            ("qwen3.attention.causal", GgufValue::Bool(true)),
            ("qwen3.context_length", GgufValue::U32(8_192)),
        ],
    );
    let info = parse_info(Cursor::new(bytes)).unwrap();

    assert_eq!(info.quant_label, "Q6_K");
    assert_eq!(info.context_length, Some(8_192));
}

#[test]
fn rejects_a_bad_magic() {
    let bytes = synth_gguf_raw(3, *b"GGML", "qwen3", 15, &[], &[]);
    assert!(matches!(
        parse_info(Cursor::new(bytes)),
        Err(GgufError::BadMagic)
    ));
}

#[test]
fn rejects_version_1() {
    let bytes = synth_gguf(1, "qwen3", 15, &[], &[]);
    assert!(matches!(
        parse_info(Cursor::new(bytes)),
        Err(GgufError::UnsupportedVersion(1))
    ));
}

#[test]
fn rejects_an_absurd_tensor_count() {
    let mut bytes = synth_gguf(3, "qwen3", 15, &[], &[]);
    bytes[8..16].copy_from_slice(&(GGUF_MAX_TENSORS + 1).to_le_bytes());

    match parse_info(Cursor::new(bytes)) {
        Err(GgufError::TooLarge { what, value, limit }) => {
            assert_eq!(what, "tensor count");
            assert_eq!(value, GGUF_MAX_TENSORS + 1);
            assert_eq!(limit, GGUF_MAX_TENSORS);
        }
        other => panic!("expected TooLarge, got {other:?}"),
    }
}

#[test]
fn rejects_an_absurd_metadata_count() {
    let mut bytes = synth_gguf(3, "qwen3", 15, &[], &[]);
    bytes[16..24].copy_from_slice(&(GGUF_MAX_METADATA_KV + 1).to_le_bytes());

    match parse_info(Cursor::new(bytes)) {
        Err(GgufError::TooLarge { what, .. }) => assert_eq!(what, "metadata KV count"),
        other => panic!("expected TooLarge, got {other:?}"),
    }
}

#[test]
fn rejects_an_overlong_tensor_name() {
    let name = "n".repeat(128);
    let bytes = synth_gguf(3, "qwen3", 15, &[(&name, &[4], GGML_F32)], &[]);

    match parse_info(Cursor::new(bytes)) {
        Err(GgufError::Malformed(message)) => assert!(
            message.contains("tensor name"),
            "message should name the field: {message}"
        ),
        other => panic!("expected Malformed, got {other:?}"),
    }
}

#[test]
fn accepts_a_tensor_name_at_the_limit() {
    let name = "n".repeat(127);
    let bytes = synth_gguf(3, "qwen3", 15, &[(&name, &[4], GGML_F32)], &[]);
    assert_eq!(parse_info(Cursor::new(bytes)).unwrap().tensor_count, 1);
}

#[test]
fn rejects_overlapping_tensor_offsets() {
    // Second tensor starts inside the first one's 4 KiB of data.
    let bytes = synth_gguf_raw(
        3,
        *b"GGUF",
        "qwen3",
        15,
        &[
            ("a.weight", &[32, 32], GGML_F32, 0),
            ("b.weight", &[32, 32], GGML_F32, 2048),
        ],
        &[],
    );

    match parse_info(Cursor::new(bytes)) {
        Err(GgufError::Malformed(message)) => assert!(
            message.contains("overlap"),
            "message should say overlap: {message}"
        ),
        other => panic!("expected Malformed, got {other:?}"),
    }
}

#[test]
fn rejects_an_unaligned_tensor_offset() {
    let bytes = synth_gguf_raw(
        3,
        *b"GGUF",
        "qwen3",
        15,
        &[("a.weight", &[32], GGML_F32, 7)],
        &[],
    );

    match parse_info(Cursor::new(bytes)) {
        Err(GgufError::Malformed(message)) => assert!(
            message.contains("align"),
            "message should say alignment: {message}"
        ),
        other => panic!("expected Malformed, got {other:?}"),
    }
}

#[test]
fn rejects_a_bad_alignment() {
    for bad in [0u32, 48, 8192] {
        let bytes = synth_gguf(
            3,
            "qwen3",
            15,
            &[],
            &[("general.alignment", GgufValue::U32(bad))],
        );
        match parse_info(Cursor::new(bytes)) {
            Err(GgufError::Malformed(message)) => assert!(
                message.contains("alignment"),
                "message should say alignment: {message}"
            ),
            other => panic!("expected Malformed for alignment {bad}, got {other:?}"),
        }
    }
}

#[test]
fn rejects_an_unknown_tensor_dtype() {
    let bytes = synth_gguf_raw(
        3,
        *b"GGUF",
        "qwen3",
        15,
        &[("a.weight", &[32], 4242, 0)],
        &[],
    );

    match parse_info(Cursor::new(bytes)) {
        Err(GgufError::Malformed(message)) => assert!(
            message.contains("4242"),
            "message should name the dtype: {message}"
        ),
        other => panic!("expected Malformed, got {other:?}"),
    }
}

#[test]
fn requires_the_architecture_key() {
    let bytes = synth_gguf_raw(3, *b"GGUF", "", 15, &[], &[]);
    assert!(matches!(
        parse_info(Cursor::new(bytes)),
        Err(GgufError::MissingMetadata("general.architecture"))
    ));
}

#[test]
fn reports_a_truncated_header_as_io() {
    let mut bytes = tiny_moe_gguf();
    bytes.truncate(bytes.len() - 12);
    assert!(matches!(
        parse_info(Cursor::new(bytes)),
        Err(GgufError::Io(_))
    ));
}

#[test]
fn quant_label_covers_the_ftype_table_and_falls_back() {
    assert_eq!(quant_label_for(15), "Q4_K_M");
    assert_eq!(quant_label_for(0), "F32");
    assert_eq!(quant_label_for(1), "F16");
    assert_eq!(quant_label_for(7), "Q8_0");
    assert_eq!(quant_label_for(18), "Q6_K");
    assert_eq!(quant_label_for(32), "BF16");
    assert_eq!(quant_label_for(999), "unknown(999)");
}

#[test]
fn read_info_opens_a_file_on_disk() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tiny.gguf");
    std::fs::write(&path, tiny_moe_gguf()).unwrap();

    let info = read_info(&path).unwrap();
    assert_eq!(info.architecture, "qwen3moe");
}

#[test]
fn read_info_on_a_missing_file_is_io() {
    let dir = tempfile::tempdir().unwrap();
    assert!(matches!(
        read_info(&dir.path().join("absent.gguf")),
        Err(GgufError::Io(_))
    ));
}
