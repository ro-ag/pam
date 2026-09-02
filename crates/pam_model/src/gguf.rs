//! A bounded GGUF header parser: what a file claims to be, read safely.
//!
//! # Why a hand-rolled parser
//!
//! candle can open a GGUF file, but only by mapping the whole thing. The
//! registry scans a directory that may hold a hundred gigabytes of weights
//! and wants one line of description per file, so it needs the header and
//! nothing else. This module reads exactly that — magic, version, metadata
//! key/values, tensor descriptors — and stops at the first byte of tensor
//! data.
//!
//! # Hostile input is the normal case
//!
//! A `.gguf` in the models directory is whatever the filesystem happens to
//! contain: a half-finished download, a renamed zip, a file the human
//! copied from somewhere. So every length in the header is treated as a
//! claim, not a fact. Counts, string lengths, and the running header size
//! are checked against hard caps before a single allocation
//! ([`GGUF_MAX_TENSORS`], [`GGUF_MAX_METADATA_KV`],
//! [`GGUF_MAX_STRING_BYTES`], [`GGUF_MAX_HEADER_BYTES`]); tensor offsets
//! must be aligned and must not overlap. The hardening is ported from
//! pam-old, which learned it the direct way.
//!
//! Every failure is a [`GgufError`] naming the field. Nothing here panics
//! and nothing here allocates on an unvalidated length.
//!
//! # Format
//!
//! Little-endian throughout: magic `GGUF`, `version: u32`,
//! `tensor_count: u64`, `metadata_kv_count: u64`, then the KV pairs
//! (`key: string`, `type: u32`, value), then one descriptor per tensor
//! (`name: string`, `n_dims: u32`, `dims: [u64]`, `dtype: u32`,
//! `offset: u64`). Version 1 used 32-bit counts and is refused; 2 and 3 are
//! accepted and differ only in details this parser does not read.

use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;

/// Hard cap on the bytes a header may consume before the parser gives up.
///
/// Real Qwen headers run a few megabytes (the tokenizer vocabulary lives in
/// metadata); 256 MiB is far above anything honest and far below anything
/// that would hurt.
pub const GGUF_MAX_HEADER_BYTES: u64 = 256 * 1024 * 1024;

/// Hard cap on one metadata string.
pub const GGUF_MAX_STRING_BYTES: u64 = 256 * 1024 * 1024;

/// Hard cap on a tensor name; ggml itself allows 64, llama.cpp writes far
/// less.
pub const GGUF_MAX_TENSOR_NAME_BYTES: u64 = 127;

/// Hard cap on the declared tensor count.
pub const GGUF_MAX_TENSORS: u64 = 1 << 20;

/// Hard cap on the declared metadata key/value count.
pub const GGUF_MAX_METADATA_KV: u64 = 1 << 16;

/// Largest tensor alignment a file may ask for.
const GGUF_MAX_ALIGNMENT: u64 = 4096;

/// Alignment used when `general.alignment` is absent.
const GGUF_DEFAULT_ALIGNMENT: u64 = 32;

/// Highest number of dimensions a GGUF tensor may declare.
const GGUF_MAX_DIMS: u32 = 4;

/// What a GGUF file says about itself.
///
/// Everything here comes from the header alone, so building one is cheap
/// enough to do for every file in the models directory on every scan.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GgufInfo {
    /// `general.architecture` — `qwen3`, `qwen3moe`, … The runtime
    /// dispatches on this and refuses what it does not implement.
    pub architecture: String,
    /// `general.name`, when the file carries one.
    pub name: Option<String>,
    /// Human label for the quantization, from `general.file_type`
    /// (`Q4_K_M`, `Q8_0`, …), or `unknown(<n>)` for a file type this
    /// binary does not know.
    pub quant_label: String,
    /// Sum over tensors of the product of their dimensions — the parameter
    /// count, computed rather than trusted (no GGUF key holds it reliably).
    pub parameter_count: u64,
    /// `<architecture>.context_length`, when present.
    pub context_length: Option<u64>,
    /// `<architecture>.expert_count` — present on mixture-of-experts
    /// models only, and the cheapest way to tell one from a dense file.
    pub expert_count: Option<u32>,
    /// Number of tensor descriptors in the header.
    pub tensor_count: u64,
    /// GGUF version: 2 or 3.
    pub version: u32,
}

/// Everything a GGUF header can be wrong about.
#[derive(Debug, thiserror::Error)]
pub enum GgufError {
    /// The file could not be opened or ended early. A truncated download
    /// lands here.
    #[error("could not read the GGUF header: {0}")]
    Io(#[from] std::io::Error),

    /// The first four bytes are not `GGUF`.
    #[error("not a GGUF file: the magic bytes are wrong")]
    BadMagic,

    /// A GGUF version this binary does not read (version 1, or something
    /// from the future).
    #[error("GGUF version {0} is not supported; pam reads versions 2 and 3")]
    UnsupportedVersion(u32),

    /// A declared length or count is past its hard cap — a corrupt or
    /// hostile header, caught before anything is allocated.
    #[error("GGUF {what} is {value}, over the {limit} pam accepts")]
    TooLarge {
        /// Which field overflowed its cap.
        what: &'static str,
        /// The value the header claimed.
        value: u64,
        /// The cap it broke.
        limit: u64,
    },

    /// The header is internally inconsistent: an unknown value type, an
    /// unaligned or overlapping tensor, a nonsense dimension count.
    #[error("malformed GGUF header: {0}")]
    Malformed(String),

    /// A key the rest of the model layer cannot work without is absent.
    #[error("GGUF header has no {0}")]
    MissingMetadata(&'static str),
}

/// The scalar metadata values this parser keeps. Arrays and the types no
/// consumer reads are walked past without being stored.
#[derive(Debug, Clone)]
enum Scalar {
    Unsigned(u64),
    Signed(i64),
    Text(String),
}

impl Scalar {
    /// The value as an unsigned integer, for the numeric keys.
    fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Unsigned(v) => Some(*v),
            Self::Signed(v) => u64::try_from(*v).ok(),
            Self::Text(_) => None,
        }
    }

    /// The value as text, for `general.architecture` and `general.name`.
    fn as_str(&self) -> Option<&str> {
        match self {
            Self::Text(v) => Some(v),
            _ => None,
        }
    }
}

/// A reader that counts what it has consumed and refuses to go past
/// [`GGUF_MAX_HEADER_BYTES`].
///
/// The budget is the parser's real defence: every individual cap can be
/// satisfied by a header that still asks for gigabytes in aggregate, and
/// this is what stops that.
struct HeaderReader<R> {
    inner: BufReader<R>,
    consumed: u64,
}

impl<R: Read + Seek> HeaderReader<R> {
    fn new(reader: R) -> Self {
        Self {
            inner: BufReader::new(reader),
            consumed: 0,
        }
    }

    /// Bytes still inside the header budget.
    fn remaining(&self) -> u64 {
        GGUF_MAX_HEADER_BYTES.saturating_sub(self.consumed)
    }

    /// Charges `bytes` to the budget, failing if that would exceed it.
    fn charge(&mut self, bytes: u64) -> Result<(), GgufError> {
        self.consumed = self.consumed.saturating_add(bytes);
        if self.consumed > GGUF_MAX_HEADER_BYTES {
            return Err(GgufError::TooLarge {
                what: "header size",
                value: self.consumed,
                limit: GGUF_MAX_HEADER_BYTES,
            });
        }
        Ok(())
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), GgufError> {
        self.charge(buf.len() as u64)?;
        self.inner.read_exact(buf)?;
        Ok(())
    }

    fn u8(&mut self) -> Result<u8, GgufError> {
        let mut buf = [0u8; 1];
        self.read_exact(&mut buf)?;
        Ok(buf[0])
    }

    fn u16(&mut self) -> Result<u16, GgufError> {
        let mut buf = [0u8; 2];
        self.read_exact(&mut buf)?;
        Ok(u16::from_le_bytes(buf))
    }

    fn u32(&mut self) -> Result<u32, GgufError> {
        let mut buf = [0u8; 4];
        self.read_exact(&mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    fn u64(&mut self) -> Result<u64, GgufError> {
        let mut buf = [0u8; 8];
        self.read_exact(&mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    /// Walks past `bytes` without reading them into memory.
    fn skip(&mut self, bytes: u64) -> Result<(), GgufError> {
        if bytes == 0 {
            return Ok(());
        }
        if bytes > self.remaining() {
            return Err(GgufError::TooLarge {
                what: "header size",
                value: self.consumed.saturating_add(bytes),
                limit: GGUF_MAX_HEADER_BYTES,
            });
        }
        self.charge(bytes)?;
        // `bytes` is inside the header budget, so it fits in an i64.
        self.inner
            .seek(SeekFrom::Current(i64::try_from(bytes).map_err(|_| {
                GgufError::Malformed(format!("cannot skip {bytes} bytes"))
            })?))?;
        Ok(())
    }

    /// Reads a length-prefixed string, refusing anything over `limit`
    /// before allocating. `what` names the field in the refusal.
    fn string(&mut self, limit: u64, what: &str) -> Result<String, GgufError> {
        let len = self.u64()?;
        if len > limit {
            return Err(GgufError::Malformed(format!(
                "{what} is {len} bytes, over the {limit} allowed"
            )));
        }
        if len > self.remaining() {
            return Err(GgufError::TooLarge {
                what: "header size",
                value: self.consumed.saturating_add(len),
                limit: GGUF_MAX_HEADER_BYTES,
            });
        }
        self.charge(len)?;
        let mut buf = vec![0u8; usize::try_from(len).unwrap_or(usize::MAX)];
        self.inner.read_exact(&mut buf)?;
        String::from_utf8(buf)
            .map_err(|_| GgufError::Malformed(format!("{what} is not valid UTF-8")))
    }

    /// Reads one metadata value, keeping it when it is a scalar this crate
    /// might read and walking past it otherwise.
    ///
    /// The value types are GGUF's own numbering, and the ones pam never
    /// looks at (floats, arrays) are skipped rather than decoded — the
    /// point of the walk is to arrive at the tensor descriptors.
    fn metadata_value(&mut self) -> Result<Option<Scalar>, GgufError> {
        match self.u32()? {
            // 0 is u8 and 7 is bool; both arrive as one byte and both are
            // only ever read as a number.
            0 | 7 => Ok(Some(Scalar::Unsigned(u64::from(self.u8()?)))),
            1 => Ok(Some(Scalar::Signed(i64::from(self.u8()?.cast_signed())))),
            2 => Ok(Some(Scalar::Unsigned(u64::from(self.u16()?)))),
            3 => Ok(Some(Scalar::Signed(i64::from(self.u16()?.cast_signed())))),
            4 => Ok(Some(Scalar::Unsigned(u64::from(self.u32()?)))),
            5 => Ok(Some(Scalar::Signed(i64::from(self.u32()?.cast_signed())))),
            6 => {
                self.skip(4)?;
                Ok(None)
            }
            8 => Ok(Some(Scalar::Text(
                self.string(GGUF_MAX_STRING_BYTES, "metadata string")?,
            ))),
            9 => {
                self.skip_array()?;
                Ok(None)
            }
            10 => Ok(Some(Scalar::Unsigned(self.u64()?))),
            11 => {
                let raw = self.u64()?;
                Ok(Some(Scalar::Signed(i64::from_le_bytes(raw.to_le_bytes()))))
            }
            12 => {
                self.skip(8)?;
                Ok(None)
            }
            other => Err(GgufError::Malformed(format!(
                "unknown metadata value type {other}"
            ))),
        }
    }

    /// Walks past an array value. Fixed-width elements are skipped in one
    /// seek; strings have to be walked one length prefix at a time.
    fn skip_array(&mut self) -> Result<(), GgufError> {
        let element_type = self.u32()?;
        let count = self.u64()?;

        // Every element costs at least this many bytes, so a count that
        // cannot fit the budget is refused before the walk starts.
        let min_element_bytes = match element_type {
            0 | 1 | 7 => 1,
            2 | 3 => 2,
            4..=6 => 4,
            // A string element is at least its own 8-byte length prefix.
            8 | 10..=12 => 8,
            9 => {
                return Err(GgufError::Malformed(
                    "nested metadata arrays are not supported".to_owned(),
                ));
            }
            other => {
                return Err(GgufError::Malformed(format!(
                    "unknown array element type {other}"
                )));
            }
        };
        let floor = count.saturating_mul(min_element_bytes);
        if floor > self.remaining() {
            return Err(GgufError::TooLarge {
                what: "header size",
                value: self.consumed.saturating_add(floor),
                limit: GGUF_MAX_HEADER_BYTES,
            });
        }

        if element_type == 8 {
            for _ in 0..count {
                let len = self.u64()?;
                if len > GGUF_MAX_STRING_BYTES {
                    return Err(GgufError::Malformed(format!(
                        "array string is {len} bytes, over the {GGUF_MAX_STRING_BYTES} allowed"
                    )));
                }
                self.skip(len)?;
            }
        } else {
            self.skip(floor)?;
        }
        Ok(())
    }
}

/// Elements per block and bytes per block for a ggml dtype.
///
/// Only the dtypes candle's quantized kernels cover; anything else is a
/// malformed header as far as pam is concerned, because pam could not run
/// it anyway.
fn ggml_block_layout(dtype: u32) -> Option<(u64, u64)> {
    let layout = match dtype {
        0 => (1, 4),      // F32
        1 | 30 => (1, 2), // F16, BF16
        2 => (32, 18),    // Q4_0
        3 => (32, 20),    // Q4_1
        6 => (32, 22),    // Q5_0
        7 => (32, 24),    // Q5_1
        8 => (32, 34),    // Q8_0
        9 => (32, 36),    // Q8_1
        10 => (256, 84),  // Q2_K
        11 => (256, 110), // Q3_K
        12 => (256, 144), // Q4_K
        13 => (256, 176), // Q5_K
        14 => (256, 210), // Q6_K
        15 => (256, 292), // Q8_K
        _ => return None,
    };
    Some(layout)
}

/// `llama.cpp`'s `LLAMA_FTYPE` table as a human label.
///
/// The values are a historical record, not a clean enum: 5 and 6 were
/// `Q4_2`/`Q4_3` and were removed, 33–35 were the Arm repacking types and were
/// removed too. An unknown value renders as `unknown(<n>)` rather than
/// guessing — a wrong quant label in the GUI is worse than an honest gap.
#[must_use]
pub fn quant_label_for(file_type: u32) -> String {
    let label = match file_type {
        0 => "F32",
        1 => "F16",
        2 => "Q4_0",
        3 => "Q4_1",
        4 => "Q4_1_SOME_F16",
        7 => "Q8_0",
        8 => "Q5_0",
        9 => "Q5_1",
        10 => "Q2_K",
        11 => "Q3_K_S",
        12 => "Q3_K_M",
        13 => "Q3_K_L",
        14 => "Q4_K_S",
        15 => "Q4_K_M",
        16 => "Q5_K_S",
        17 => "Q5_K_M",
        18 => "Q6_K",
        19 => "IQ2_XXS",
        20 => "IQ2_XS",
        21 => "Q2_K_S",
        22 => "IQ3_XS",
        23 => "IQ3_XXS",
        24 => "IQ1_S",
        25 => "IQ4_NL",
        26 => "IQ3_S",
        27 => "IQ3_M",
        28 => "IQ2_S",
        29 => "IQ2_M",
        30 => "IQ4_XS",
        31 => "IQ1_M",
        32 => "BF16",
        36 => "TQ1_0",
        37 => "TQ2_0",
        other => return format!("unknown({other})"),
    };
    label.to_owned()
}

/// Reads the header of the GGUF file at `path`.
///
/// Blocking: the caller decides whether that needs a `spawn_blocking`.
pub fn read_info(path: &Path) -> Result<GgufInfo, GgufError> {
    let file = std::fs::File::open(path)?;
    parse_info(file)
}

/// Parses a GGUF header from anything seekable.
///
/// Reading stops at the end of the tensor descriptors; the tensor data is
/// never touched.
pub fn parse_info<R: Read + Seek>(reader: R) -> Result<GgufInfo, GgufError> {
    let mut r = HeaderReader::new(reader);

    let mut magic = [0u8; 4];
    r.read_exact(&mut magic)?;
    if &magic != b"GGUF" {
        return Err(GgufError::BadMagic);
    }

    let version = r.u32()?;
    if !(2..=3).contains(&version) {
        return Err(GgufError::UnsupportedVersion(version));
    }

    let tensor_count = r.u64()?;
    if tensor_count > GGUF_MAX_TENSORS {
        return Err(GgufError::TooLarge {
            what: "tensor count",
            value: tensor_count,
            limit: GGUF_MAX_TENSORS,
        });
    }

    let kv_count = r.u64()?;
    if kv_count > GGUF_MAX_METADATA_KV {
        return Err(GgufError::TooLarge {
            what: "metadata KV count",
            value: kv_count,
            limit: GGUF_MAX_METADATA_KV,
        });
    }

    let metadata = read_metadata(&mut r, kv_count)?;

    let architecture = metadata
        .iter()
        .find(|(key, _)| key == "general.architecture")
        .and_then(|(_, value)| value.as_str())
        .ok_or(GgufError::MissingMetadata("general.architecture"))?
        .to_owned();

    let alignment = match lookup(&metadata, "general.alignment").and_then(Scalar::as_u64) {
        Some(value) => {
            if value == 0 || !value.is_power_of_two() || value > GGUF_MAX_ALIGNMENT {
                return Err(GgufError::Malformed(format!(
                    "general.alignment {value} is not a power of two at or below {GGUF_MAX_ALIGNMENT}"
                )));
            }
            value
        }
        None => GGUF_DEFAULT_ALIGNMENT,
    };

    let name = lookup(&metadata, "general.name")
        .and_then(Scalar::as_str)
        .map(ToOwned::to_owned);
    let quant_label = lookup(&metadata, "general.file_type")
        .and_then(Scalar::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .map_or_else(|| "unknown".to_owned(), quant_label_for);
    let context_length =
        lookup(&metadata, &format!("{architecture}.context_length")).and_then(Scalar::as_u64);
    let expert_count = lookup(&metadata, &format!("{architecture}.expert_count"))
        .and_then(Scalar::as_u64)
        .and_then(|value| u32::try_from(value).ok());

    let parameter_count = read_tensors(&mut r, tensor_count, alignment)?;

    Ok(GgufInfo {
        architecture,
        name,
        quant_label,
        parameter_count,
        context_length,
        expert_count,
        tensor_count,
        version,
    })
}

/// The metadata keys worth keeping. The architecture prefix is unknown
/// while the pairs stream past, so the suffix is what qualifies the
/// architecture-scoped keys; the architecture is applied afterwards.
fn is_interesting(key: &str) -> bool {
    matches!(
        key,
        "general.architecture" | "general.name" | "general.file_type" | "general.alignment"
    ) || key.ends_with(".context_length")
        || key.ends_with(".expert_count")
}

fn lookup<'a>(metadata: &'a [(String, Scalar)], key: &str) -> Option<&'a Scalar> {
    metadata
        .iter()
        .find(|(candidate, _)| candidate == key)
        .map(|(_, value)| value)
}

/// Streams the metadata pairs, keeping only what [`is_interesting`] admits.
fn read_metadata<R: Read + Seek>(
    r: &mut HeaderReader<R>,
    kv_count: u64,
) -> Result<Vec<(String, Scalar)>, GgufError> {
    let mut kept = Vec::new();
    for _ in 0..kv_count {
        let key = r.string(GGUF_MAX_STRING_BYTES, "metadata key")?;
        let value = r.metadata_value()?;
        if let Some(value) = value
            && is_interesting(&key)
        {
            kept.push((key, value));
        }
    }
    Ok(kept)
}

/// Streams the tensor descriptors, validating the layout and returning the
/// summed parameter count.
///
/// Offsets are checked as they arrive: each must sit on an `alignment`
/// boundary and must start at or after the end of the previous tensor. That
/// is both the "strictly increasing" and the "non-overlapping" rule, and it
/// is what a truncated or spliced file fails.
fn read_tensors<R: Read + Seek>(
    r: &mut HeaderReader<R>,
    tensor_count: u64,
    alignment: u64,
) -> Result<u64, GgufError> {
    let mut parameter_count: u64 = 0;
    let mut previous_end: u64 = 0;

    for _ in 0..tensor_count {
        let name = r.string(GGUF_MAX_TENSOR_NAME_BYTES, "tensor name")?;

        let n_dims = r.u32()?;
        if n_dims == 0 || n_dims > GGUF_MAX_DIMS {
            return Err(GgufError::Malformed(format!(
                "tensor {name} declares {n_dims} dimensions; GGUF allows 1 to {GGUF_MAX_DIMS}"
            )));
        }

        let mut elements: u64 = 1;
        for _ in 0..n_dims {
            let dim = r.u64()?;
            elements = elements.checked_mul(dim).ok_or_else(|| {
                GgufError::Malformed(format!("tensor {name} has an impossible element count"))
            })?;
        }

        let dtype = r.u32()?;
        let (block_elements, block_bytes) = ggml_block_layout(dtype).ok_or_else(|| {
            GgufError::Malformed(format!("tensor {name} uses unknown ggml dtype {dtype}"))
        })?;

        let offset = r.u64()?;
        if offset % alignment != 0 {
            return Err(GgufError::Malformed(format!(
                "tensor {name} starts at offset {offset}, which is not aligned to {alignment}"
            )));
        }
        if offset < previous_end {
            return Err(GgufError::Malformed(format!(
                "tensor {name} starts at offset {offset} and overlaps the tensor before it, \
                 which ends at {previous_end}"
            )));
        }

        let bytes = elements
            .div_ceil(block_elements)
            .checked_mul(block_bytes)
            .ok_or_else(|| {
                GgufError::Malformed(format!("tensor {name} has an impossible byte size"))
            })?;
        previous_end = offset.checked_add(bytes).ok_or_else(|| {
            GgufError::Malformed(format!("tensor {name} ends past the addressable range"))
        })?;

        parameter_count = parameter_count.checked_add(elements).ok_or_else(|| {
            GgufError::Malformed("the summed parameter count overflows".to_owned())
        })?;
    }

    Ok(parameter_count)
}
