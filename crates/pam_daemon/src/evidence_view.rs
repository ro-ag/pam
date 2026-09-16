//! Immutable byte views and conservative evidence provenance.
//!
//! Redact the complete bounded artifact before paging or model input. The fixed
//! detectors cover recognizable credential assignments, HTTP credential headers,
//! URL user information/token queries, sensitive JSON keys, and PEM blocks. This
//! is not a guarantee that arbitrary secrets or obfuscated credentials are found.
//! Unknown bytes (including invalid UTF-8) are preserved, not decoded lossily.
//! A byte view is not promised to remain a valid structured document: malformed
//! credential syntax is masked conservatively. Raw source and maps stay private.

use pam_compact::{Compacted, FragmentKind, MAX_SOURCE_BYTES, sha256_hex};
use serde::{Deserialize, Serialize};

/// Fixed detector policy; changing detection changes immutable view identity.
pub const POLICY_VERSION: &str = "pam-evidence-redact-v1";
/// Bounds map allocation independently of source size.
pub const MAX_SEGMENTS: usize = 100_000;
const MASK: &[u8] = b"[REDACTED]";
const JSON_MASK: &[u8] = b"\"[REDACTED]\"";

/// Half-open byte range in the named artifact, never a character index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByteRange {
    /// Inclusive byte offset.
    pub start: u64,
    /// Exclusive byte offset.
    pub end: u64,
}

/// Accuracy of the relation to a parent artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Relation {
    /// Unchanged bytes; substring offsets may be translated arithmetically.
    Identity,
    /// Replacement covers the entire parent range, never its secret content.
    Redacted,
    /// Normalized display refers to a whole source record, not exact substrings.
    CoveringRecord,
    /// Generated text has no source byte range (for example the status footer).
    Synthetic,
    /// Marker describes omitted parent bytes; it is not a quotation of them.
    Omitted,
}

/// One view-to-parent edge. The owning sidecar identifies the parent artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Segment {
    /// Range in the readable view.
    pub view: ByteRange,
    /// Corresponding range in the protected parent, when there is one.
    pub parent: Option<ByteRange>,
    /// Whether this is byte identity, coarse coverage or generated text.
    pub relation: Relation,
}

/// Whole-artifact result, suitable for immutable storage before range reads.
#[derive(Debug, Clone, Serialize)]
pub struct RedactedView {
    /// Exact view bytes; a reader must not silently replace invalid UTF-8.
    pub bytes: Vec<u8>,
    /// Contiguous view-to-source mapping.
    pub segments: Vec<Segment>,
    /// Detector policy responsible for this view.
    pub policy_version: &'static str,
    /// Digest of the protected original bytes.
    pub source_sha256: String,
    /// Digest of the returned bytes, after redaction.
    pub view_sha256: String,
    /// Exact original byte length.
    pub source_bytes: u64,
    /// Number of merged redaction ranges, not number of detected credentials.
    pub redactions: usize,
}

/// Refusals contain no offending content or credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ViewError {
    /// Source or rendered view exceeds the fixed byte ceiling.
    #[error("evidence view exceeds the 64 MiB byte ceiling")]
    TooLarge,
    /// Excessive fragmentation would allocate an unbounded map.
    #[error("evidence view exceeds the provenance segment ceiling")]
    TooManySegments,
    /// Stored parent digest does not identify the supplied bytes.
    #[error("evidence provenance parent digest or size does not match")]
    ParentMismatch,
    /// A stored map is malformed or the requested range is out of bounds.
    #[error("evidence provenance ranges or rendering are invalid")]
    InvalidMap,
}

#[derive(Clone, Copy)]
struct Hit {
    start: usize,
    end: usize,
    replacement: &'static [u8],
}

/// Redact one complete bounded artifact. Never redact independently per page.
pub fn redact(bytes: &[u8]) -> Result<RedactedView, ViewError> {
    bounded(bytes.len())?;
    let mut hits = Vec::new();
    detect_pem(bytes, &mut hits)?;
    detect_json(bytes, &mut hits)?;
    detect_assignments(bytes, &mut hits)?;
    detect_urls(bytes, &mut hits)?;
    hits.sort_unstable_by_key(|hit| (hit.start, std::cmp::Reverse(hit.end)));
    let mut merged: Vec<Hit> = Vec::new();
    for hit in hits {
        if let Some(previous) = merged.last_mut().filter(|last| hit.start <= last.end) {
            previous.end = previous.end.max(hit.end);
        } else {
            merged.push(hit);
        }
    }
    let mut output = Vec::new();
    let mut segments = Vec::new();
    let mut cursor = 0;
    for hit in &merged {
        append(
            &mut output,
            &mut segments,
            &bytes[cursor..hit.start],
            Some(range(cursor, hit.start)),
            Relation::Identity,
        )?;
        append(
            &mut output,
            &mut segments,
            hit.replacement,
            Some(range(hit.start, hit.end)),
            Relation::Redacted,
        )?;
        cursor = hit.end;
    }
    append(
        &mut output,
        &mut segments,
        &bytes[cursor..],
        Some(range(cursor, bytes.len())),
        Relation::Identity,
    )?;
    Ok(RedactedView {
        source_sha256: sha256_hex(bytes),
        view_sha256: sha256_hex(&output),
        source_bytes: bytes.len() as u64,
        bytes: output,
        segments,
        policy_version: POLICY_VERSION,
        redactions: merged.len(),
    })
}

fn bounded(length: usize) -> Result<(), ViewError> {
    if length > MAX_SOURCE_BYTES {
        Err(ViewError::TooLarge)
    } else {
        Ok(())
    }
}

fn range(start: usize, end: usize) -> ByteRange {
    ByteRange {
        start: start as u64,
        end: end as u64,
    }
}

fn hit(
    hits: &mut Vec<Hit>,
    start: usize,
    end: usize,
    replacement: &'static [u8],
) -> Result<(), ViewError> {
    if start == end {
        return Ok(());
    }
    if hits.len() >= MAX_SEGMENTS / 2 {
        return Err(ViewError::TooManySegments);
    }
    hits.push(Hit {
        start,
        end,
        replacement,
    });
    Ok(())
}

fn append(
    output: &mut Vec<u8>,
    segments: &mut Vec<Segment>,
    text: &[u8],
    parent: Option<ByteRange>,
    relation: Relation,
) -> Result<(), ViewError> {
    if text.is_empty() {
        return Ok(());
    }
    bounded(
        output
            .len()
            .checked_add(text.len())
            .ok_or(ViewError::TooLarge)?,
    )?;
    if segments.len() >= MAX_SEGMENTS {
        return Err(ViewError::TooManySegments);
    }
    let start = output.len();
    output.extend_from_slice(text);
    segments.push(Segment {
        view: range(start, output.len()),
        parent,
        relation,
    });
    Ok(())
}

fn find(bytes: &[u8], needle: &[u8]) -> Option<usize> {
    bytes.windows(needle.len()).position(|part| part == needle)
}

fn detect_pem(bytes: &[u8], hits: &mut Vec<Hit>) -> Result<(), ViewError> {
    let mut cursor = 0;
    while let Some(relative) = find(&bytes[cursor..], b"-----BEGIN ") {
        let start = cursor + relative;
        let label_start = start + 11;
        let limit = (label_start + 128).min(bytes.len());
        let Some(label_len) = find(&bytes[label_start..limit], b"-----") else {
            hit(hits, start, bytes.len(), MASK)?;
            break;
        };
        let label = &bytes[label_start..label_start + label_len];
        if label.is_empty()
            || !label
                .iter()
                .all(|b| b.is_ascii_uppercase() || *b == b' ' || *b == b'-' || b.is_ascii_digit())
        {
            cursor = label_start;
            continue;
        }
        let mut end_marker = b"-----END ".to_vec();
        end_marker.extend_from_slice(label);
        end_marker.extend_from_slice(b"-----");
        let body = label_start + label_len + 5;
        let end = find(&bytes[body..], &end_marker)
            .map_or(bytes.len(), |offset| body + offset + end_marker.len());
        hit(hits, start, end, MASK)?;
        cursor = end;
    }
    Ok(())
}

fn sensitive(name: &[u8]) -> bool {
    if name.len() > 1024 {
        return false;
    }
    let key = normalized_key(name);
    [
        b"password".as_slice(),
        b"passwd",
        b"secret",
        b"credential",
        b"apikey",
        b"privatekey",
    ]
    .iter()
    .any(|word| find(&key, word).is_some())
        || key.ends_with(b"token")
        || [
            b"authorization".as_slice(),
            b"proxyauthorization",
            b"cookie",
            b"setcookie",
            b"pwd",
            b"accesskey",
            b"accesskeyid",
            b"signingkey",
        ]
        .contains(&key.as_slice())
}

fn escape_end(bytes: &[u8], start: usize) -> usize {
    let mut cursor = (start + 2).min(bytes.len());
    match bytes.get(start + 1) {
        Some(b'[') => {
            while cursor < bytes.len() {
                let last = (0x40..=0x7e).contains(&bytes[cursor]);
                cursor += 1;
                if last {
                    break;
                }
            }
        }
        Some(b']') => {
            while cursor < bytes.len() {
                if bytes[cursor] == 7 {
                    return cursor + 1;
                }
                if bytes[cursor..].starts_with(b"\x1b\\") {
                    return cursor + 2;
                }
                cursor += 1;
            }
        }
        _ => {}
    }
    cursor
}

fn normalized_key(name: &[u8]) -> Vec<u8> {
    let mut key = Vec::new();
    let mut cursor = 0;
    while cursor < name.len() {
        if name[cursor] == 0x1b {
            cursor = escape_end(name, cursor);
        } else {
            if name[cursor].is_ascii_alphanumeric() {
                key.push(name[cursor].to_ascii_lowercase());
            }
            cursor += 1;
        }
    }
    key
}

fn white(bytes: &[u8], mut cursor: usize) -> usize {
    while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
        cursor += 1;
    }
    cursor
}

fn quoted_end(bytes: &[u8], start: usize) -> Option<usize> {
    let quote = bytes[start];
    let mut cursor = start + 1;
    while cursor < bytes.len() {
        if bytes[cursor] == b'\\' {
            cursor = (cursor + 2).min(bytes.len());
        } else if bytes[cursor] == quote {
            return Some(cursor + 1);
        } else {
            cursor += 1;
        }
    }
    None
}

fn json_value_end(bytes: &[u8], start: usize) -> usize {
    let mut depth = 0_usize;
    let mut cursor = start;
    while cursor < bytes.len() {
        match bytes[cursor] {
            b'"' => cursor = quoted_end(bytes, cursor).unwrap_or(bytes.len()),
            b'{' | b'[' => {
                depth += 1;
                cursor += 1;
            }
            b'}' | b']' | b',' if depth == 0 => break,
            b'}' | b']' => {
                depth -= 1;
                cursor += 1;
                if depth == 0 {
                    break;
                }
            }
            byte if byte.is_ascii_whitespace() && depth == 0 => break,
            _ => cursor += 1,
        }
    }
    cursor
}

fn detect_json(bytes: &[u8], hits: &mut Vec<Hit>) -> Result<(), ViewError> {
    let mut cursor = 0;
    while cursor < bytes.len() {
        if bytes[cursor] != b'"' {
            cursor += 1;
            continue;
        }
        let Some(end) = quoted_end(bytes, cursor) else {
            break;
        };
        let separator = white(bytes, end);
        let key = if end - cursor <= 1024 {
            serde_json::from_slice::<String>(&bytes[cursor..end]).ok()
        } else {
            None
        };
        if bytes.get(separator) == Some(&b':') && key.is_some_and(|key| sensitive(key.as_bytes())) {
            let start = white(bytes, separator + 1);
            if bytes.get(start) == Some(&b'"') {
                let closing = quoted_end(bytes, start);
                let end = closing.unwrap_or(bytes.len());
                let content_end = closing.map_or(end, |end| end - 1);
                hit(hits, start + 1, content_end, MASK)?;
                cursor = end;
            } else {
                let end = json_value_end(bytes, start);
                hit(hits, start, end, JSON_MASK)?;
                cursor = end;
            }
        } else {
            cursor = end;
        }
    }
    Ok(())
}

fn word(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')
}

fn detect_assignments(bytes: &[u8], hits: &mut Vec<Hit>) -> Result<(), ViewError> {
    let mut cursor = 0;
    while cursor < bytes.len() {
        if !word(bytes[cursor]) {
            cursor += 1;
            continue;
        }
        let start = cursor;
        while cursor < bytes.len() {
            if word(bytes[cursor]) {
                cursor += 1;
            } else if bytes[cursor] == 0x1b {
                cursor = escape_end(bytes, cursor);
            } else {
                break;
            }
        }
        let key = &bytes[start..cursor];
        let after_key = if matches!(bytes.get(cursor), Some(b'"' | b'\'')) {
            cursor + 1
        } else {
            cursor
        };
        let separator = white(bytes, after_key);
        if !sensitive(key) || !matches!(bytes.get(separator), Some(b'=' | b':')) {
            continue;
        }
        let value_start = white(bytes, separator + 1);
        if value_start == bytes.len() {
            continue;
        }
        let header = [
            b"authorization".as_slice(),
            b"proxyauthorization",
            b"cookie",
            b"setcookie",
        ]
        .contains(&normalized_key(key).as_slice());
        if header && bytes[separator] == b':' && !matches!(bytes[value_start], b'"' | b'\'') {
            let mut end = value_start;
            loop {
                while end < bytes.len() && !matches!(bytes[end], b'\r' | b'\n') {
                    end += 1;
                }
                let mut next = end;
                if bytes.get(next) == Some(&b'\r') {
                    next += 1;
                }
                if bytes.get(next) == Some(&b'\n') {
                    next += 1;
                }
                if matches!(bytes.get(next), Some(b' ' | b'\t')) {
                    end = next + 1;
                } else {
                    break;
                }
            }
            hit(hits, value_start, end, MASK)?;
            cursor = end;
        } else if matches!(bytes[value_start], b'"' | b'\'') {
            let closing = quoted_end(bytes, value_start);
            let end = closing.unwrap_or(bytes.len());
            let content_end = closing.map_or(end, |end| end - 1);
            hit(hits, value_start + 1, content_end, MASK)?;
            cursor = end;
        } else {
            let mut end = value_start;
            while end < bytes.len()
                && !bytes[end].is_ascii_whitespace()
                && !matches!(bytes[end], b'&' | b';' | b',' | b'"' | b'\'' | b'<' | b'>')
            {
                end += 1;
            }
            hit(hits, value_start, end, MASK)?;
            cursor = end;
        }
    }
    Ok(())
}

fn decode_query_key(bytes: &[u8]) -> Vec<u8> {
    let mut decoded = Vec::new();
    let mut cursor = 0;
    while cursor < bytes.len() {
        if bytes[cursor] == b'%' && cursor + 2 < bytes.len() {
            let hex = |b: u8| {
                char::from(b)
                    .to_digit(16)
                    .and_then(|v| u8::try_from(v).ok())
            };
            if let (Some(a), Some(b)) = (hex(bytes[cursor + 1]), hex(bytes[cursor + 2])) {
                decoded.push(a * 16 + b);
                cursor += 3;
                continue;
            }
        }
        decoded.push(bytes[cursor]);
        cursor += 1;
    }
    decoded
}

fn detect_urls(bytes: &[u8], hits: &mut Vec<Hit>) -> Result<(), ViewError> {
    let mut cursor = 0;
    while cursor < bytes.len() {
        if bytes[cursor..].starts_with(b"://") {
            let start = cursor + 3;
            let mut end = start;
            while end < bytes.len()
                && !bytes[end].is_ascii_whitespace()
                && !matches!(bytes[end], b'/' | b'?' | b'#' | b'"' | b'\'')
            {
                end += 1;
            }
            if let Some(at) = bytes[start..end].iter().rposition(|b| *b == b'@') {
                hit(hits, start, start + at, MASK)?;
            }
            cursor = end;
        } else if matches!(bytes[cursor], b'?' | b'&') {
            let start = cursor + 1;
            let mut end = start;
            while end < bytes.len()
                && end - start <= 1024
                && !bytes[end].is_ascii_whitespace()
                && !matches!(bytes[end], b'=' | b'&' | b'#' | b'"' | b'\'')
            {
                end += 1;
            }
            if bytes.get(end) == Some(&b'=') && sensitive(&decode_query_key(&bytes[start..end])) {
                let value_start = end + 1;
                end = value_start;
                while end < bytes.len()
                    && !bytes[end].is_ascii_whitespace()
                    && !matches!(bytes[end], b'&' | b'#' | b'"' | b'\'')
                {
                    end += 1;
                }
                hit(hits, value_start, end, MASK)?;
            }
            cursor = end.max(cursor + 1);
        } else {
            cursor += 1;
        }
    }
    Ok(())
}

/// Map a compact rendering to complete records in its actual source. Source may
/// already be a redacted view; the caller retains the separate edge to raw bytes.
/// Display normalization prevents claiming byte identity within retained records.
pub fn compact_segments(report: &Compacted, source: &[u8]) -> Result<Vec<Segment>, ViewError> {
    bounded(source.len())?;
    bounded(report.rendered_text.len())?;
    if report.source_bytes != source.len() as u64 || report.source_sha256 != sha256_hex(source) {
        return Err(ViewError::ParentMismatch);
    }
    if report.algorithm_version != pam_compact::ALGORITHM_VERSION
        || report.fragments.len() > MAX_SEGMENTS
    {
        return Err(ViewError::InvalidMap);
    }
    let mut output = Vec::new();
    let mut segments = Vec::new();
    let mut source_end = 0;
    for fragment in &report.fragments {
        let end = fragment
            .offset
            .checked_add(fragment.length)
            .ok_or(ViewError::InvalidMap)?;
        if fragment.offset != source_end || end > report.source_bytes || fragment.length == 0 {
            return Err(ViewError::InvalidMap);
        }
        let relation = match fragment.kind {
            FragmentKind::Retained { .. } => Relation::CoveringRecord,
            FragmentKind::Omitted { .. } => Relation::Omitted,
        };
        append(
            &mut output,
            &mut segments,
            fragment.rendered.as_bytes(),
            Some(ByteRange {
                start: fragment.offset,
                end,
            }),
            relation,
        )?;
        source_end = end;
    }
    if source_end != report.source_bytes {
        return Err(ViewError::InvalidMap);
    }
    if source.is_empty() {
        append(
            &mut output,
            &mut segments,
            b"[no log output]\n",
            None,
            Relation::Synthetic,
        )?;
    }
    let footer = report.exit_status.map_or_else(
        || "[exit status: unknown]\n".to_owned(),
        |status| format!("[exit status: {status}]\n"),
    );
    append(
        &mut output,
        &mut segments,
        footer.as_bytes(),
        None,
        Relation::Synthetic,
    )?;
    if output != report.rendered_text.as_bytes() {
        return Err(ViewError::InvalidMap);
    }
    Ok(segments)
}

/// Resolve a view range through one map edge. Only identity segments translate
/// subranges by arithmetic. Other relations return whole covering parent ranges.
pub fn resolve(segments: &[Segment], requested: ByteRange) -> Result<Vec<Segment>, ViewError> {
    let end = validate_segments(segments)?;
    if requested.start > requested.end || requested.end > end {
        return Err(ViewError::InvalidMap);
    }
    Ok(resolve_validated(segments, requested))
}

fn validate_segments(segments: &[Segment]) -> Result<u64, ViewError> {
    if segments.len() > MAX_SEGMENTS {
        return Err(ViewError::TooManySegments);
    }
    let mut end = 0;
    for segment in segments {
        if segment.view.start != end
            || segment.view.start >= segment.view.end
            || segment.view.end > MAX_SOURCE_BYTES as u64
        {
            return Err(ViewError::InvalidMap);
        }
        if let Some(parent) = segment.parent {
            if segment.relation == Relation::Synthetic
                || parent.start >= parent.end
                || parent.end > MAX_SOURCE_BYTES as u64
                || (segment.relation == Relation::Identity
                    && parent.end - parent.start != segment.view.end - segment.view.start)
            {
                return Err(ViewError::InvalidMap);
            }
        } else if segment.relation != Relation::Synthetic {
            return Err(ViewError::InvalidMap);
        }
        end = segment.view.end;
    }
    Ok(end)
}

fn resolve_validated(segments: &[Segment], requested: ByteRange) -> Vec<Segment> {
    if requested.start == requested.end {
        return Vec::new();
    }
    let first = segments.partition_point(|segment| segment.view.end <= requested.start);
    segments[first..]
        .iter()
        .take_while(|segment| segment.view.start < requested.end)
        .map(|segment| {
            let start = requested.start.max(segment.view.start);
            let stop = requested.end.min(segment.view.end);
            let parent = if segment.relation == Relation::Identity {
                segment.parent.map(|parent| ByteRange {
                    start: parent.start + start - segment.view.start,
                    end: parent.start + stop - segment.view.start,
                })
            } else {
                segment.parent
            };
            Segment {
                view: ByteRange { start, end: stop },
                parent,
                relation: segment.relation,
            }
        })
        .collect()
}

/// Compose view→intermediate and intermediate→source edges. Identity may split
/// at parent boundaries. A coarse child keeps its whole view range and maps to
/// the covering hull of source ranges; it never acquires byte-exact authority.
pub fn compose_segments(child: &[Segment], parent: &[Segment]) -> Result<Vec<Segment>, ViewError> {
    validate_segments(child)?;
    let parent_end = validate_segments(parent)?;
    let mut result = Vec::new();
    let mut visited = 0_usize;
    for segment in child {
        let Some(input) = segment.parent else {
            result.push(segment.clone());
            continue;
        };
        if input.end > parent_end {
            return Err(ViewError::InvalidMap);
        }
        let mapped = resolve_validated(parent, input);
        visited = visited.saturating_add(mapped.len());
        if visited > MAX_SEGMENTS {
            return Err(ViewError::TooManySegments);
        }
        if segment.relation == Relation::Identity {
            for part in mapped {
                result.push(Segment {
                    view: ByteRange {
                        start: segment.view.start + part.view.start - input.start,
                        end: segment.view.start + part.view.end - input.start,
                    },
                    parent: part.parent,
                    relation: part.relation,
                });
            }
        } else {
            let mut hull: Option<ByteRange> = None;
            let mut relation = segment.relation;
            for part in mapped {
                if part.relation == Relation::Redacted && relation != Relation::Omitted {
                    relation = Relation::Redacted;
                }
                if let Some(range) = part.parent {
                    hull = Some(hull.map_or(range, |old| ByteRange {
                        start: old.start.min(range.start),
                        end: old.end.max(range.end),
                    }));
                }
            }
            result.push(Segment {
                view: segment.view,
                parent: hull,
                relation: if hull.is_some() {
                    relation
                } else {
                    Relation::Synthetic
                },
            });
        }
        if result.len() > MAX_SEGMENTS {
            return Err(ViewError::TooManySegments);
        }
    }
    resolve(&result, ByteRange { start: 0, end: 0 })?;
    Ok(result)
}

/// Sanitize a structured response without reparsing a possibly malformed byte
/// view. Object keys and value types survive except sensitive-key values, which
/// become a fixed marker. String contents receive the same detector policy.
pub fn redact_json(value: &serde_json::Value) -> Result<serde_json::Value, ViewError> {
    let mut visited = 0;
    let mut bytes = 0;
    let safe = redact_json_inner(value, 0, &mut visited, &mut bytes)?;
    // Count escaped JSON bytes without allocating a serialized copy.
    let mut counter = JsonCounter(0);
    serde_json::to_writer(&mut counter, &safe).map_err(|_| ViewError::TooLarge)?;
    Ok(safe)
}

struct JsonCounter(usize);

impl std::io::Write for JsonCounter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self.0.saturating_add(bytes.len());
        if self.0 > MAX_SOURCE_BYTES {
            return Err(std::io::Error::other("evidence JSON exceeds byte ceiling"));
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn charge_json(bytes: &mut usize, amount: usize) -> Result<(), ViewError> {
    *bytes = bytes.saturating_add(amount);
    bounded(*bytes)
}

fn redact_json_inner(
    value: &serde_json::Value,
    depth: usize,
    visited: &mut usize,
    bytes: &mut usize,
) -> Result<serde_json::Value, ViewError> {
    use serde_json::Value;
    *visited += 1;
    if depth > 64 || *visited > MAX_SEGMENTS {
        return Err(ViewError::TooManySegments);
    }
    charge_json(bytes, 8)?;
    Ok(match value {
        Value::String(text) => {
            charge_json(bytes, text.len())?;
            let view = redact(text.as_bytes())?;
            Value::String(String::from_utf8(view.bytes).map_err(|_| ViewError::InvalidMap)?)
        }
        Value::Array(values) => {
            let mut output = Vec::new();
            for child in values {
                output.push(redact_json_inner(child, depth + 1, visited, bytes)?);
            }
            Value::Array(output)
        }
        Value::Object(values) => {
            let mut output = serde_json::Map::new();
            for (key, child) in values {
                charge_json(bytes, key.len())?;
                let child = if sensitive(key.as_bytes()) {
                    Value::String("[REDACTED]".to_owned())
                } else {
                    redact_json_inner(child, depth + 1, visited, bytes)?
                };
                output.insert(key.clone(), child);
            }
            Value::Object(output)
        }
        other => other.clone(),
    })
}
