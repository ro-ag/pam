use std::{fmt::Write as _, ops::Range};

pub const MAX_AUDIT_DETAIL_INPUT_BYTES: usize = 1024 * 1024;
pub const MAX_AUDIT_DETAIL_OUTPUT_BYTES: usize = 16 * 1024;
pub const REDACTION_MARKER: &str = "[REDACTED]";
pub const TRUNCATION_MARKER: &str = "[TRUNCATED]";

/// Redacts secret-shaped audit detail and renders it as terminal-safe UTF-8.
///
/// Processing is deterministic and bounded. At most
/// [`MAX_AUDIT_DETAIL_INPUT_BYTES`] are inspected, and the returned string never
/// exceeds [`MAX_AUDIT_DETAIL_OUTPUT_BYTES`]. Invalid UTF-8 is replaced, secret
/// ranges are conservatively collapsed to [`REDACTION_MARKER`], terminal control
/// characters are escaped, and any bounded prefix ends with
/// [`TRUNCATION_MARKER`].
#[must_use]
pub fn redact_audit_detail(input: &[u8]) -> String {
    let inspected_length = input.len().min(MAX_AUDIT_DETAIL_INPUT_BYTES);
    let input_was_truncated = inspected_length < input.len();
    let source = String::from_utf8_lossy(&input[..inspected_length]);
    let mut ranges = RedactionRanges::default();

    mark_sensitive_headers(&source, &mut ranges);
    mark_authentication_schemes(&source, &mut ranges);
    mark_url_userinfo(&source, &mut ranges);
    mark_query_secrets(&source, &mut ranges);
    mark_json_secrets(&source, &mut ranges);
    mark_environment_secrets(&source, &mut ranges);
    mark_private_keys(&source, &mut ranges);
    mark_jwts(&source, &mut ranges);
    if input_was_truncated {
        ranges.add(&source, partial_tail_start(&source), source.len());
    }

    let redacted = ranges.render(&source);
    let sanitized = sanitize_terminal_text(&redacted);
    bound_output(&sanitized, input_was_truncated)
}

#[derive(Default)]
struct RedactionRanges(Vec<Range<usize>>);

impl RedactionRanges {
    fn add(&mut self, source: &str, mut start: usize, mut end: usize) {
        start = start.min(source.len());
        end = end.min(source.len());
        while start > 0 && !source.is_char_boundary(start) {
            start -= 1;
        }
        while end < source.len() && !source.is_char_boundary(end) {
            end += 1;
        }
        if start < end {
            self.0.push(start..end);
        }
    }

    fn render(mut self, source: &str) -> String {
        self.0.sort_unstable_by_key(|range| range.start);
        let mut merged: Vec<Range<usize>> = Vec::with_capacity(self.0.len());
        for range in self.0 {
            if let Some(previous) = merged.last_mut()
                && range.start <= previous.end
            {
                previous.end = previous.end.max(range.end);
                continue;
            }
            merged.push(range);
        }

        let mut output = String::with_capacity(source.len().min(MAX_AUDIT_DETAIL_OUTPUT_BYTES));
        let mut cursor = 0;
        for range in merged {
            output.push_str(&source[cursor..range.start]);
            output.push_str(REDACTION_MARKER);
            cursor = range.end;
        }
        output.push_str(&source[cursor..]);
        output
    }
}

fn mark_sensitive_headers(source: &str, ranges: &mut RedactionRanges) {
    let bytes = source.as_bytes();
    let lines = line_ranges(bytes);
    for (index, line) in lines.iter().enumerate() {
        let mut cursor = skip_ascii_space(bytes, line.start, line.end);
        let key_start = cursor;
        while cursor < line.end && is_key_byte(bytes[cursor]) {
            cursor += 1;
        }
        let key_end = cursor;
        cursor = skip_ascii_space(bytes, cursor, line.end);
        if cursor >= line.end || bytes[cursor] != b':' {
            continue;
        }
        let Some(key) = normalized_key(&bytes[key_start..key_end]) else {
            continue;
        };
        if !matches!(
            key.as_str(),
            "authorization" | "proxyauthorization" | "cookie" | "setcookie"
        ) {
            continue;
        }
        let value_start = skip_ascii_space(bytes, cursor + 1, line.end);
        let has_continuation = lines
            .get(index + 1)
            .is_some_and(|continuation| is_folded_header_line(bytes, continuation));
        let has_ambiguous_value = sensitive_header_value_is_ambiguous(
            &key,
            trim_ascii_space(&bytes[value_start..line.end]),
        );
        let value_end = if has_continuation || (has_ambiguous_value && line.end < source.len()) {
            // Obsolete folding and incomplete header values are ambiguous in
            // untrusted audit detail. Consume the remaining tail rather than
            // risk treating attacker-controlled continuation bytes as a new
            // field or an unindented line.
            source.len()
        } else {
            line.end
        };
        // Remove the field name with its value. Besides being conservative,
        // this prevents a terminal-sanitized line break from making a second
        // pass reinterpret the remainder as part of the same header value.
        ranges.add(source, key_start, value_end);
        if value_end == source.len() {
            return;
        }
    }
}

fn is_folded_header_line(bytes: &[u8], line: &Range<usize>) -> bool {
    line.start < line.end && matches!(bytes[line.start], b' ' | b'\t')
}

fn sensitive_header_value_is_ambiguous(key: &str, value: &[u8]) -> bool {
    if value.is_empty() {
        return true;
    }
    if matches!(key, "authorization" | "proxyauthorization") {
        let Some(separator) = value.iter().position(u8::is_ascii_whitespace) else {
            return true;
        };
        return trim_ascii_space(&value[separator..]).is_empty();
    }

    let mut saw_cookie_pair = false;
    for segment in value.split(|byte| *byte == b';') {
        let segment = trim_ascii_space(segment);
        if segment.is_empty() {
            return true;
        }
        if let Some(equals) = segment.iter().position(|byte| *byte == b'=') {
            if trim_ascii_space(&segment[equals + 1..]).is_empty() {
                return true;
            }
            saw_cookie_pair = true;
        } else if !saw_cookie_pair {
            return true;
        }
    }
    !saw_cookie_pair
}

fn mark_authentication_schemes(source: &str, ranges: &mut RedactionRanges) {
    let bytes = source.as_bytes();
    let mut cursor = 0;
    while cursor < bytes.len() {
        let scheme_length = [b"bearer".as_slice(), b"basic".as_slice()]
            .into_iter()
            .find(|scheme| {
                ascii_case_eq_at(bytes, cursor, scheme)
                    && has_word_boundary_before(bytes, cursor)
                    && bytes
                        .get(cursor + scheme.len())
                        .is_some_and(u8::is_ascii_whitespace)
            })
            .map_or(0, <[u8]>::len);
        if scheme_length == 0 {
            cursor += 1;
            continue;
        }

        let token_start = skip_ascii_space(bytes, cursor + scheme_length, bytes.len());
        let token_end = scan_credential_end(bytes, token_start);
        if token_end.saturating_sub(token_start) >= 4 {
            ranges.add(source, token_start, token_end);
        }
        cursor = token_end.max(cursor + 1);
    }
}

fn mark_url_userinfo(source: &str, ranges: &mut RedactionRanges) {
    let bytes = source.as_bytes();
    let mut cursor = 0;
    while let Some(separator) = find_exact(bytes, cursor, b"://") {
        let userinfo_start = separator + 3;
        let mut end = userinfo_start;
        while end < bytes.len() {
            match bytes[end] {
                b'@' => {
                    ranges.add(source, userinfo_start, end);
                    break;
                }
                b'/' | b'?' | b'#' | b'\\' | b'\'' | b'"' => break,
                byte if byte.is_ascii_whitespace() || byte.is_ascii_control() => break,
                _ => end += 1,
            }
        }
        cursor = end.saturating_add(1).max(separator + 3);
    }
}

fn mark_query_secrets(source: &str, ranges: &mut RedactionRanges) {
    let bytes = source.as_bytes();
    let mut cursor = 0;
    while cursor < bytes.len() {
        if !matches!(bytes[cursor], b'?' | b'&' | b';') {
            cursor += 1;
            continue;
        }
        let key_start = cursor + 1;
        let mut key_end = key_start;
        while key_end < bytes.len() && is_encoded_key_byte(bytes[key_end]) {
            key_end += 1;
        }
        let Some(key) = normalized_key(&bytes[key_start..key_end]) else {
            cursor += 1;
            continue;
        };
        let equals = skip_ascii_space(bytes, key_end, bytes.len());
        if equals >= bytes.len() || bytes[equals] != b'=' || !is_sensitive_key(&key, true) {
            cursor += 1;
            continue;
        }
        let value_start = skip_ascii_space(bytes, equals + 1, bytes.len());
        let value_end = scan_query_value_end(bytes, value_start);
        ranges.add(source, value_start, value_end);
        cursor = value_end.max(cursor + 1);
    }
}

fn mark_json_secrets(source: &str, ranges: &mut RedactionRanges) {
    let bytes = source.as_bytes();
    let mut cursor = 0;
    while cursor < bytes.len() {
        if bytes[cursor] != b'"' {
            cursor += 1;
            continue;
        }
        let Some(key_end_quote) = closing_quote(bytes, cursor, b'"') else {
            break;
        };
        let Some(key) = normalized_key(&bytes[cursor + 1..key_end_quote]) else {
            cursor = key_end_quote + 1;
            continue;
        };
        let colon = skip_json_whitespace(bytes, key_end_quote + 1, bytes.len());
        if colon >= bytes.len() || bytes[colon] != b':' || !is_sensitive_key(&key, false) {
            cursor = key_end_quote + 1;
            continue;
        }
        let value_start = skip_json_whitespace(bytes, colon + 1, bytes.len());
        let value_end = json_value_end(bytes, value_start);
        ranges.add(source, value_start, value_end);
        cursor = value_end.max(key_end_quote + 1);
    }
}

fn mark_environment_secrets(source: &str, ranges: &mut RedactionRanges) {
    let bytes = source.as_bytes();
    for line in line_ranges(bytes) {
        let mut cursor = line.start;
        while cursor < line.end {
            if !is_environment_key_start(bytes, cursor, line.start) {
                cursor += 1;
                continue;
            }
            let key_start = cursor;
            while cursor < line.end && is_key_byte(bytes[cursor]) {
                cursor += 1;
            }
            let key_end = cursor;
            let equals = skip_ascii_space(bytes, key_end, line.end);
            let Some(key) = normalized_key(&bytes[key_start..key_end]) else {
                continue;
            };
            if equals >= line.end || bytes[equals] != b'=' || !is_sensitive_key(&key, false) {
                continue;
            }
            let value_start = skip_ascii_space(bytes, equals + 1, line.end);
            let value_end = scan_environment_value_end(bytes, value_start, line.end);
            ranges.add(source, value_start, value_end);
            cursor = value_end.max(cursor + 1);
        }
    }
}

fn mark_private_keys(source: &str, ranges: &mut RedactionRanges) {
    let bytes = source.as_bytes();
    let mut cursor = 0;
    while let Some(begin) = find_ascii_case_insensitive(bytes, cursor, b"-----BEGIN ") {
        let header_end = scan_line_end(bytes, begin);
        if find_ascii_case_insensitive_in(bytes, begin, header_end, b"PRIVATE KEY-----").is_none() {
            cursor = header_end.max(begin + 1);
            continue;
        }

        let end = find_ascii_case_insensitive(bytes, header_end, b"-----END ")
            .and_then(|candidate| {
                let candidate_end = scan_line_end(bytes, candidate);
                find_ascii_case_insensitive_in(bytes, candidate, candidate_end, b"PRIVATE KEY-----")
                    .map(|_| candidate_end)
            })
            .unwrap_or(bytes.len());
        ranges.add(source, begin, end);
        cursor = end.max(begin + 1);
    }
}

fn mark_jwts(source: &str, ranges: &mut RedactionRanges) {
    let bytes = source.as_bytes();
    let mut cursor = 0;
    while cursor < bytes.len() {
        if !is_jwt_byte(bytes[cursor]) || bytes[cursor] == b'.' {
            cursor += 1;
            continue;
        }
        let start = cursor;
        while cursor < bytes.len() && is_jwt_byte(bytes[cursor]) {
            cursor += 1;
        }
        if jwt_segment_lengths(&bytes[start..cursor])
            .is_some_and(|lengths| lengths[0] >= 8 && lengths[1] >= 8 && lengths[2] >= 8)
        {
            ranges.add(source, start, cursor);
        }
    }
}

fn line_ranges(bytes: &[u8]) -> Vec<Range<usize>> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut cursor = 0;
    while cursor < bytes.len() {
        if matches!(bytes[cursor], b'\r' | b'\n') {
            lines.push(start..cursor);
            if bytes[cursor] == b'\r' && bytes.get(cursor + 1) == Some(&b'\n') {
                cursor += 1;
            }
            start = cursor + 1;
        }
        cursor += 1;
    }
    lines.push(start..bytes.len());
    lines
}

fn normalized_key(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() || bytes.len() > 256 {
        return None;
    }
    let mut normalized = String::with_capacity(bytes.len());
    let mut cursor = 0;
    while cursor < bytes.len() {
        let byte = bytes[cursor];
        if byte.is_ascii_alphanumeric() {
            normalized.push(char::from(byte.to_ascii_lowercase()));
            cursor += 1;
        } else if matches!(byte, b'_' | b'-' | b'.') {
            cursor += 1;
        } else if byte == b'%' && cursor + 2 < bytes.len() {
            let decoded = decode_hex_pair(bytes[cursor + 1], bytes[cursor + 2])?;
            push_normalized_byte(&mut normalized, decoded)?;
            cursor += 3;
        } else if byte == b'\\'
            && bytes.get(cursor + 1).is_some_and(|next| *next == b'u')
            && cursor + 5 < bytes.len()
        {
            let decoded = decode_ascii_unicode_escape(&bytes[cursor + 2..cursor + 6])?;
            push_normalized_byte(&mut normalized, decoded)?;
            cursor += 6;
        } else {
            return None;
        }
    }
    (!normalized.is_empty()).then_some(normalized)
}

fn push_normalized_byte(output: &mut String, byte: u8) -> Option<()> {
    if byte.is_ascii_alphanumeric() {
        output.push(char::from(byte.to_ascii_lowercase()));
        Some(())
    } else if matches!(byte, b'_' | b'-' | b'.') {
        Some(())
    } else {
        None
    }
}

fn is_sensitive_key(key: &str, include_query_abbreviations: bool) -> bool {
    matches!(
        key,
        "authorization"
            | "proxyauthorization"
            | "password"
            | "passwd"
            | "pwd"
            | "secret"
            | "token"
            | "accesstoken"
            | "refreshtoken"
            | "idtoken"
            | "apikey"
            | "clientsecret"
            | "credential"
            | "credentials"
            | "cookie"
            | "setcookie"
            | "privatekey"
            | "signingkey"
    ) || key.ends_with("token")
        || key.ends_with("secret")
        || key.ends_with("password")
        || key.ends_with("passwd")
        || key.ends_with("apikey")
        || key.ends_with("credential")
        || key.ends_with("privatekey")
        || (include_query_abbreviations && matches!(key, "key" | "sig" | "signature" | "auth"))
}

fn json_value_end(bytes: &[u8], start: usize) -> usize {
    let Some(first) = bytes.get(start).copied() else {
        return start;
    };
    if matches!(first, b'"' | b'\'') {
        return closing_quote(bytes, start, first).map_or(bytes.len(), |end| end + 1);
    }
    if !matches!(first, b'{' | b'[') {
        return (start..bytes.len())
            .find(|index| matches!(bytes[*index], b',' | b'}' | b']' | b'\r' | b'\n'))
            .unwrap_or(bytes.len());
    }

    let mut depth = 0_usize;
    let mut cursor = start;
    while cursor < bytes.len() {
        match bytes[cursor] {
            b'"' | b'\'' => {
                cursor =
                    closing_quote(bytes, cursor, bytes[cursor]).map_or(bytes.len(), |end| end + 1);
                continue;
            }
            b'{' | b'[' => depth += 1,
            b'}' | b']' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return cursor + 1;
                }
            }
            _ => {}
        }
        cursor += 1;
    }
    bytes.len()
}

fn closing_quote(bytes: &[u8], start: usize, quote: u8) -> Option<usize> {
    let mut cursor = start + 1;
    while cursor < bytes.len() {
        if bytes[cursor] == b'\\' {
            cursor = (cursor + 2).min(bytes.len());
        } else if bytes[cursor] == quote {
            return Some(cursor);
        } else {
            cursor += 1;
        }
    }
    None
}

fn scan_query_value_end(bytes: &[u8], start: usize) -> usize {
    if bytes
        .get(start)
        .is_some_and(|byte| matches!(byte, b'"' | b'\''))
    {
        return closing_quote(bytes, start, bytes[start]).map_or(bytes.len(), |end| end + 1);
    }
    (start..bytes.len())
        .find(|index| {
            matches!(bytes[*index], b'&' | b';' | b'#' | b'"' | b'\'')
                || bytes[*index].is_ascii_whitespace()
                || bytes[*index].is_ascii_control()
        })
        .unwrap_or(bytes.len())
}

fn scan_environment_value_end(bytes: &[u8], start: usize, line_end: usize) -> usize {
    if bytes
        .get(start)
        .is_some_and(|byte| matches!(byte, b'"' | b'\''))
    {
        return closing_quote(bytes, start, bytes[start])
            .map_or(line_end, |end| (end + 1).min(line_end));
    }
    (start..line_end)
        .find(|index| {
            bytes[*index].is_ascii_whitespace()
                || bytes[*index] == b';'
                || is_escaped_control_start(bytes, *index)
        })
        .unwrap_or(line_end)
}

fn is_escaped_control_start(bytes: &[u8], index: usize) -> bool {
    bytes.get(index) == Some(&b'\\')
        && bytes
            .get(index + 1)
            .is_some_and(|byte| matches!(byte, b'n' | b'r' | b't' | b'u'))
}

fn scan_credential_end(bytes: &[u8], start: usize) -> usize {
    (start..bytes.len())
        .find(|index| {
            bytes[*index].is_ascii_whitespace()
                || bytes[*index].is_ascii_control()
                || matches!(bytes[*index], b',' | b';' | b'"' | b'\'')
        })
        .unwrap_or(bytes.len())
}

fn scan_line_end(bytes: &[u8], start: usize) -> usize {
    (start..bytes.len())
        .find(|index| matches!(bytes[*index], b'\r' | b'\n'))
        .unwrap_or(bytes.len())
}

fn jwt_segment_lengths(bytes: &[u8]) -> Option<[usize; 3]> {
    let mut lengths = [0_usize; 3];
    let mut segment = 0;
    for byte in bytes {
        if *byte == b'.' {
            segment += 1;
            if segment > 2 {
                return None;
            }
        } else {
            lengths[segment] += 1;
        }
    }
    (segment == 2).then_some(lengths)
}

fn is_environment_key_start(bytes: &[u8], index: usize, line_start: usize) -> bool {
    (bytes[index].is_ascii_alphabetic() || bytes[index] == b'_')
        && (index == line_start || !is_key_byte(bytes[index - 1]))
}

fn is_key_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')
}

fn is_encoded_key_byte(byte: u8) -> bool {
    is_key_byte(byte) || byte == b'%'
}

fn is_jwt_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
}

fn has_word_boundary_before(bytes: &[u8], index: usize) -> bool {
    index == 0 || !is_key_byte(bytes[index - 1])
}

fn skip_ascii_space(bytes: &[u8], mut cursor: usize, end: usize) -> usize {
    while cursor < end && matches!(bytes[cursor], b' ' | b'\t') {
        cursor += 1;
    }
    cursor
}

fn trim_ascii_space(mut bytes: &[u8]) -> &[u8] {
    while bytes
        .first()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        bytes = &bytes[1..];
    }
    while bytes
        .last()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

fn skip_json_whitespace(bytes: &[u8], mut cursor: usize, end: usize) -> usize {
    while cursor < end {
        if matches!(bytes[cursor], b' ' | b'\t' | b'\r' | b'\n') {
            cursor += 1;
        } else if bytes[cursor] == b'\\'
            && bytes
                .get(cursor + 1)
                .is_some_and(|byte| matches!(byte, b't' | b'r' | b'n'))
        {
            // Terminal sanitization renders structural JSON whitespace this
            // way. Recognizing that representation keeps repeated redaction
            // stable while remaining conservative for arbitrary byte input.
            cursor += 2;
        } else {
            break;
        }
    }
    cursor
}

fn ascii_case_eq_at(bytes: &[u8], start: usize, needle: &[u8]) -> bool {
    bytes
        .get(start..start.saturating_add(needle.len()))
        .is_some_and(|candidate| candidate.eq_ignore_ascii_case(needle))
}

fn find_exact(bytes: &[u8], start: usize, needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || start > bytes.len().saturating_sub(needle.len()) {
        return None;
    }
    (start..=bytes.len() - needle.len())
        .find(|index| &bytes[*index..*index + needle.len()] == needle)
}

fn find_ascii_case_insensitive(bytes: &[u8], start: usize, needle: &[u8]) -> Option<usize> {
    find_ascii_case_insensitive_in(bytes, start, bytes.len(), needle)
}

fn find_ascii_case_insensitive_in(
    bytes: &[u8],
    start: usize,
    end: usize,
    needle: &[u8],
) -> Option<usize> {
    let end = end.min(bytes.len());
    if needle.is_empty() {
        return None;
    }
    let last_start = end.checked_sub(needle.len())?;
    if start > last_start {
        return None;
    }
    (start..=last_start).find(|index| ascii_case_eq_at(bytes, *index, needle))
}

fn decode_hex_pair(high: u8, low: u8) -> Option<u8> {
    hex_value(high)?
        .checked_mul(16)?
        .checked_add(hex_value(low)?)
}

fn decode_ascii_unicode_escape(bytes: &[u8]) -> Option<u8> {
    if bytes.len() != 4 || bytes[0] != b'0' || bytes[1] != b'0' {
        return None;
    }
    decode_hex_pair(bytes[2], bytes[3])
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn partial_tail_start(source: &str) -> usize {
    source
        .as_bytes()
        .iter()
        .rposition(|byte| {
            byte.is_ascii_whitespace()
                || byte.is_ascii_control()
                || matches!(byte, b',' | b';' | b'{' | b'}' | b'[' | b']' | b'(' | b')')
        })
        .map_or(0, |index| index + 1)
}

fn sanitize_terminal_text(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if character.is_control() || is_unicode_format_control(character) => {
                write!(output, "\\u{{{:X}}}", u32::from(character))
                    .expect("writing to a String cannot fail");
            }
            character => output.push(character),
        }
    }
    output
}

fn is_unicode_format_control(character: char) -> bool {
    matches!(
        character,
        '\u{061c}'
            | '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{206f}'
            | '\u{feff}'
    )
}

fn bound_output(value: &str, input_was_truncated: bool) -> String {
    let must_truncate = input_was_truncated || value.len() > MAX_AUDIT_DETAIL_OUTPUT_BYTES;
    if !must_truncate {
        return value.to_owned();
    }

    let maximum_prefix = MAX_AUDIT_DETAIL_OUTPUT_BYTES - TRUNCATION_MARKER.len();
    let mut end = value.len().min(maximum_prefix);
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    let mut output = String::with_capacity(end + TRUNCATION_MARKER.len());
    output.push_str(&value[..end]);
    output.push_str(TRUNCATION_MARKER);
    output
}
