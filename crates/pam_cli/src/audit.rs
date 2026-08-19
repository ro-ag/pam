use std::fmt::Write as _;

use pam_store::{AuditEventRecord, AuditExport};

/// Encodes one bounded audit page as deterministic, versioned ASCII NDJSON.
#[must_use]
pub(crate) fn encode_audit_export(export: &AuditExport) -> Vec<u8> {
    let mut encoded = String::new();
    encoded.push_str("{\"type\":\"pam_audit_export\",\"version\":");
    write!(encoded, "{}", export.version).expect("writing to a String cannot fail");
    encoded.push_str(",\"project_id\":");
    push_json_string(&mut encoded, export.project_id.as_str());
    write!(
        encoded,
        ",\"after_sequence\":{},\"through_sequence\":{},\"next_after_sequence\":{},\"has_more\":{}",
        export.after_sequence, export.through_sequence, export.next_after_sequence, export.has_more
    )
    .expect("writing to a String cannot fail");
    encoded.push_str("}\n");

    for event in &export.events {
        encode_event(&mut encoded, event);
    }
    encoded.into_bytes()
}

fn encode_event(encoded: &mut String, event: &AuditEventRecord) {
    encoded.push_str("{\"type\":\"audit_event\",\"sequence\":");
    write!(encoded, "{}", event.sequence).expect("writing to a String cannot fail");
    encoded.push_str(",\"event_id\":");
    push_json_string(encoded, &event.event_id);
    encoded.push_str(",\"project_id\":");
    push_json_string(encoded, event.project_id.as_str());
    encoded.push_str(",\"caller_id\":");
    push_json_string(encoded, event.caller_id.as_str());
    encoded.push_str(",\"action\":");
    push_json_string(encoded, &event.action);
    encoded.push_str(",\"decision\":");
    push_json_string(encoded, &event.decision);
    encoded.push_str(",\"outcome\":");
    push_json_string(encoded, &event.outcome);
    encoded.push_str(",\"redacted_detail\":");
    push_json_string(encoded, &event.redacted_detail);
    write!(
        encoded,
        ",\"occurred_at_unix_ms\":{},\"retain_until_unix_ms\":{}",
        event.occurred_at_ms, event.retain_until_ms
    )
    .expect("writing to a String cannot fail");
    encoded.push_str("}\n");
}

fn push_json_string(encoded: &mut String, value: &str) {
    encoded.push('"');
    for character in value.chars() {
        match character {
            '"' => encoded.push_str("\\\""),
            '\\' => encoded.push_str("\\\\"),
            '\u{08}' => encoded.push_str("\\b"),
            '\u{0c}' => encoded.push_str("\\f"),
            '\n' => encoded.push_str("\\n"),
            '\r' => encoded.push_str("\\r"),
            '\t' => encoded.push_str("\\t"),
            ' '..='~' => encoded.push(character),
            character if u32::from(character) <= 0xffff => {
                write!(encoded, "\\u{:04x}", u32::from(character))
                    .expect("writing to a String cannot fail");
            }
            character => {
                let scalar = u32::from(character) - 0x1_0000;
                let high = 0xd800 + (scalar >> 10);
                let low = 0xdc00 + (scalar & 0x3ff);
                write!(encoded, "\\u{high:04x}\\u{low:04x}")
                    .expect("writing to a String cannot fail");
            }
        }
    }
    encoded.push('"');
}
