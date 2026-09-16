use pam_compact::{Policy, compact, sha256_hex};

use crate::evidence_view::{
    ByteRange, MAX_SEGMENTS, POLICY_VERSION, Relation, Segment, ViewError, compact_segments,
    compose_segments, redact, resolve,
};

fn span(start: usize, end: usize) -> ByteRange {
    ByteRange {
        start: start as u64,
        end: end as u64,
    }
}

#[test]
fn evidence_view_masks_headers_assignments_urls_and_pem_as_one_artifact() {
    let source = b"Authorization: Bearer header-secret\r\nCookie: cookie-secret\r\nSet-Cookie: session=server-secret\r\n\tcontinued-secret\r\npassword='quoted secret' safe=kept\nAWS_SESSION_TOKEN=assignment-secret\nhttps://user:url-secret@host/path?%61ccess_token=query-secret&safe=kept\n-----BEGIN PRIVATE KEY-----\nprivate-body\n-----END PRIVATE KEY-----\nend\n";
    let view = redact(source).unwrap();
    let text = std::str::from_utf8(&view.bytes).unwrap();
    for secret in [
        "header-secret",
        "cookie-secret",
        "server-secret",
        "continued-secret",
        "quoted secret",
        "assignment-secret",
        "url-secret",
        "query-secret",
        "private-body",
    ] {
        assert!(!text.contains(secret), "{secret}");
    }
    assert!(text.contains("safe=kept"));
    assert!(text.contains("@host/path"));
    assert!(text.ends_with("end\n"));
    assert_eq!(view.policy_version, POLICY_VERSION);
    assert_eq!(view.source_sha256, sha256_hex(source));
    assert_eq!(view.view_sha256, sha256_hex(&view.bytes));
    for segment in &view.segments {
        let parent = segment.parent.unwrap();
        if segment.relation == Relation::Identity {
            assert_eq!(
                &view.bytes[usize::try_from(segment.view.start).unwrap()
                    ..usize::try_from(segment.view.end).unwrap()],
                &source
                    [usize::try_from(parent.start).unwrap()..usize::try_from(parent.end).unwrap()]
            );
        }
    }
    resolve(&view.segments, span(0, view.bytes.len())).unwrap();
}

#[test]
fn evidence_view_masks_sensitive_json_values_and_escaped_key_names() {
    let source = br#"{"password":"json secret","nested":{"api\u005fkey":"key secret"},"credentials":{"user":"nested secret"},"access_token":["array secret"],"Authorization":"Bearer header secret","safe":41}"#;
    let view = redact(source).unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&view.bytes).unwrap();
    assert_eq!(parsed["safe"], 41);
    assert_eq!(parsed["password"], "[REDACTED]");
    assert_eq!(parsed["credentials"], "[REDACTED]");
    assert_eq!(parsed["nested"]["api_key"], "[REDACTED]");
    assert!(!String::from_utf8(view.bytes).unwrap().contains("secret"));
}

#[test]
fn evidence_view_pages_cannot_expose_a_secret_split_at_the_page_boundary() {
    let mut source = vec![b'x'; 16_375];
    source.extend_from_slice(b"\naccess_token=boundary-crossing-secret\ntrailer");
    let view = redact(&source).unwrap();
    for page_size in [1, 7, 16_384, 65_536] {
        let fetched: Vec<u8> = view.bytes.chunks(page_size).flatten().copied().collect();
        assert_eq!(sha256_hex(&fetched), view.view_sha256);
        assert!(
            !String::from_utf8(fetched)
                .unwrap()
                .contains("boundary-crossing-secret")
        );
    }
    let hidden = view
        .segments
        .iter()
        .find(|segment| segment.relation == Relation::Redacted)
        .unwrap();
    let parent = hidden.parent.unwrap();
    assert_eq!(
        &source[usize::try_from(parent.start).unwrap()..usize::try_from(parent.end).unwrap()],
        b"boundary-crossing-secret"
    );
}

#[test]
fn evidence_view_invalid_utf8_is_preserved_without_offset_drift() {
    let source = b"\xff token=secret\n\xfe keep";
    let view = redact(source).unwrap();
    assert_eq!(view.bytes, b"\xff token=[REDACTED]\n\xfe keep");
    assert!(std::str::from_utf8(&view.bytes).is_err());
    let tail = resolve(&view.segments, span(view.bytes.len() - 4, view.bytes.len())).unwrap();
    assert_eq!(tail[0].parent, Some(span(source.len() - 4, source.len())));
}

#[test]
fn evidence_view_recognizes_ansi_obscured_credential_names() {
    let source = b"pass\x1b[31mword=ansi-secret\nAuth\x1b[0morization: Bearer other-secret\n";
    let view = redact(source).unwrap();
    let text = String::from_utf8(view.bytes).unwrap();
    assert!(!text.contains("ansi-secret"));
    assert!(!text.contains("other-secret"));
}

#[test]
fn evidence_view_malformed_quotes_and_unterminated_pem_never_panic_or_return_secrets() {
    for source in [
        b"password=\"".as_slice(),
        b"{\"password\":\"",
        b"password='",
        b"{\"password\":",
    ] {
        redact(source).unwrap();
    }
    for source in [
        b"password=\"unfinished-secret".as_slice(),
        b"-----BEGIN PRIVATE KEY-----\nunfinished-secret",
        b"-----BEGIN invalid\nunfinished-secret",
    ] {
        assert!(
            !String::from_utf8(redact(source).unwrap().bytes)
                .unwrap()
                .contains("unfinished-secret")
        );
    }
    let sample = b"{\"password\":\"escape\\\"secret\",\"token\":true}";
    for end in 0..=sample.len() {
        redact(&sample[..end]).unwrap();
    }
}

#[test]
fn evidence_view_refuses_source_and_fragmentation_limits() {
    assert_eq!(
        redact(&vec![b'x'; pam_compact::MAX_SOURCE_BYTES + 1]).unwrap_err(),
        ViewError::TooLarge
    );
    let source = b"token=x\n".repeat(MAX_SEGMENTS / 2 + 1);
    assert_eq!(redact(&source).unwrap_err(), ViewError::TooManySegments);
}

#[test]
fn evidence_view_compact_substrings_cover_full_original_records() {
    let source = b"\x1b[31merror\x1b[0m:\tbad\xff\r\n";
    let report = compact(source, Some(1), &Policy::default()).unwrap();
    let map = compact_segments(&report, source).unwrap();
    let resolved = resolve(&map, span(0, 5)).unwrap();
    assert_eq!(resolved[0].relation, Relation::CoveringRecord);
    assert_eq!(resolved[0].parent, Some(span(0, source.len())));
    let footer = map.last().unwrap();
    assert_eq!(footer.relation, Relation::Synthetic);
    assert!(footer.parent.is_none());
}

#[test]
fn evidence_view_compact_omissions_and_empty_footer_are_not_source_quotes() {
    let source = b"first\nsecond\nthird\n";
    let report = compact(
        source,
        None,
        &Policy {
            boundary_records: 0,
            failure_context_records: 0,
        },
    )
    .unwrap();
    let map = compact_segments(&report, source).unwrap();
    assert_eq!(map[0].relation, Relation::Omitted);
    assert_eq!(map[0].parent, Some(span(0, source.len())));
    let empty = compact(b"", None, &Policy::default()).unwrap();
    assert!(
        compact_segments(&empty, b"")
            .unwrap()
            .iter()
            .all(|segment| segment.relation == Relation::Synthetic && segment.parent.is_none())
    );
}

#[test]
fn evidence_view_compact_rejects_forged_parent_and_noncontiguous_map() {
    let source = b"a\nb\n";
    let report = compact(source, None, &Policy::default()).unwrap();
    assert_eq!(
        compact_segments(&report, b"x\ny\n"),
        Err(ViewError::ParentMismatch)
    );
    let mut broken = report.clone();
    broken.fragments[1].offset += 1;
    assert_eq!(
        compact_segments(&broken, source),
        Err(ViewError::InvalidMap)
    );
    let mut broken = report;
    broken.rendered_text.push_str("invented");
    assert_eq!(
        compact_segments(&broken, source),
        Err(ViewError::InvalidMap)
    );
}

#[test]
fn evidence_view_composition_keeps_redaction_and_normalization_coarse() {
    let source = b"password=source-secret\nokay\n";
    let source_view = redact(source).unwrap();
    let compact = compact(&source_view.bytes, Some(1), &Policy::default()).unwrap();
    let compact_map = compact_segments(&compact, &source_view.bytes).unwrap();
    let final_view = redact(compact.rendered_text.as_bytes()).unwrap();
    let first = compose_segments(&final_view.segments, &compact_map).unwrap();
    let chain = compose_segments(&first, &source_view.segments).unwrap();
    let hidden = chain
        .iter()
        .find(|segment| segment.relation == Relation::Redacted)
        .unwrap();
    assert!(hidden.parent.unwrap().end <= source.len() as u64);
    assert_eq!(chain.last().unwrap().relation, Relation::Synthetic);
    assert!(
        String::from_utf8(final_view.bytes)
            .unwrap()
            .contains("[REDACTED]")
    );
}

#[test]
fn evidence_view_rejects_invalid_range_arithmetic_and_empty_reads_resolve_empty() {
    let view = redact(b"ordinary").unwrap();
    assert!(resolve(&view.segments, span(3, 3)).unwrap().is_empty());
    assert_eq!(
        resolve(
            &view.segments,
            ByteRange {
                start: 0,
                end: u64::MAX
            }
        ),
        Err(ViewError::InvalidMap)
    );
    let bad = [Segment {
        view: span(0, 4),
        parent: Some(span(0, 2)),
        relation: Relation::Identity,
    }];
    assert_eq!(resolve(&bad, span(0, 1)), Err(ViewError::InvalidMap));
    let child = [Segment {
        view: span(0, 1),
        parent: Some(span(8, 9)),
        relation: Relation::Redacted,
    }];
    assert_eq!(
        compose_segments(&child, &view.segments),
        Err(ViewError::InvalidMap)
    );
}

#[test]
fn evidence_view_json_preserves_structure_and_masks_nested_strings() {
    let source = serde_json::json!({"request":"req_1","steps":[{"password":{"nested":"hidden"},"status":"failed","detail":"Authorization: Bearer embedded-secret","url":"https://u:url-secret@host/path?token=query-secret"}],"count":42,"ok":false});
    let safe = crate::evidence_view::redact_json(&source).unwrap();
    assert_eq!(safe["request"], "req_1");
    assert_eq!(safe["steps"][0]["password"], "[REDACTED]");
    assert_eq!(safe["steps"][0]["status"], "failed");
    assert_eq!(safe["count"], 42);
    assert_eq!(safe["ok"], false);
    let serialized = serde_json::to_string(&safe).unwrap();
    for secret in ["hidden", "embedded-secret", "url-secret", "query-secret"] {
        assert!(!serialized.contains(secret));
    }
}

#[test]
fn evidence_view_json_rejects_excessive_depth_without_serializing_it() {
    let mut nested = serde_json::Value::Null;
    for _ in 0..66 {
        nested = serde_json::Value::Array(vec![nested]);
    }
    assert_eq!(
        crate::evidence_view::redact_json(&nested),
        Err(ViewError::TooManySegments)
    );
}
