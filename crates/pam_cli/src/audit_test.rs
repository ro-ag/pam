use pam_core::{CallerId, ProjectId};
use pam_store::{AUDIT_EXPORT_VERSION, AuditEventRecord, AuditExport};

use super::audit::encode_audit_export;

#[test]
fn audit_export_is_deterministic_versioned_ascii_ndjson() {
    let export = AuditExport {
        version: AUDIT_EXPORT_VERSION,
        project_id: ProjectId::from("project-\u{1f680}"),
        after_sequence: 4,
        through_sequence: 12,
        next_after_sequence: 7,
        has_more: true,
        events: vec![AuditEventRecord {
            sequence: 7,
            event_id: "event-7".to_owned(),
            project_id: ProjectId::from("project-\u{1f680}"),
            caller_id: CallerId::from("caller-1"),
            action: "request.authorize".to_owned(),
            decision: "allow".to_owned(),
            outcome: "observed".to_owned(),
            redacted_detail: "line\n\"[REDACTED]\"".to_owned(),
            occurred_at_ms: 100,
            retain_until_ms: 200,
        }],
    };

    let encoded = encode_audit_export(&export);
    assert!(encoded.is_ascii());
    assert_eq!(
        String::from_utf8(encoded).unwrap(),
        concat!(
            "{\"type\":\"pam_audit_export\",\"version\":1,\"project_id\":\"project-\\ud83d\\ude80\",\"after_sequence\":4,\"through_sequence\":12,\"next_after_sequence\":7,\"has_more\":true}\n",
            "{\"type\":\"audit_event\",\"sequence\":7,\"event_id\":\"event-7\",\"project_id\":\"project-\\ud83d\\ude80\",\"caller_id\":\"caller-1\",\"action\":\"request.authorize\",\"decision\":\"allow\",\"outcome\":\"observed\",\"redacted_detail\":\"line\\n\\\"[REDACTED]\\\"\",\"occurred_at_unix_ms\":100,\"retain_until_unix_ms\":200}\n",
        )
    );
}
