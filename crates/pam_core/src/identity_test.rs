use super::{CallerId, IdempotencyKey, ProjectId, RequestId};

#[test]
fn identifiers_preserve_their_text_values() {
    assert_eq!(CallerId::from("cli").as_str(), "cli");
    assert_eq!(IdempotencyKey::from("status-1").as_str(), "status-1");
    assert_eq!(ProjectId::from("project").as_str(), "project");
    assert_eq!(RequestId::from("request").as_str(), "request");
}
