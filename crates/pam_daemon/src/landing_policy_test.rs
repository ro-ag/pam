use crate::landing_policy::{Snapshot, valid_ref};
use pam_store::Store;
use serde_json::json;

#[test]
fn ref_targets_cannot_be_options_revisions_or_wildcards() {
    for value in [
        "--all",
        "main..other",
        "HEAD~1",
        "branch@{1}",
        "refs/*",
        "a//b",
        "a.lock",
        "a/.b",
        "a b",
    ] {
        assert!(!valid_ref(value), "{value}");
    }
    assert!(valid_ref("feat/approved-work"));
}

#[tokio::test]
async fn missing_policy_denies_and_stale_editor_cannot_overwrite() {
    let store = Store::open_in_memory().await.unwrap();
    let base = tempfile::tempdir().unwrap();
    let current = Snapshot::load(&store).await.unwrap();
    assert!(current.repository(base.path()).is_err());
    let stale = json!({"expected_revision":"stale", "repositories":[]});
    assert_eq!(
        Snapshot::save(&store, &stale, base.path())
            .await
            .err()
            .unwrap()
            .cause,
        "landing_policy_changed"
    );
    let valid = json!({"expected_revision":current.revision,"repositories":[]});
    assert!(Snapshot::save(&store, &valid, base.path()).await.is_ok());
    let unknown = json!({"expected_revision":current.revision,"repositories":[],"grant_all":true});
    assert_eq!(
        Snapshot::save(&store, &unknown, base.path())
            .await
            .err()
            .unwrap()
            .cause,
        "landing_policy_invalid"
    );
}
