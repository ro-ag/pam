use crate::sonar_mapping::Snapshot;
use pam_store::Store;
use serde_json::json;

fn mapping() -> serde_json::Value {
    json!({"server":"https://SONAR.example:443/sonar","project":"org:project","repository":"https://GIT.example:443/org/repo"})
}

#[tokio::test]
async fn mappings_normalize_lookup_and_reject_stale_editors() {
    let store = Store::open_in_memory().await.unwrap();
    let empty = Snapshot::load(&store).await.unwrap();
    assert!(
        empty
            .repository("https://sonar.example/sonar", "org:project")
            .is_none()
    );
    let update = json!({"expected_revision":empty.revision(),"mappings":[mapping()]});
    let saved = Snapshot::save(&store, &update).await.unwrap();
    assert_eq!(
        saved.repository("https://sonar.example/sonar/", "org:project"),
        Some("https://git.example/org/repo")
    );
    assert!(
        saved
            .repository("https://other.example/sonar/", "org:project")
            .is_none()
    );
    assert!(
        saved
            .repository("https://sonar.example/sonar/", "other")
            .is_none()
    );
    assert_eq!(
        Snapshot::save(&store, &update).await.err().unwrap().cause(),
        "sonar_mapping_conflict"
    );
    assert_eq!(
        Snapshot::load(&store).await.unwrap().revision(),
        saved.revision()
    );
}

#[tokio::test]
async fn duplicate_credentials_and_malformed_mappings_refuse() {
    let store = Store::open_in_memory().await.unwrap();
    let revision = Snapshot::load(&store).await.unwrap().revision().to_owned();
    let mut credential = mapping();
    credential["server"] = json!("https://user:secret@sonar.example/");
    let mut list = mapping();
    list["project"] = json!("one,two");
    let mut repo = mapping();
    repo["repository"] = json!("https://user:secret@git.example/repo");
    for mappings in [
        json!([mapping(), mapping()]),
        json!([credential]),
        json!([list]),
        json!([repo]),
        json!(vec![mapping(); 65]),
    ] {
        assert!(
            Snapshot::save(
                &store,
                &json!({"expected_revision":revision,"mappings":mappings})
            )
            .await
            .is_err()
        );
    }
    store
        .set_setting("sonar.repository_mappings", "[]")
        .await
        .unwrap();
    assert!(Snapshot::load(&store).await.is_err());
    store
        .set_setting("sonar.repository_mappings", &"x".repeat(32769))
        .await
        .unwrap();
    assert!(Snapshot::load(&store).await.is_err());
}

#[tokio::test]
async fn concurrent_mapping_editors_cannot_overwrite_each_other() {
    let store = Store::open_in_memory().await.unwrap();
    let initial = Snapshot::load(&store).await.unwrap();
    let first = json!({"expected_revision":initial.revision(),"mappings":[mapping()]});
    let mut different = mapping();
    different["repository"] = json!("https://git.example/org/other");
    let second = json!({"expected_revision":initial.revision(),"mappings":[different]});
    let (a, b) = tokio::join!(
        Snapshot::save(&store, &first),
        Snapshot::save(&store, &second)
    );
    assert_ne!(a.is_ok(), b.is_ok());
}
