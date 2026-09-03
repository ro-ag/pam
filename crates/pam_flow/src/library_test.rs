use std::fs;
use std::path::PathBuf;

use tempfile::TempDir;

use super::builtin::builtin;
use super::library::{Library, Source};
use super::validate::FlowError;

const DEMO: &str = "schema: 1\nid: demo\nname: Demo\nsteps:\n  - id: a\n    run: [git, status]\n";

fn library() -> (TempDir, Library) {
    let dir = TempDir::new().expect("temp dir");
    let library = Library::new(dir.path().join("flows"));
    (dir, library)
}

#[test]
fn an_empty_library_lists_only_the_builtins() {
    let (_dir, library) = library();
    let entries = library.list().expect("list");
    assert_eq!(entries.len(), builtin().len());
    assert!(entries.iter().all(|entry| entry.source == Source::Builtin));
    assert!(entries.iter().all(|entry| entry.path.is_none()));
    assert!(entries.iter().all(|entry| entry.parsed.is_ok()));
    let ids: Vec<_> = entries.iter().map(|entry| entry.id.as_str()).collect();
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    assert_eq!(ids, sorted);
    assert!(!library.dir().exists(), "listing creates nothing");
}

#[test]
fn saving_adds_a_flow_and_creates_the_directory() {
    let (_dir, library) = library();
    let saved = library.save("demo", DEMO).expect("save");
    assert_eq!(saved.source, Source::Library);
    assert_eq!(saved.path, Some(library.dir().join("demo.yaml")));
    assert_eq!(saved.yaml, DEMO);
    assert!(saved.parsed.is_ok());
    assert_eq!(
        fs::read_to_string(library.dir().join("demo.yaml")).unwrap(),
        DEMO
    );

    let entries = library.list().expect("list");
    assert_eq!(entries.len(), builtin().len() + 1);
    let demo = entries
        .iter()
        .find(|entry| entry.id == "demo")
        .expect("demo");
    assert_eq!(demo.source, Source::Library);
}

#[test]
fn a_library_file_shadows_a_builtin_and_deleting_it_reveals_the_builtin() {
    let (_dir, library) = library();
    let shadow =
        "schema: 1\nid: pr-readiness\nname: Mine\nsteps:\n  - id: a\n    run: [git, status]\n";
    library.save("pr-readiness", shadow).expect("save");

    let entries = library.list().expect("list");
    assert_eq!(
        entries.len(),
        builtin().len(),
        "the shadow replaces, not adds"
    );
    let entry = library.get("pr-readiness").expect("get").expect("present");
    assert_eq!(entry.source, Source::Library);
    assert_eq!(entry.yaml, shadow);

    assert!(
        library.delete("pr-readiness").expect("delete"),
        "a builtin is revealed"
    );
    let entry = library.get("pr-readiness").expect("get").expect("present");
    assert_eq!(entry.source, Source::Builtin);
    assert_eq!(entries.len(), library.list().expect("list").len());
}

#[test]
fn deleting_a_plain_library_flow_reveals_nothing() {
    let (_dir, library) = library();
    library.save("demo", DEMO).expect("save");
    assert!(!library.delete("demo").expect("delete"));
    assert_eq!(library.get("demo").expect("get"), None);
}

#[test]
fn deleting_an_unknown_flow_names_the_id() {
    let (_dir, library) = library();
    for id in ["demo", "pr-readiness", "../etc/passwd", ""] {
        match library.delete(id) {
            Err(FlowError::Invalid { path, message }) => {
                assert_eq!(path, "id");
                assert!(message.contains("no library flow named"), "{message}");
            }
            other => panic!("expected Invalid for `{id}`, got {other:?}"),
        }
    }
}

#[test]
fn save_refuses_an_id_mismatch_and_writes_nothing() {
    let (_dir, library) = library();
    let (path, message) = match library.save("other", DEMO) {
        Err(FlowError::Invalid { path, message }) => (path, message),
        other => panic!("expected Invalid, got {other:?}"),
    };
    assert_eq!(path, "id");
    assert!(message.contains("demo"), "{message}");
    assert!(!library.dir().exists(), "nothing was written");
}

#[test]
fn save_refuses_invalid_yaml_and_leaves_no_temporary_behind() {
    let (_dir, library) = library();
    library.save("demo", DEMO).expect("seed the directory");

    let broken = "schema: 1\nid: demo\nname: Demo\nsteps:\n  - id: a\n    run: [bash, -c, ls]\n";
    match library.save("demo", broken) {
        Err(FlowError::Invalid { path, .. }) => assert_eq!(path, "steps[0].run[0]"),
        other => panic!("expected Invalid, got {other:?}"),
    }
    assert_eq!(
        fs::read_to_string(library.dir().join("demo.yaml")).unwrap(),
        DEMO,
        "the old file survives"
    );
    let leftovers: Vec<PathBuf> = fs::read_dir(library.dir())
        .expect("read dir")
        .map(|entry| entry.expect("entry").path())
        .filter(|path| path.to_string_lossy().contains(".tmp-"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}

#[test]
fn save_refuses_an_id_that_could_never_be_a_file() {
    let (_dir, library) = library();
    for id in ["../escape", "Demo", "", "with space"] {
        match library.save(id, DEMO) {
            Err(FlowError::Invalid { path, .. }) => assert_eq!(path, "id", "{id}"),
            other => panic!("expected Invalid for `{id}`, got {other:?}"),
        }
    }
}

#[test]
fn only_yaml_files_named_after_a_flow_id_are_read() {
    let (_dir, library) = library();
    library.save("demo", DEMO).expect("save");
    fs::write(library.dir().join("notes.txt"), "hello").expect("write");
    fs::write(library.dir().join("other.yml"), DEMO).expect("write");
    fs::write(library.dir().join("Demo.yaml"), DEMO).expect("write");
    fs::write(library.dir().join("demo.yaml.tmp-1"), DEMO).expect("write");
    fs::create_dir(library.dir().join("nested.yaml")).expect("mkdir");

    let entries = library.list().expect("list");
    assert_eq!(entries.len(), builtin().len() + 1);
    assert_eq!(
        entries
            .iter()
            .filter(|entry| entry.source == Source::Library)
            .count(),
        1
    );
}

#[test]
fn a_broken_library_file_is_listed_with_its_error() {
    let (_dir, library) = library();
    fs::create_dir_all(library.dir()).expect("mkdir");
    fs::write(
        library.dir().join("broken.yaml"),
        "schema: 1\nid: broken\nname: Broken\n",
    )
    .expect("write");

    let entry = library.get("broken").expect("get").expect("present");
    assert_eq!(entry.source, Source::Library);
    let error = entry.parsed.expect_err("invalid");
    assert!(error.to_string().contains("steps"), "{error}");

    let listed = library.list().expect("list");
    let broken = listed
        .iter()
        .find(|entry| entry.id == "broken")
        .expect("listed");
    assert!(broken.parsed.is_err());
}

#[test]
fn a_file_whose_flow_claims_another_id_is_invalid() {
    let (_dir, library) = library();
    fs::create_dir_all(library.dir()).expect("mkdir");
    fs::write(library.dir().join("other.yaml"), DEMO).expect("write");

    let entry = library.get("other").expect("get").expect("present");
    match entry.parsed.expect_err("invalid") {
        FlowError::Invalid { path, message } => {
            assert_eq!(path, "id");
            assert!(message.contains("demo"), "{message}");
        }
        other => panic!("expected Invalid, got {other:?}"),
    }
}

#[test]
fn get_answers_none_for_an_unknown_or_impossible_id() {
    let (_dir, library) = library();
    assert_eq!(library.get("demo").expect("get"), None);
    assert_eq!(library.get("../../etc/passwd").expect("get"), None);
    assert_eq!(library.get("").expect("get"), None);
    assert!(library.get("pr-readiness").expect("get").is_some());
}

#[test]
fn the_library_is_capped() {
    let (_dir, library) = library();
    fs::create_dir_all(library.dir()).expect("mkdir");
    for n in 0..256 {
        let id = format!("flow-{n}");
        let yaml =
            format!("schema: 1\nid: {id}\nname: Flow\nsteps:\n  - id: a\n    run: [git, status]\n");
        fs::write(library.dir().join(format!("{id}.yaml")), yaml).expect("write");
    }
    assert_eq!(library.list().expect("list").len(), builtin().len() + 256);

    match library.save("demo", DEMO) {
        Err(FlowError::Invalid { path, message }) => {
            assert_eq!(path, "library");
            assert!(message.contains("256"), "{message}");
        }
        other => panic!("expected Invalid, got {other:?}"),
    }

    // Overwriting one that already exists still works at the cap.
    let existing =
        "schema: 1\nid: flow-0\nname: Renamed\nsteps:\n  - id: a\n    run: [git, status]\n";
    library
        .save("flow-0", existing)
        .expect("overwrite at the cap");

    fs::write(library.dir().join("flow-256.yaml"), DEMO).expect("write");
    match library.list() {
        Err(FlowError::Invalid { path, .. }) => assert_eq!(path, "library"),
        other => panic!("expected Invalid, got {other:?}"),
    }
}
