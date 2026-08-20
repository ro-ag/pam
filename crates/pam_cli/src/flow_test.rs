use std::{fs, path::PathBuf};

use uuid::Uuid;

use super::flow::{FlowCatalog, FlowCatalogError};

fn test_root(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("pam-cli-flow-{name}-{}", Uuid::new_v4()));
    fs::create_dir_all(root.join(".pam/flows")).unwrap();
    root
}

pub(crate) fn flow_source(id: &str, name: &str) -> String {
    format!(
        r#"schema_version = 2
id = "{id}"
name = "{name}"
description = "A bounded local CLI flow."
revision = 1

[outcome]
solved = "Solved."
changed = "Changed."
verified = "Verified."
unresolved = "Unresolved."
blocked = "Blocked."

[[steps]]
id = "inspect"
description = "Inspect the worktree."
timeout_seconds = 10
effect = "read_only"
semantic = "observe"
action = {{ type = "command", program = "git", args = ["status", "--short"], working_directory = "." }}
"#
    )
}

fn write_flow(root: &std::path::Path, file_name: &str, id: &str, name: &str) {
    fs::write(
        root.join(".pam/flows").join(file_name),
        flow_source(id, name),
    )
    .unwrap();
}

#[test]
fn catalog_is_sorted_and_selects_only_exact_id_or_matching_file_name() {
    let root = test_root("sorted");
    write_flow(&root, "flow-zeta.toml", "flow-zeta", "Zeta flow");
    write_flow(&root, "flow-alpha.toml", "flow-alpha", "Alpha flow");

    let catalog = FlowCatalog::load(&root).unwrap();
    assert_eq!(
        catalog
            .entries()
            .iter()
            .map(|entry| entry.file_name.as_str())
            .collect::<Vec<_>>(),
        vec!["flow-alpha.toml", "flow-zeta.toml"]
    );
    for selector in ["flow-alpha", "flow-alpha.toml"] {
        assert_eq!(
            catalog.select(selector).unwrap().definition.id(),
            "flow-alpha"
        );
    }
    assert!(matches!(
        catalog.select("Alpha flow"),
        Err(FlowCatalogError::NotFound(_))
    ));
    let selected = catalog.select("flow-alpha").unwrap();
    assert_eq!(selected.source, flow_source("flow-alpha", "Alpha flow"));
    assert!(selected.normalized.starts_with("schema_version = 2\n"));
    assert!(selected.normalized.contains("semantic = \"observe\"\n"));

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn catalog_rejects_traversal_filename_mismatch_and_invalid_definitions() {
    let root = test_root("invalid");
    write_flow(&root, "first.toml", "first", "First");
    let catalog = FlowCatalog::load(&root).unwrap();
    assert!(matches!(
        catalog.select("../alpha"),
        Err(FlowCatalogError::InvalidSelector)
    ));
    write_flow(&root, "second.toml", "other", "First");
    assert!(matches!(
        FlowCatalog::load(&root),
        Err(FlowCatalogError::FileNameMismatch { .. })
    ));
    fs::remove_file(root.join(".pam/flows/second.toml")).unwrap();
    let secret = "private-definition-value-must-not-echo";
    fs::write(
        root.join(".pam/flows/broken.toml"),
        format!("not = [{secret}"),
    )
    .unwrap();
    let error = FlowCatalog::load(&root).unwrap_err();
    assert!(matches!(error, FlowCatalogError::InvalidDefinition { .. }));
    assert!(!error.to_string().contains(secret));

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn catalog_is_direct_only_and_bounds_each_document() {
    let root = test_root("bounded");
    write_flow(&root, "direct.toml", "direct", "Direct");
    fs::create_dir_all(root.join(".pam/flows/nested")).unwrap();
    fs::write(
        root.join(".pam/flows/nested/hidden.toml"),
        flow_source("hidden", "Hidden"),
    )
    .unwrap();
    fs::write(root.join(".pam/flows/notes.txt"), "ignored").unwrap();
    let catalog = FlowCatalog::load(&root).unwrap();
    assert_eq!(catalog.entries().len(), 1);
    assert!(matches!(
        catalog.select("hidden"),
        Err(FlowCatalogError::NotFound(_))
    ));

    fs::write(
        root.join(".pam/flows/huge.toml"),
        vec![b'x'; pam_flow::MAX_FLOW_DOCUMENT_BYTES + 1],
    )
    .unwrap();
    assert!(matches!(
        FlowCatalog::load(&root),
        Err(FlowCatalogError::FileTooLarge(_))
    ));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn catalog_charges_actual_bytes_when_definitions_grow_after_metadata() {
    use std::io::Write as _;

    let root = test_root("growth-accounting");
    for index in 0..9 {
        write_flow(
            &root,
            &format!("flow-{index}.toml"),
            &format!("flow-{index}"),
            &format!("Flow {index}"),
        );
    }
    let flow_directory = root.join(".pam/flows");
    let result = FlowCatalog::load_after_metadata(&root, |_, file_name| {
        let path = flow_directory.join(file_name);
        let size = usize::try_from(fs::metadata(&path).unwrap().len()).unwrap();
        let mut file = fs::OpenOptions::new().append(true).open(path).unwrap();
        file.write_all(&vec![b' '; pam_flow::MAX_FLOW_DOCUMENT_BYTES - size])
            .unwrap();
    });

    assert!(matches!(result, Err(FlowCatalogError::CatalogTooLarge)));
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn catalog_rejects_symlinked_directories_and_definition_entries() {
    use std::os::unix::fs::symlink;

    let target = test_root("symlink-target");
    write_flow(&target, "target.toml", "target", "Target");
    let linked_root = std::env::temp_dir().join(format!("pam-cli-flow-link-{}", Uuid::new_v4()));
    fs::create_dir_all(linked_root.join(".pam")).unwrap();
    symlink(target.join(".pam/flows"), linked_root.join(".pam/flows")).unwrap();
    assert!(matches!(
        FlowCatalog::load(&linked_root),
        Err(FlowCatalogError::UnsafeDirectory(_))
    ));

    fs::remove_file(linked_root.join(".pam/flows")).unwrap();
    fs::create_dir(linked_root.join(".pam/flows")).unwrap();
    symlink(
        target.join(".pam/flows/target.toml"),
        linked_root.join(".pam/flows/linked.toml"),
    )
    .unwrap();
    assert!(matches!(
        FlowCatalog::load(&linked_root),
        Err(FlowCatalogError::UnsafeEntry(_))
    ));

    fs::remove_dir_all(linked_root).unwrap();
    fs::remove_dir_all(target).unwrap();
}

#[cfg(unix)]
#[test]
fn no_follow_open_rejects_a_definition_swapped_to_a_symlink() {
    use std::os::unix::fs::symlink;

    let root = test_root("swap-root");
    let outside = test_root("swap-outside");
    write_flow(&root, "swap.toml", "swap", "Inside");
    write_flow(&outside, "outside.toml", "outside", "Outside");
    let candidate = root.join(".pam/flows/swap.toml");
    let replacement = outside.join(".pam/flows/outside.toml");
    let mut swapped = false;
    let result = FlowCatalog::load_after_candidate(&root, |_, file_name| {
        if file_name == "swap.toml" && !swapped {
            fs::remove_file(&candidate).unwrap();
            symlink(&replacement, &candidate).unwrap();
            swapped = true;
        }
    });
    assert!(matches!(result, Err(FlowCatalogError::UnsafeEntry(_))));

    fs::remove_dir_all(root).unwrap();
    fs::remove_dir_all(outside).unwrap();
}
