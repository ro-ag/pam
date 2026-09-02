use std::ffi::OsStr;
use std::path::Path;

use crate::catalog::{CATALOG, QWEN_BASE_URL, find_preset};
use crate::registry::MODEL_FLOOR_BYTES;

const GB: u64 = 1_000_000_000;

#[test]
fn every_preset_clears_the_engine_floor() {
    for preset in CATALOG {
        assert!(
            preset.size_bytes >= MODEL_FLOOR_BYTES,
            "{} is {} bytes, under the {MODEL_FLOOR_BYTES} floor; the catalog \
             must never offer a model that cannot serve a job",
            preset.id,
            preset.size_bytes
        );
    }
}

#[test]
fn preset_ids_are_unique() {
    let mut ids: Vec<&str> = CATALOG.iter().map(|preset| preset.id).collect();
    let before = ids.len();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), before, "duplicate preset id in the catalog");
}

#[test]
fn file_names_are_unique_and_end_in_gguf() {
    let mut names: Vec<&str> = CATALOG.iter().map(|preset| preset.file_name).collect();
    let before = names.len();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), before, "duplicate file name in the catalog");

    for preset in CATALOG {
        assert_eq!(
            Path::new(preset.file_name)
                .extension()
                .and_then(OsStr::to_str),
            Some("gguf"),
            "{} does not name a .gguf file",
            preset.id
        );
    }
}

#[test]
fn digests_are_sixty_four_lowercase_hex_characters() {
    for preset in CATALOG {
        assert_eq!(
            preset.sha256.len(),
            64,
            "{} digest is not 64 chars",
            preset.id
        );
        assert!(
            preset
                .sha256
                .chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
            "{} digest is not lowercase hex",
            preset.id
        );
    }
}

#[test]
fn urls_point_at_the_named_file() {
    for preset in CATALOG {
        assert!(
            preset.url.starts_with("https://"),
            "{} is not fetched over https",
            preset.id
        );
        assert_eq!(
            preset.url,
            format!("{QWEN_BASE_URL}{}", preset.file_name),
            "{} url is not its base plus its file name",
            preset.id
        );
        assert!(
            preset.license_url.starts_with("https://"),
            "{} license link is not a url",
            preset.id
        );
    }
}

#[test]
fn find_preset_hits_and_misses() {
    let hit = find_preset("qwen3-coder-30b-a3b-q4_k_m").expect("the Q4_K_M preset exists");
    assert_eq!(hit.quant, "Q4_K_M");
    assert_eq!(hit.size_bytes, 18_556_689_568);
    assert!(find_preset("qwen3-coder-30b-a3b-q1_ludicrous").is_none());
    assert!(find_preset("").is_none());
}

#[test]
fn fits_host_gates_on_declared_ram() {
    let small = find_preset("qwen3-coder-30b-a3b-q4_k_m").unwrap();
    let large = find_preset("qwen3-coder-30b-a3b-q8_0").unwrap();

    assert!(small.fits_host(32 * GB));
    assert!(!large.fits_host(32 * GB));
    assert!(large.fits_host(64 * GB));
    assert!(!small.fits_host(16 * GB));
}

#[test]
fn model_id_matches_the_registry_layout() {
    let preset = find_preset("qwen3-coder-30b-a3b-q4_k_m").unwrap();
    assert_eq!(
        preset.model_id(),
        "qwen/Qwen3-Coder-30B-A3B-Instruct-Q4_K_M"
    );
}

#[test]
fn ram_requirements_never_drop_below_the_weights() {
    for preset in CATALOG {
        assert!(
            preset.min_host_ram_bytes > preset.size_bytes,
            "{} asks for less RAM than the file weighs",
            preset.id
        );
    }
}
