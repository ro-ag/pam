use std::path::{Path, PathBuf};

use super::{ModelError, ModelKey, default_model_path, validate_model_filename};

#[test]
fn default_location_is_user_owned_home_llm_vendor_filename() {
    let key = ModelKey::new("qwen", "qwen3.6-35b").unwrap();
    assert_eq!(
        default_model_path(Path::new("/Users/example"), &key, "qwen3.6-35b-q4.gguf").unwrap(),
        PathBuf::from("/Users/example/llm/qwen/qwen3.6-35b-q4.gguf")
    );
}

#[test]
fn filenames_are_single_gguf_segments() {
    assert!(validate_model_filename("model.gguf").is_ok());
    for filename in [
        "model.bin",
        "../model.gguf",
        "a/b.gguf",
        ".gguf",
        "model gguf",
    ] {
        assert!(matches!(
            validate_model_filename(filename),
            Err(ModelError::InvalidFilename)
        ));
    }
}

#[test]
fn default_location_requires_an_absolute_unicode_home() {
    let key = ModelKey::new("vendor", "model").unwrap();
    assert!(matches!(
        default_model_path(Path::new("relative"), &key, "model.gguf"),
        Err(ModelError::InvalidPath)
    ));
}
