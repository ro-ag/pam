use std::path::PathBuf;

use llama_cpp_4::{
    context::params::LlamaFlashAttnType,
    model::{LlamaChatMessage, params::LlamaModelParams},
    quantize::GgmlType,
};
use pam_core::ContentDigest;

use super::{
    GgufMetadata, LicenseSnapshot, ModelKey, ModelSource, RegisteredModel, RuntimeError,
    RuntimeFinishReason, RuntimeFlashAttention, RuntimeGpuOffload, RuntimeHostSnapshot,
    RuntimeKvCachePrecision, RuntimeMemoryPressure, RuntimeMessage, RuntimeMessageRole,
    RuntimeRequest, RuntimeSampling, RuntimeSwapTrend,
};
use crate::llama_cpp_macos::{
    admit_bytes, bounded_template_size, build_chat_messages, calibrated_contingency,
    calibrated_runtime_profile, final_prefill_sample_slot, fixed_context_params,
    fixed_model_params, metal_and_host_memory_limits, prefill_chunk_ranges,
    projection_from_entries, required_os_reserve, test_calibrated_digest, test_calibrated_size,
    validate_calibrated_artifact, validate_host_admission,
};

fn registered(digest: ContentDigest, size_bytes: u64) -> RegisteredModel {
    RegisteredModel {
        key: ModelKey::new("qwen", "qwen3-coder-30b-a3b-instruct-q4-k-s").unwrap(),
        path: PathBuf::from("/tmp/model.gguf"),
        digest,
        size_bytes,
        gguf: GgufMetadata {
            version: 3,
            tensor_count: 1,
            metadata_kv_count: 1,
        },
        license: LicenseSnapshot::new(
            "Apache-2.0",
            "https://example.test/license",
            ContentDigest::from_sha256([7; 32]),
        )
        .unwrap(),
        source: ModelSource::Local,
        registered_at_ms: 0,
    }
}

#[test]
fn calibrated_profile_requires_exact_digest_and_size() {
    let digest = ContentDigest::parse(test_calibrated_digest()).unwrap();
    assert!(
        validate_calibrated_artifact(&registered(digest.clone(), test_calibrated_size())).is_ok()
    );
    assert!(matches!(
        validate_calibrated_artifact(&registered(digest, test_calibrated_size() - 1)),
        Err(RuntimeError::UnsupportedArtifact)
    ));
    assert!(matches!(
        validate_calibrated_artifact(&registered(
            ContentDigest::from_sha256([0; 32]),
            test_calibrated_size(),
        )),
        Err(RuntimeError::UnsupportedArtifact)
    ));
}

#[test]
fn calibrated_runtime_parameters_are_exact() {
    let model_params: LlamaModelParams = fixed_model_params();
    assert_eq!(model_params.n_gpu_layers(), i32::MAX);

    let context_params = fixed_context_params();
    assert_eq!(context_params.n_ctx().unwrap().get(), 8_192);
    assert_eq!(context_params.n_batch(), 512);
    assert_eq!(context_params.n_ubatch(), 512);
    assert_eq!(context_params.n_seq_max(), 1);
    assert_eq!(context_params.flash_attn_type(), LlamaFlashAttnType::Auto);
    assert_eq!(context_params.cache_type_k(), GgmlType::F16 as u32);
    assert_eq!(context_params.cache_type_v(), GgmlType::F16 as u32);
    assert!(!context_params.kv_unified());

    let digest = ContentDigest::parse(test_calibrated_digest()).unwrap();
    let projection = projection_from_entries(digest.clone(), [(1, 2, 3)]).unwrap();
    let profile = calibrated_runtime_profile(digest, projection).unwrap();
    assert_eq!(profile.context_tokens(), 8_192);
    assert_eq!(profile.batch_tokens(), 512);
    assert_eq!(profile.physical_batch_tokens(), 512);
    assert_eq!(profile.parallel_sequences(), 1);
    assert_eq!(profile.gpu_offload(), RuntimeGpuOffload::All);
    assert_eq!(profile.flash_attention(), RuntimeFlashAttention::Auto);
    assert_eq!(profile.kv_cache_precision(), RuntimeKvCachePrecision::F16);
    assert!(!profile.kv_cache_unified());
    assert_eq!(profile.sampling(), RuntimeSampling::TopKTopPTemperature);
    assert_eq!(profile.max_projected_bytes(), 20_000_000_000);
}

#[test]
fn projection_aggregates_all_entries_and_enforces_decimal_cap() {
    let digest = ContentDigest::parse(test_calibrated_digest()).unwrap();
    let projection = projection_from_entries(digest, [(10, 20, 30), (1, 2, 3)]).unwrap();
    assert_eq!(projection.weight_bytes(), 11);
    assert_eq!(projection.context_bytes(), 22);
    assert_eq!(projection.compute_bytes(), 33);
    assert!(admit_bytes(20_000_000_000).is_ok());
    assert!(matches!(
        admit_bytes(20_000_000_001),
        Err(RuntimeError::AdmissionRejected {
            projected_bytes: 20_000_000_001,
            maximum_bytes: 20_000_000_000,
        })
    ));
}

#[test]
fn calibrated_projection_contingency_rounds_up_to_five_percent() {
    assert_eq!(calibrated_contingency(18_587_496_448).unwrap(), 929_374_823);
    assert_eq!(calibrated_contingency(1).unwrap(), 256 * 1024 * 1024);
}

#[test]
fn prefill_is_bounded_and_sampling_slot_tracks_final_chunk() {
    assert_eq!(
        prefill_chunk_ranges(1_025).unwrap(),
        vec![0..512, 512..1_024, 1_024..1_025]
    );
    assert_eq!(final_prefill_sample_slot(512).unwrap(), 511);
    assert_eq!(final_prefill_sample_slot(513).unwrap(), 0);
    assert!(prefill_chunk_ranges(0).is_err());
    assert!(final_prefill_sample_slot(0).is_err());
}

#[test]
fn embedded_template_retry_is_strictly_bounded() {
    assert_eq!(bounded_template_size(4_097).unwrap(), 4_097);
    assert!(bounded_template_size(0).is_err());
    assert!(bounded_template_size(1024 * 1024 + 1).is_err());
}

#[test]
fn chat_messages_preserve_non_thinking_candidate_content_exactly() {
    let request = RuntimeRequest::new(
        vec![RuntimeMessage::new(RuntimeMessageRole::User, "analyze this").unwrap()],
        32,
    )
    .unwrap();
    assert_eq!(
        build_chat_messages(&request).unwrap(),
        vec![LlamaChatMessage::new("user".to_owned(), "analyze this".to_owned()).unwrap()]
    );
}

#[test]
fn host_admission_requires_fresh_normal_memory_facts() {
    let digest = ContentDigest::parse(test_calibrated_digest()).unwrap();
    let model = registered(digest.clone(), test_calibrated_size());
    let projection = projection_from_entries(digest, [(10, 20, 30)]).unwrap();
    let gib = 1024 * 1024 * 1024;
    let snapshot = RuntimeHostSnapshot::new(
        32 * gib,
        32 * gib,
        8 * gib,
        512 * 1024 * 1024,
        256 * 1024 * 1024,
        RuntimeMemoryPressure::Normal,
        RuntimeSwapTrend::Stable,
    )
    .unwrap();
    assert!(
        validate_host_admission(&model, &projection, snapshot, 20_000_000_000, 32 * gib,).is_ok()
    );
    let unknown_pressure = RuntimeHostSnapshot::new(
        32 * gib,
        32 * gib,
        8 * gib,
        512 * 1024 * 1024,
        256 * 1024 * 1024,
        RuntimeMemoryPressure::Unknown,
        RuntimeSwapTrend::Stable,
    )
    .unwrap();
    assert!(matches!(
        validate_host_admission(
            &model,
            &projection,
            unknown_pressure,
            20_000_000_000,
            32 * gib,
        ),
        Err(RuntimeError::AdmissionUnavailable(_))
    ));
    let rising_swap = RuntimeHostSnapshot::new(
        32 * gib,
        32 * gib,
        8 * gib,
        512 * 1024 * 1024,
        256 * 1024 * 1024,
        RuntimeMemoryPressure::Normal,
        RuntimeSwapTrend::Rising,
    )
    .unwrap();
    assert!(matches!(
        validate_host_admission(&model, &projection, rising_swap, 20_000_000_000, 32 * gib,),
        Err(RuntimeError::AdmissionUnavailable(_))
    ));
}

#[test]
fn memory_limits_require_one_positive_metal_and_one_positive_host_entry() {
    assert_eq!(
        metal_and_host_memory_limits([20_000_000_000, 32 * 1024 * 1024 * 1024]).unwrap(),
        (20_000_000_000, 32 * 1024 * 1024 * 1024)
    );
    for totals in [
        vec![],
        vec![20_000_000_000],
        vec![0, 32],
        vec![-1, 32],
        vec![1, 0],
        vec![1, -1],
        vec![1, 2, 3],
    ] {
        assert!(matches!(
            metal_and_host_memory_limits(totals),
            Err(RuntimeError::AdmissionUnavailable(_))
        ));
    }
}

#[test]
fn os_reserve_is_at_least_eight_gib_and_twenty_percent_physical() {
    let gib = 1024 * 1024 * 1024;
    assert_eq!(required_os_reserve(32 * gib), 8 * gib);
    assert_eq!(required_os_reserve(64 * gib), 13_743_895_348);
}

#[test]
fn host_admission_rejects_low_fractional_reserve_and_projection_mismatch() {
    let digest = ContentDigest::parse(test_calibrated_digest()).unwrap();
    let model = registered(digest.clone(), test_calibrated_size());
    let projection = projection_from_entries(digest, [(10, 20, 30)]).unwrap();
    let gib = 1024 * 1024 * 1024;
    let required = required_os_reserve(64 * gib);
    let low_reserve = RuntimeHostSnapshot::new(
        64 * gib,
        64 * gib,
        required - 1,
        512 * 1024 * 1024,
        256 * 1024 * 1024,
        RuntimeMemoryPressure::Normal,
        RuntimeSwapTrend::Stable,
    )
    .unwrap();
    assert!(matches!(
        validate_host_admission(&model, &projection, low_reserve, 20_000_000_000, 64 * gib,),
        Err(RuntimeError::AdmissionUnavailable(_))
    ));

    let valid_reserve = RuntimeHostSnapshot::new(
        64 * gib,
        64 * gib,
        required,
        512 * 1024 * 1024,
        256 * 1024 * 1024,
        RuntimeMemoryPressure::Normal,
        RuntimeSwapTrend::Stable,
    )
    .unwrap();
    assert!(
        validate_host_admission(&model, &projection, valid_reserve, 20_000_000_000, 64 * gib,)
            .is_ok()
    );
    assert!(matches!(
        validate_host_admission(&model, &projection, valid_reserve, 20_000_000_000, 32 * gib,),
        Err(RuntimeError::AdmissionUnavailable(_))
    ));
}

#[test]
fn host_snapshot_rejects_inconsistent_os_memory() {
    assert!(matches!(
        RuntimeHostSnapshot::new(
            1,
            2,
            0,
            0,
            0,
            RuntimeMemoryPressure::Normal,
            RuntimeSwapTrend::Stable,
        ),
        Err(RuntimeError::AdmissionUnavailable(_))
    ));
}

#[test]
fn finish_reason_remains_model_neutral() {
    assert_ne!(RuntimeFinishReason::Stop, RuntimeFinishReason::Length);
}
