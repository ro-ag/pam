use std::path::PathBuf;

use pam_core::ContentDigest;

use crate::{
    GgufMetadata, HostMemoryBudget, LicenseSnapshot, MemoryEstimateError, MemoryFit, ModelSource,
    RegisteredModel, RuntimeMemoryProjection, UnifiedWorkingSetLimit, estimate_memory,
};

const GIB: u64 = 1024 * 1024 * 1024;

fn digest(byte: u8) -> ContentDigest {
    ContentDigest::from_sha256([byte; 32])
}

fn model(size_bytes: u64) -> RegisteredModel {
    RegisteredModel {
        key: crate::ModelKey::new("qwen", "qwen3.6-35b").unwrap(),
        path: PathBuf::from("/models/qwen.gguf"),
        digest: digest(1),
        size_bytes,
        gguf: GgufMetadata {
            version: 3,
            tensor_count: 733,
            metadata_kv_count: 54,
        },
        license: LicenseSnapshot::new("Apache-2.0", "https://example.test/license", digest(2))
            .unwrap(),
        source: ModelSource::Local,
        registered_at_ms: 1,
    }
}

fn projection() -> RuntimeMemoryProjection {
    RuntimeMemoryProjection::new(digest(1), 4_096, 1_000, 64, 100).unwrap()
}

#[test]
fn estimate_reports_exact_components_and_exact_fit() {
    let model = model(900);
    let host = HostMemoryBudget::new(
        2_000,
        1_420,
        UnifiedWorkingSetLimit::NotApplicable,
        128,
        64,
        64,
    )
    .unwrap();

    let estimate = estimate_memory(&model, &projection(), host).unwrap();

    assert_eq!(estimate.allocated_context_tokens, 4_096);
    assert_eq!(estimate.artifact_size_bytes, 900);
    assert_eq!(estimate.weight_bytes, 1_000);
    assert_eq!(estimate.context_bytes, 64);
    assert_eq!(estimate.compute_bytes, 100);
    assert_eq!(estimate.runtime_required_bytes, 1_164);
    assert_eq!(estimate.model_working_set_bytes, 1_292);
    assert_eq!(estimate.required_with_headroom_bytes, 1_420);
    assert_eq!(estimate.physical_capacity_for_model_bytes, 1_744);
    assert_eq!(estimate.currently_available_for_model_bytes, 1_164);
    assert_eq!(estimate.fit, MemoryFit::Fits { spare_bytes: 0 });
}

#[test]
fn estimate_distinguishes_spare_transient_shortfall_and_capacity_shortfall() {
    let model = model(900);
    let one_byte_spare = HostMemoryBudget::new(
        2_000,
        1_421,
        UnifiedWorkingSetLimit::NotApplicable,
        256,
        0,
        0,
    )
    .unwrap();
    let one_byte_short = HostMemoryBudget::new(
        2_000,
        1_419,
        UnifiedWorkingSetLimit::NotApplicable,
        256,
        0,
        0,
    )
    .unwrap();
    let physical_short = HostMemoryBudget::new(
        1_419,
        1_419,
        UnifiedWorkingSetLimit::NotApplicable,
        256,
        0,
        0,
    )
    .unwrap();

    assert_eq!(
        estimate_memory(&model, &projection(), one_byte_spare)
            .unwrap()
            .fit,
        MemoryFit::Fits { spare_bytes: 1 }
    );
    assert_eq!(
        estimate_memory(&model, &projection(), one_byte_short)
            .unwrap()
            .fit,
        MemoryFit::InsufficientAvailable { shortfall_bytes: 1 }
    );
    assert_eq!(
        estimate_memory(&model, &projection(), physical_short)
            .unwrap()
            .fit,
        MemoryFit::InsufficientCapacity { shortfall_bytes: 1 }
    );
}

#[test]
fn unified_working_set_limit_is_an_independent_fail_closed_gate() {
    let model = model(900);
    let host =
        HostMemoryBudget::new(4_000, 4_000, UnifiedWorkingSetLimit::Known(1_163), 0, 0, 0).unwrap();

    assert_eq!(
        estimate_memory(&model, &projection(), host).unwrap().fit,
        MemoryFit::InsufficientWorkingSet { shortfall_bytes: 1 }
    );
}

#[test]
fn unknown_required_working_set_limit_fails_closed() {
    let host =
        HostMemoryBudget::new(4_000, 4_000, UnifiedWorkingSetLimit::Unknown, 0, 0, 0).unwrap();

    assert_eq!(
        estimate_memory(&model(900), &projection(), host),
        Err(MemoryEstimateError::UnknownWorkingSetLimit)
    );
}

#[test]
fn fit_spare_uses_the_tightest_unified_or_host_constraint() {
    let model = model(900);
    let host =
        HostMemoryBudget::new(4_000, 4_000, UnifiedWorkingSetLimit::Known(1_174), 0, 5, 5).unwrap();

    assert_eq!(
        estimate_memory(&model, &projection(), host).unwrap().fit,
        MemoryFit::Fits { spare_bytes: 0 }
    );
}

#[test]
fn reserve_above_live_availability_reports_shortfall_without_underflow() {
    let estimate = estimate_memory(
        &model(900),
        &projection(),
        HostMemoryBudget::new(2_000, 200, UnifiedWorkingSetLimit::NotApplicable, 256, 0, 0)
            .unwrap(),
    )
    .unwrap();

    assert_eq!(estimate.currently_available_for_model_bytes, 0);
    assert_eq!(
        estimate.fit,
        MemoryFit::InsufficientAvailable {
            shortfall_bytes: 1_164
        }
    );
}

#[test]
fn projection_digest_model_and_host_invariants_are_enforced() {
    assert_eq!(
        RuntimeMemoryProjection::new(digest(1), 0, 1, 1, 1),
        Err(MemoryEstimateError::InvalidProjection)
    );
    assert_eq!(
        RuntimeMemoryProjection::new(digest(1), 1, 0, 1, 1),
        Err(MemoryEstimateError::InvalidProjection)
    );
    assert_eq!(
        HostMemoryBudget::new(0, 0, UnifiedWorkingSetLimit::NotApplicable, 0, 0, 0),
        Err(MemoryEstimateError::InvalidHostMemory)
    );
    assert_eq!(
        HostMemoryBudget::new(100, 101, UnifiedWorkingSetLimit::NotApplicable, 0, 0, 0),
        Err(MemoryEstimateError::InvalidHostMemory)
    );
    assert_eq!(
        HostMemoryBudget::new(100, 50, UnifiedWorkingSetLimit::NotApplicable, 101, 0, 0),
        Err(MemoryEstimateError::InvalidHostMemory)
    );
    assert_eq!(
        HostMemoryBudget::new(100, 50, UnifiedWorkingSetLimit::Known(0), 0, 0, 0),
        Err(MemoryEstimateError::InvalidHostMemory)
    );
    assert_eq!(
        estimate_memory(
            &model(900),
            &RuntimeMemoryProjection::new(digest(9), 1, 1, 1, 1).unwrap(),
            HostMemoryBudget::new(
                10_000,
                10_000,
                UnifiedWorkingSetLimit::NotApplicable,
                0,
                0,
                0,
            )
            .unwrap(),
        ),
        Err(MemoryEstimateError::DigestMismatch)
    );
    assert_eq!(
        estimate_memory(
            &model(0),
            &projection(),
            HostMemoryBudget::new(
                10_000,
                10_000,
                UnifiedWorkingSetLimit::NotApplicable,
                0,
                0,
                0,
            )
            .unwrap(),
        ),
        Err(MemoryEstimateError::InvalidModelSize)
    );
}

#[test]
fn checked_component_and_headroom_arithmetic_reject_overflow() {
    let host = HostMemoryBudget::new(
        u64::MAX,
        u64::MAX,
        UnifiedWorkingSetLimit::NotApplicable,
        0,
        0,
        0,
    )
    .unwrap();
    let component_overflow = RuntimeMemoryProjection::new(digest(1), 1, u64::MAX, 1, 0).unwrap();
    let headroom_overflow_host = HostMemoryBudget::new(
        u64::MAX,
        u64::MAX,
        UnifiedWorkingSetLimit::NotApplicable,
        u64::MAX,
        1,
        0,
    )
    .unwrap();

    assert_eq!(
        estimate_memory(&model(900), &component_overflow, host),
        Err(MemoryEstimateError::ArithmeticOverflow)
    );
    assert_eq!(
        estimate_memory(&model(900), &projection(), headroom_overflow_host),
        Err(MemoryEstimateError::ArithmeticOverflow)
    );
}

#[test]
fn pinned_q6_projection_is_not_a_32_gib_candidate_with_os_headroom() {
    let q6 = model(31_843_777_504);
    let pinned_projection =
        RuntimeMemoryProjection::new(digest(1), 512, 31_832_787_456, 76_349_440, 526_424_128)
            .unwrap();
    let target_scenario = HostMemoryBudget::new(
        32 * GIB,
        32 * GIB,
        UnifiedWorkingSetLimit::NotApplicable,
        6 * GIB,
        0,
        0,
    )
    .unwrap();

    assert!(matches!(
        estimate_memory(&q6, &pinned_projection, target_scenario)
            .unwrap()
            .fit,
        MemoryFit::InsufficientCapacity { .. }
    ));
}
