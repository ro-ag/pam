use std::{error::Error, fmt};

use pam_core::ContentDigest;

use crate::{ModelDescriptor, RegisteredModel};

/// Runtime-produced memory projection for one exact artifact and context.
///
/// The selected model runtime owns architecture-specific KV, recurrent-state,
/// cache-precision, batch, flash-attention, and offload calculations. PAM keeps
/// only their model-neutral component totals and binds them to the exact model
/// digest. A separate projection is required for every runtime configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeMemoryProjection {
    model_digest: ContentDigest,
    allocated_context_tokens: u32,
    weight_bytes: u64,
    context_bytes: u64,
    compute_bytes: u64,
}

impl RuntimeMemoryProjection {
    /// Creates a projection from a selected runtime's no-allocation query.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryEstimateError::InvalidProjection`] when context or
    /// projected weight bytes are zero.
    pub fn new(
        model_digest: ContentDigest,
        allocated_context_tokens: u32,
        weight_bytes: u64,
        context_bytes: u64,
        compute_bytes: u64,
    ) -> Result<Self, MemoryEstimateError> {
        if allocated_context_tokens == 0 || weight_bytes == 0 {
            return Err(MemoryEstimateError::InvalidProjection);
        }
        Ok(Self {
            model_digest,
            allocated_context_tokens,
            weight_bytes,
            context_bytes,
            compute_bytes,
        })
    }

    #[must_use]
    pub fn model_digest(&self) -> &ContentDigest {
        &self.model_digest
    }

    #[must_use]
    pub fn allocated_context_tokens(&self) -> u32 {
        self.allocated_context_tokens
    }

    #[must_use]
    pub fn weight_bytes(&self) -> u64 {
        self.weight_bytes
    }

    #[must_use]
    pub fn context_bytes(&self) -> u64 {
        self.context_bytes
    }

    #[must_use]
    pub fn compute_bytes(&self) -> u64 {
        self.compute_bytes
    }
}

/// Availability of an accelerator working-set limit on a unified-memory host.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnifiedWorkingSetLimit {
    /// This host/runtime has no unified accelerator working-set constraint.
    NotApplicable,
    /// The platform reported the limit in bytes.
    Known(u64),
    /// The host requires the limit, but the platform query failed.
    Unknown,
}

/// Volatile host-memory facts and caller-selected headroom inputs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostMemoryBudget {
    total: u64,
    available: u64,
    unified_working_set_limit: UnifiedWorkingSetLimit,
    reserved_os: u64,
    reserved_application: u64,
    projection_contingency: u64,
}

impl HostMemoryBudget {
    /// Creates a host budget without choosing a product headroom policy.
    ///
    /// The reserve may exceed currently available memory. That is a valid
    /// snapshot which produces a transient shortfall rather than underflowing.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryEstimateError::InvalidHostMemory`] when total memory is
    /// zero, available memory exceeds total memory, the reserve exceeds total
    /// memory, or a known working-set limit is zero. An unknown limit is a
    /// valid failed-query snapshot that [`estimate_memory`] rejects.
    pub fn new(
        total_bytes: u64,
        available_bytes: u64,
        unified_working_set_limit: UnifiedWorkingSetLimit,
        reserved_os_bytes: u64,
        reserved_application_bytes: u64,
        projection_contingency_bytes: u64,
    ) -> Result<Self, MemoryEstimateError> {
        if total_bytes == 0
            || available_bytes > total_bytes
            || reserved_os_bytes > total_bytes
            || matches!(unified_working_set_limit, UnifiedWorkingSetLimit::Known(0))
        {
            return Err(MemoryEstimateError::InvalidHostMemory);
        }
        Ok(Self {
            total: total_bytes,
            available: available_bytes,
            unified_working_set_limit,
            reserved_os: reserved_os_bytes,
            reserved_application: reserved_application_bytes,
            projection_contingency: projection_contingency_bytes,
        })
    }

    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.total
    }

    #[must_use]
    pub fn available_bytes(&self) -> u64 {
        self.available
    }

    #[must_use]
    pub fn unified_working_set_limit(&self) -> UnifiedWorkingSetLimit {
        self.unified_working_set_limit
    }

    #[must_use]
    pub fn reserved_os_bytes(&self) -> u64 {
        self.reserved_os
    }

    #[must_use]
    pub fn reserved_application_bytes(&self) -> u64 {
        self.reserved_application
    }

    #[must_use]
    pub fn projection_contingency_bytes(&self) -> u64 {
        self.projection_contingency
    }
}

/// Whether the projected runtime allocation fits the physical and live budget.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryFit {
    /// The allocation fits while preserving the requested OS reserve.
    Fits { spare_bytes: u64 },
    /// The allocation cannot fit in physical memory with the requested reserve.
    InsufficientCapacity { shortfall_bytes: u64 },
    /// The projected allocation exceeds a unified accelerator working-set cap.
    InsufficientWorkingSet { shortfall_bytes: u64 },
    /// It can fit physically, but the current availability snapshot is too low.
    InsufficientAvailable { shortfall_bytes: u64 },
}

/// Checked component breakdown for one runtime projection and host snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryEstimate {
    pub allocated_context_tokens: u32,
    pub artifact_size_bytes: u64,
    pub weight_bytes: u64,
    pub context_bytes: u64,
    pub compute_bytes: u64,
    pub runtime_required_bytes: u64,
    pub reserved_application_bytes: u64,
    pub projection_contingency_bytes: u64,
    pub model_working_set_bytes: u64,
    pub reserved_os_bytes: u64,
    pub required_with_headroom_bytes: u64,
    pub physical_capacity_for_model_bytes: u64,
    pub currently_available_for_model_bytes: u64,
    pub fit: MemoryFit,
}

/// Typed failures for invalid or unrepresentable memory estimates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryEstimateError {
    InvalidProjection,
    DigestMismatch,
    InvalidModelSize,
    InvalidHostMemory,
    UnknownWorkingSetLimit,
    ArithmeticOverflow,
}

impl fmt::Display for MemoryEstimateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidProjection => "runtime memory projection is invalid",
            Self::DigestMismatch => "runtime memory projection does not match the artifact",
            Self::InvalidModelSize => "registered model size is invalid",
            Self::InvalidHostMemory => "host memory budget is invalid",
            Self::UnknownWorkingSetLimit => {
                "unified-memory working-set limit is required but unknown"
            }
            Self::ArithmeticOverflow => "model memory estimate overflowed",
        })
    }
}

impl Error for MemoryEstimateError {}

/// Applies explicit OS headroom to a runtime-owned component projection.
///
/// This function does not derive KV cost from generic GGUF metadata or assume
/// that file size equals resident weight memory. Host availability is a
/// volatile admission snapshot, not a reservation or target-machine benchmark.
///
/// # Errors
///
/// Returns an error for a mismatched artifact, invalid model size, an unknown
/// required working-set limit, or checked-arithmetic overflow.
pub fn estimate_memory(
    model: &RegisteredModel,
    projection: &RuntimeMemoryProjection,
    host: HostMemoryBudget,
) -> Result<MemoryEstimate, MemoryEstimateError> {
    if model.digest != projection.model_digest {
        return Err(MemoryEstimateError::DigestMismatch);
    }
    if !(ModelDescriptor::MIN_SIZE_BYTES..=ModelDescriptor::MAX_SIZE_BYTES)
        .contains(&model.size_bytes)
    {
        return Err(MemoryEstimateError::InvalidModelSize);
    }
    let unified_working_set_limit = match host.unified_working_set_limit {
        UnifiedWorkingSetLimit::NotApplicable => None,
        UnifiedWorkingSetLimit::Known(limit) => Some(limit),
        UnifiedWorkingSetLimit::Unknown => {
            return Err(MemoryEstimateError::UnknownWorkingSetLimit);
        }
    };

    let runtime_required_bytes = projection
        .weight_bytes
        .checked_add(projection.context_bytes)
        .and_then(|value| value.checked_add(projection.compute_bytes))
        .ok_or(MemoryEstimateError::ArithmeticOverflow)?;
    let model_working_set_bytes = runtime_required_bytes
        .checked_add(host.reserved_application)
        .and_then(|value| value.checked_add(host.projection_contingency))
        .ok_or(MemoryEstimateError::ArithmeticOverflow)?;
    let required_with_headroom_bytes = model_working_set_bytes
        .checked_add(host.reserved_os)
        .ok_or(MemoryEstimateError::ArithmeticOverflow)?;
    let physical_capacity_for_model_bytes = host
        .total
        .saturating_sub(host.reserved_os)
        .saturating_sub(host.reserved_application)
        .saturating_sub(host.projection_contingency);
    let currently_available_for_model_bytes = host
        .available
        .saturating_sub(host.reserved_os)
        .saturating_sub(host.reserved_application)
        .saturating_sub(host.projection_contingency);

    let working_set_shortfall = unified_working_set_limit
        .and_then(|limit| model_working_set_bytes.checked_sub(limit))
        .filter(|shortfall| *shortfall > 0);
    let fit = if let Some(shortfall_bytes) = working_set_shortfall {
        MemoryFit::InsufficientWorkingSet { shortfall_bytes }
    } else if runtime_required_bytes > physical_capacity_for_model_bytes {
        MemoryFit::InsufficientCapacity {
            shortfall_bytes: runtime_required_bytes - physical_capacity_for_model_bytes,
        }
    } else if runtime_required_bytes > currently_available_for_model_bytes {
        MemoryFit::InsufficientAvailable {
            shortfall_bytes: runtime_required_bytes - currently_available_for_model_bytes,
        }
    } else {
        let available_spare = currently_available_for_model_bytes - runtime_required_bytes;
        let working_set_spare =
            unified_working_set_limit.map_or(u64::MAX, |limit| limit - model_working_set_bytes);
        MemoryFit::Fits {
            spare_bytes: available_spare.min(working_set_spare),
        }
    };

    Ok(MemoryEstimate {
        allocated_context_tokens: projection.allocated_context_tokens,
        artifact_size_bytes: model.size_bytes,
        weight_bytes: projection.weight_bytes,
        context_bytes: projection.context_bytes,
        compute_bytes: projection.compute_bytes,
        runtime_required_bytes,
        reserved_application_bytes: host.reserved_application,
        projection_contingency_bytes: host.projection_contingency,
        model_working_set_bytes,
        reserved_os_bytes: host.reserved_os,
        required_with_headroom_bytes,
        physical_capacity_for_model_bytes,
        currently_available_for_model_bytes,
        fit,
    })
}
