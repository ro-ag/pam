#![forbid(unsafe_code)]

mod acquisition;
mod error;
#[cfg(target_os = "macos")]
mod llama_cpp_macos;
mod memory;
mod model;
mod path;
mod runtime;

#[cfg(test)]
mod acquisition_test;
#[cfg(all(test, target_os = "macos"))]
mod llama_cpp_macos_test;
#[cfg(test)]
mod memory_test;
#[cfg(test)]
mod model_test;
#[cfg(test)]
mod path_test;
#[cfg(test)]
mod runtime_test;

pub use acquisition::{
    DownloadRequest, DownloadResponse, DownloadTransport, ImportRequest, ReqwestDownloadTransport,
    TransferRequest, download_https, import_existing, revalidate_registered_model,
};
pub use error::ModelError;
#[cfg(target_os = "macos")]
pub use llama_cpp_macos::MacosLlamaCppRuntime;
pub use memory::{
    HostMemoryBudget, MemoryEstimate, MemoryEstimateError, MemoryFit, RuntimeMemoryProjection,
    UnifiedWorkingSetLimit, estimate_memory,
};
pub use model::{
    GgufMetadata, LicenseConsent, LicenseSnapshot, ModelDescriptor, ModelKey, ModelSource,
    RegisteredModel,
};
pub use path::{default_model_path, validate_model_filename};
pub use runtime::{
    CancellationSignal, CancellationToken, ModelRuntime, RuntimeError, RuntimeFinishReason,
    RuntimeFlashAttention, RuntimeGpuOffload, RuntimeHostAdmission, RuntimeHostSnapshot,
    RuntimeKvCachePrecision, RuntimeMemoryPressure, RuntimeMessage, RuntimeMessageRole,
    RuntimeProfile, RuntimeRequest, RuntimeResponse, RuntimeSampling, RuntimeSwapTrend,
    RuntimeUsage,
};
