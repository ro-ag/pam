#![forbid(unsafe_code)]

mod acquisition;
mod error;
mod memory;
mod model;
mod path;

#[cfg(test)]
mod acquisition_test;
#[cfg(test)]
mod memory_test;
#[cfg(test)]
mod model_test;
#[cfg(test)]
mod path_test;

pub use acquisition::{
    DownloadRequest, DownloadResponse, DownloadTransport, ImportRequest, ReqwestDownloadTransport,
    TransferRequest, download_https, import_existing,
};
pub use error::ModelError;
pub use memory::{
    HostMemoryBudget, MemoryEstimate, MemoryEstimateError, MemoryFit, RuntimeMemoryProjection,
    UnifiedWorkingSetLimit, estimate_memory,
};
pub use model::{
    GgufMetadata, LicenseConsent, LicenseSnapshot, ModelDescriptor, ModelKey, ModelSource,
    RegisteredModel,
};
pub use path::{default_model_path, validate_model_filename};
