use std::{fmt, path::PathBuf};

use pam_core::ContentDigest;
use url::Url;

use crate::ModelError;

const MAX_SEGMENT_BYTES: usize = 128;
const MAX_LICENSE_ID_BYTES: usize = 128;
const MAX_LICENSE_URL_BYTES: usize = 2048;
const MAX_SOURCE_URL_BYTES: usize = 4096;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ModelKey {
    vendor: String,
    name: String,
}

impl ModelKey {
    /// Creates a stable model identity from two filesystem-safe segments.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidModelIdentity`] when either segment is empty,
    /// too long, reserved, or contains a path separator or unsupported byte.
    pub fn new(vendor: impl Into<String>, name: impl Into<String>) -> Result<Self, ModelError> {
        let vendor = vendor.into();
        let name = name.into();
        if !valid_segment(&vendor) || !valid_segment(&name) {
            return Err(ModelError::InvalidModelIdentity);
        }
        Ok(Self { vendor, name })
    }

    #[must_use]
    pub fn vendor(&self) -> &str {
        &self.vendor
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn id(&self) -> String {
        format!("{}/{}", self.vendor, self.name)
    }
}

impl fmt::Display for ModelKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.vendor, self.name)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LicenseSnapshot {
    identifier: String,
    notice_url: String,
    notice_digest: ContentDigest,
}

impl LicenseSnapshot {
    /// Captures the exact license notice a user must accept.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidLicense`] for invalid identifiers or a notice
    /// URL that is not credential-free HTTPS.
    pub fn new(
        identifier: impl Into<String>,
        notice_url: impl Into<String>,
        notice_digest: ContentDigest,
    ) -> Result<Self, ModelError> {
        let identifier = identifier.into();
        let notice_url = notice_url.into();
        if identifier.is_empty()
            || identifier.len() > MAX_LICENSE_ID_BYTES
            || identifier.chars().any(char::is_control)
            || notice_url.len() > MAX_LICENSE_URL_BYTES
            || !safe_https_url(&notice_url)
        {
            return Err(ModelError::InvalidLicense);
        }
        Ok(Self {
            identifier,
            notice_url,
            notice_digest,
        })
    }

    #[must_use]
    pub fn identifier(&self) -> &str {
        &self.identifier
    }

    #[must_use]
    pub fn notice_url(&self) -> &str {
        &self.notice_url
    }

    #[must_use]
    pub fn notice_digest(&self) -> &ContentDigest {
        &self.notice_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LicenseConsent {
    descriptor: ModelDescriptor,
}

impl LicenseConsent {
    #[must_use]
    pub fn accept(descriptor: &ModelDescriptor) -> Self {
        Self {
            descriptor: descriptor.clone(),
        }
    }

    pub(crate) fn verify(&self, descriptor: &ModelDescriptor) -> Result<(), ModelError> {
        descriptor.validate()?;
        if self.descriptor == *descriptor {
            Ok(())
        } else {
            Err(ModelError::LicenseNotAccepted)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelDescriptor {
    pub key: ModelKey,
    pub filename: String,
    pub expected_digest: ContentDigest,
    pub expected_size_bytes: u64,
    pub license: LicenseSnapshot,
}

impl ModelDescriptor {
    /// Largest model artifact PAM will acquire or register: one tebibyte.
    pub const MAX_SIZE_BYTES: u64 = 1 << 40;
    /// Smallest possible GGUF v2/v3 fixed header.
    pub const MIN_SIZE_BYTES: u64 = 24;

    /// Defines the immutable integrity and license expectations for one GGUF.
    ///
    /// # Errors
    ///
    /// Returns an error when the filename or expected byte length is invalid.
    pub fn new(
        key: ModelKey,
        filename: impl Into<String>,
        expected_digest: ContentDigest,
        expected_size_bytes: u64,
        license: LicenseSnapshot,
    ) -> Result<Self, ModelError> {
        let descriptor = Self {
            key,
            filename: filename.into(),
            expected_digest,
            expected_size_bytes,
            license,
        };
        descriptor.validate()?;
        Ok(descriptor)
    }

    fn validate(&self) -> Result<(), ModelError> {
        crate::validate_model_filename(&self.filename)?;
        if !(Self::MIN_SIZE_BYTES..=Self::MAX_SIZE_BYTES).contains(&self.expected_size_bytes) {
            return Err(ModelError::InvalidContentLength);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ModelSource {
    Local,
    Https { canonical_url: String },
}

impl ModelSource {
    /// Creates a canonical, credential-free HTTPS provenance identity.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidSource`] when the URL is not canonical HTTPS
    /// or includes credentials, a query, or a fragment.
    pub fn https(canonical_url: impl Into<String>) -> Result<Self, ModelError> {
        let canonical_url = canonical_url.into();
        if !safe_canonical_source_url(&canonical_url) {
            return Err(ModelError::InvalidSource);
        }
        Ok(Self::Https { canonical_url })
    }

    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Https { .. } => "https",
        }
    }

    #[must_use]
    pub fn identity(&self) -> Option<&str> {
        match self {
            Self::Local => None,
            Self::Https { canonical_url } => Some(canonical_url),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GgufMetadata {
    pub version: u32,
    pub tensor_count: u64,
    pub metadata_kv_count: u64,
}

impl GgufMetadata {
    pub const MIN_TENSOR_COUNT: u64 = 1;
    pub const MAX_TENSOR_COUNT: u64 = 131_072;
    pub const MAX_METADATA_KV_COUNT: u64 = 65_536;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisteredModel {
    pub key: ModelKey,
    pub path: PathBuf,
    pub digest: ContentDigest,
    pub size_bytes: u64,
    pub gguf: GgufMetadata,
    pub license: LicenseSnapshot,
    pub source: ModelSource,
    pub registered_at_ms: u64,
}

pub(crate) fn valid_segment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SEGMENT_BYTES
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn safe_https_url(value: &str) -> bool {
    Url::parse(value).is_ok_and(|url| {
        url.as_str() == value
            && url.scheme() == "https"
            && !url.cannot_be_a_base()
            && url.has_authority()
            && url.host_str().is_some()
            && url.port_or_known_default() == Some(443)
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
    })
}

fn safe_canonical_source_url(value: &str) -> bool {
    value.len() <= MAX_SOURCE_URL_BYTES
        && Url::parse(value).is_ok_and(|url| {
            url.as_str() == value
                && url.scheme() == "https"
                && !url.cannot_be_a_base()
                && url.has_authority()
                && url.host_str().is_some()
                && url.port_or_known_default() == Some(443)
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
        })
}
