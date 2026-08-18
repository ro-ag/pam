use std::{error::Error, fmt};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

const SHA256_PREFIX: &str = "sha256:";
const SHA256_HEX_LENGTH: usize = 64;
const EVIDENCE_PREFIX: &str = "evidence://";
const MAX_EVIDENCE_HANDLE_LENGTH: usize = 512;

/// An immutable, project-scoped reference to one piece of captured evidence.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct EvidenceHandle(String);

impl EvidenceHandle {
    /// Parses a canonical semantic evidence URI.
    ///
    /// # Errors
    ///
    /// Handles use lowercase path segments after `evidence://`. Empty segments,
    /// traversal markers, query text, fragments, and escaped separators are rejected.
    pub fn parse(value: impl Into<String>) -> Result<Self, InvalidEvidenceHandle> {
        let value = value.into();
        let Some(path) = value.strip_prefix(EVIDENCE_PREFIX) else {
            return Err(InvalidEvidenceHandle);
        };
        if value.len() > MAX_EVIDENCE_HANDLE_LENGTH
            || path.split('/').count() < 2
            || path.split('/').any(|segment| {
                segment.is_empty()
                    || matches!(segment, "." | "..")
                    || !segment.as_bytes().iter().all(|byte| {
                        byte.is_ascii_lowercase()
                            || byte.is_ascii_digit()
                            || matches!(byte, b'-' | b'_' | b'.' | b'~')
                    })
            })
        {
            return Err(InvalidEvidenceHandle);
        }
        Ok(Self(value))
    }

    /// Creates a collision-resistant default semantic handle.
    #[must_use]
    pub fn from_uuid(value: Uuid) -> Self {
        Self(format!("{EVIDENCE_PREFIX}pam/{}", value.hyphenated()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EvidenceHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl TryFrom<String> for EvidenceHandle {
    type Error = InvalidEvidenceHandle;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl From<EvidenceHandle> for String {
    fn from(value: EvidenceHandle) -> Self {
        value.0
    }
}

impl<'de> Deserialize<'de> for EvidenceHandle {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidEvidenceHandle;

impl fmt::Display for InvalidEvidenceHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("evidence handle must be a canonical evidence:// semantic URI")
    }
}

impl Error for InvalidEvidenceHandle {}

/// The canonical SHA-256 identity of exact evidence bytes.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ContentDigest(String);

impl ContentDigest {
    /// Constructs a digest from 32 SHA-256 bytes.
    #[must_use]
    pub fn from_sha256(bytes: [u8; 32]) -> Self {
        let mut value = String::with_capacity(SHA256_PREFIX.len() + SHA256_HEX_LENGTH);
        value.push_str(SHA256_PREFIX);
        for byte in bytes {
            use fmt::Write as _;
            write!(value, "{byte:02x}").expect("writing to a String cannot fail");
        }
        Self(value)
    }

    /// Parses a canonical lowercase `sha256:<hex>` digest.
    ///
    /// # Errors
    ///
    /// Returns an error for another algorithm, the wrong length, or non-lowercase
    /// hexadecimal text.
    pub fn parse(value: impl Into<String>) -> Result<Self, InvalidContentDigest> {
        let value = value.into();
        let Some(hex) = value.strip_prefix(SHA256_PREFIX) else {
            return Err(InvalidContentDigest);
        };
        if hex.len() != SHA256_HEX_LENGTH
            || !hex
                .as_bytes()
                .iter()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(InvalidContentDigest);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn sha256_hex(&self) -> &str {
        &self.0[SHA256_PREFIX.len()..]
    }
}

impl fmt::Display for ContentDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl TryFrom<String> for ContentDigest {
    type Error = InvalidContentDigest;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl From<ContentDigest> for String {
    fn from(value: ContentDigest) -> Self {
        value.0
    }
}

impl<'de> Deserialize<'de> for ContentDigest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidContentDigest;

impl fmt::Display for InvalidContentDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("content digest must be canonical lowercase sha256:<hex>")
    }
}

impl Error for InvalidContentDigest {}

/// A byte range in exact evidence, suitable for compacted-output provenance.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EvidenceReference {
    pub handle: EvidenceHandle,
    pub offset: u64,
    pub length: u64,
}
