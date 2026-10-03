//! What an imported CA bundle may contain, and the normalized form PAM
//! keeps of it.
//!
//! A CA bundle is an import, not a path: the daemon reads the file the
//! human named once, passes its text through [`normalize_pem`], and from
//! then on points curl at its own private copy of the result. This module
//! owns the content rule; the file checks, the private copy and its digest
//! are the daemon's (`pam_daemon::network_service`).
//!
//! The rule is small and deliberately not an X.509 parser: a bundle is
//! accepted when it holds at least one `CERTIFICATE` block whose base64
//! decodes to DER (a SEQUENCE, so the first byte is `0x30`), and refused
//! whole when any block is a private key — PAM needs only certificates and
//! a key pasted by mistake must not be copied into a second place. Expiry
//! and chain problems are the Test action's to surface.

use std::fmt;

/// The most bytes a bundle source may have: enterprise bundles are tens of
/// kilobytes; four mebibytes leaves room for every public root as well.
pub const MAX_BUNDLE_BYTES: u64 = 4 * 1024 * 1024;

/// The most certificate blocks a bundle may hold.
pub const MAX_CERTIFICATES: usize = 512;

/// Why a bundle was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaError {
    /// The text is not UTF-8.
    NotText,
    /// No `CERTIFICATE` block was found.
    NoCertificate,
    /// A `PRIVATE KEY` block (plain, encrypted, RSA or EC) is present.
    PrivateKey,
    /// A `CERTIFICATE` block's base64 does not decode, or decodes to
    /// something that is not DER.
    Malformed {
        /// Which block, counting from one.
        index: usize,
    },
    /// A `BEGIN` line has no matching `END`, or the labels differ.
    Unterminated {
        /// The label of the open block.
        label: String,
    },
    /// More than [`MAX_CERTIFICATES`] blocks.
    TooMany,
}

impl fmt::Display for CaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotText => formatter.write_str("the file is not UTF-8 text (a PEM bundle is)"),
            Self::NoCertificate => formatter.write_str(
                "the file holds no -----BEGIN CERTIFICATE----- block; PAM needs a PEM bundle of \
                 certificates",
            ),
            Self::PrivateKey => formatter.write_str(
                "this file holds a private key; PAM needs only certificates, so nothing was \
                 imported",
            ),
            Self::Malformed { index } => write!(
                formatter,
                "certificate block {index} is not valid: its base64 does not decode to a DER \
                 certificate"
            ),
            Self::Unterminated { label } => write!(
                formatter,
                "a -----BEGIN {label}----- block has no matching END line"
            ),
            Self::TooMany => write!(
                formatter,
                "the file holds more than {MAX_CERTIFICATES} certificate blocks"
            ),
        }
    }
}

impl std::error::Error for CaError {}

/// A bundle reduced to its certificate blocks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedBundle {
    /// The PEM text PAM keeps: one `CERTIFICATE` block after another, each
    /// re-wrapped at 64 columns with `\n` line ends, nothing else.
    pub pem: String,
    /// How many certificate blocks it holds.
    pub certificates: usize,
}

/// Reduces a PEM bundle to its certificate blocks, refusing what cannot
/// be a bundle of certificates.
///
/// Comments, headers, blank lines and text between blocks are dropped:
/// curl ignores them too, and the private copy should hold exactly what
/// matters so its digest means "these certificates". Blocks of other kinds
/// (`TRUSTED CERTIFICATE`, `X509 CRL`, `CERTIFICATE REQUEST`) are dropped
/// as well; any kind of private key refuses the whole file.
///
/// # Errors
///
/// [`CaError`] names what was wrong; nothing is partially accepted.
pub fn normalize_pem(bytes: &[u8]) -> Result<NormalizedBundle, CaError> {
    let text = std::str::from_utf8(bytes).map_err(|_| CaError::NotText)?;
    let mut pem = String::new();
    let mut certificates = 0;
    let mut open: Option<(String, String)> = None;
    for raw in text.lines() {
        let line = raw.trim();
        if let Some(label) = begin_label(line) {
            if is_private_key(label) {
                return Err(CaError::PrivateKey);
            }
            if let Some((label, _)) = open.take() {
                return Err(CaError::Unterminated { label });
            }
            open = Some((label.to_owned(), String::new()));
            continue;
        }
        if let Some(label) = end_label(line) {
            let Some((opened, body)) = open.take() else {
                // An END with no BEGIN is stray text; curl skips it too.
                continue;
            };
            if opened != label {
                return Err(CaError::Unterminated { label: opened });
            }
            if opened != "CERTIFICATE" {
                continue;
            }
            certificates += 1;
            if certificates > MAX_CERTIFICATES {
                return Err(CaError::TooMany);
            }
            let der = decode_base64(&body).ok_or(CaError::Malformed {
                index: certificates,
            })?;
            // DER begins with a SEQUENCE tag; anything else is not a
            // certificate, whatever its label says.
            if der.first() != Some(&0x30) {
                return Err(CaError::Malformed {
                    index: certificates,
                });
            }
            pem.push_str("-----BEGIN CERTIFICATE-----\n");
            for chunk in body.as_bytes().chunks(64) {
                // `body` holds only base64 characters, so each chunk is
                // ASCII and the conversion cannot fail.
                pem.push_str(std::str::from_utf8(chunk).unwrap_or_default());
                pem.push('\n');
            }
            pem.push_str("-----END CERTIFICATE-----\n");
            continue;
        }
        if let Some((_, body)) = open.as_mut() {
            // RFC 7468 allows explanatory headers before the data; a line
            // with a colon is one. Everything else must be base64.
            if line.is_empty() || line.contains(':') {
                continue;
            }
            body.push_str(line);
        }
    }
    if let Some((label, _)) = open {
        return Err(CaError::Unterminated { label });
    }
    if certificates == 0 {
        return Err(CaError::NoCertificate);
    }
    Ok(NormalizedBundle { pem, certificates })
}

/// The label of a `-----BEGIN <label>-----` line, trimmed.
fn begin_label(line: &str) -> Option<&str> {
    line.strip_prefix("-----BEGIN ")
        .and_then(|rest| rest.strip_suffix("-----"))
        .map(str::trim)
}

/// The label of a `-----END <label>-----` line, trimmed.
fn end_label(line: &str) -> Option<&str> {
    line.strip_prefix("-----END ")
        .and_then(|rest| rest.strip_suffix("-----"))
        .map(str::trim)
}

/// Whether a PEM label names key material of any kind.
fn is_private_key(label: &str) -> bool {
    label.to_ascii_uppercase().contains("PRIVATE KEY")
}

/// Standard base64 (RFC 4648, `+` and `/`, `=` padding) to bytes; `None`
/// when a character is not base64 or the length does not work out. Small
/// on purpose: the workspace carries no base64 crate and a bundle is the
/// only thing this crate decodes.
#[must_use]
pub fn decode_base64(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if bytes.is_empty() || !bytes.len().is_multiple_of(4) {
        return None;
    }
    let value = |byte: u8| -> Option<u32> {
        match byte {
            b'A'..=b'Z' => Some(u32::from(byte - b'A')),
            b'a'..=b'z' => Some(u32::from(byte - b'a') + 26),
            b'0'..=b'9' => Some(u32::from(byte - b'0') + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    };
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for (index, quad) in bytes.chunks(4).enumerate() {
        let last = index + 1 == bytes.len() / 4;
        let padding = quad.iter().rev().take_while(|byte| **byte == b'=').count();
        if padding > 2 || (padding > 0 && !last) {
            return None;
        }
        let mut word = 0u32;
        for byte in &quad[..4 - padding] {
            word = (word << 6) | value(*byte)?;
        }
        word <<= 6 * padding;
        let octets = word.to_be_bytes();
        out.extend_from_slice(&octets[1..4 - padding]);
    }
    Some(out)
}
