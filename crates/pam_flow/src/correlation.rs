//! Precollection revision targets. These are expectations, not proof of product
//! association. Repository identity is conservative HTTPS: host case and port
//! 443 normalize, while path case and `.git` remain significant. SSH/SCP, URL
//! credentials, escaped paths and inferred transport equivalence are unsupported.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{ArgValue, Input, Vars};

/// An optional flow declaration, resolved exactly once before collection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Correlation {
    pub repository: String,
    pub commit: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pull_request: Option<ArgValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pull_request_head: Option<String>,
}

/// Canonical expected identity to freeze in the daemon's durable request state.
/// Deserializing persisted data must be followed by [`Self::validate`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorrelationTarget {
    pub repository: String,
    pub commit: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pull_request: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pull_request_head: Option<String>,
}

/// Invalid declarations/values never include their potentially sensitive contents.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("correlation.{field}: {message}")]
pub struct CorrelationError {
    pub field: &'static str,
    pub message: &'static str,
}

fn invalid(field: &'static str, message: &'static str) -> CorrelationError {
    CorrelationError { field, message }
}

impl Correlation {
    /// Plain references needed before collection; no step outputs are permitted.
    #[must_use]
    pub fn references(&self) -> Vec<String> {
        let mut found = crate::references(&self.repository);
        found.extend(crate::references(&self.commit));
        if let Some(ArgValue::Text(text)) = &self.pull_request {
            found.extend(crate::references(text));
        }
        if let Some(text) = &self.pull_request_head {
            found.extend(crate::references(text));
        }
        found
    }

    /// Resolve whole-value references once, then validate every resulting value.
    pub fn resolve(&self, vars: &Vars) -> Result<CorrelationTarget, CorrelationError> {
        paired(
            self.pull_request.is_some(),
            self.pull_request_head.is_some(),
        )?;
        let repository =
            canonical_repository_url(&resolve_value(&self.repository, "repository", vars)?)?;
        let commit = validate_full_commit(&resolve_value(&self.commit, "commit", vars)?)?;
        let pull_request = self
            .pull_request
            .as_ref()
            .map(|value| positive_pr(&resolve_value(&value.to_string(), "pull_request", vars)?))
            .transpose()?;
        let pull_request_head = self
            .pull_request_head
            .as_ref()
            .map(|value| {
                validate_full_commit(&resolve_value(value, "pull_request_head", vars)?)
                    .map_err(|error| invalid("pull_request_head", error.message))
            })
            .transpose()?;
        Ok(CorrelationTarget {
            repository,
            commit,
            pull_request,
            pull_request_head,
        })
    }

    pub(crate) fn validated(
        mut self,
        inputs: &BTreeMap<String, Input>,
    ) -> Result<Self, CorrelationError> {
        paired(
            self.pull_request.is_some(),
            self.pull_request_head.is_some(),
        )?;
        self.repository = declaration(
            &self.repository,
            "repository",
            inputs,
            canonical_repository_url,
        )?;
        self.commit = declaration(&self.commit, "commit", inputs, validate_full_commit)?;
        if let Some(head) = &self.pull_request_head {
            self.pull_request_head = Some(declaration(
                head,
                "pull_request_head",
                inputs,
                validate_full_commit,
            )?);
        }
        if let Some(pr) = &self.pull_request {
            let text = pr.to_string();
            let normalized = declaration(&text, "pull_request", inputs, |text| {
                positive_pr(text).map(|number| number.to_string())
            })?;
            self.pull_request = Some(if normalized.starts_with("${") {
                ArgValue::Text(normalized)
            } else {
                ArgValue::Int(normalized.parse().expect("validated bounded PR number"))
            });
        }
        Ok(self)
    }
}

impl CorrelationTarget {
    /// Reject noncanonical persisted values and incomplete PR identity pairs.
    pub fn validate(&self) -> Result<(), CorrelationError> {
        paired(
            self.pull_request.is_some(),
            self.pull_request_head.is_some(),
        )?;
        if canonical_repository_url(&self.repository)? != self.repository {
            return Err(invalid(
                "repository",
                "persisted repository is not canonical",
            ));
        }
        if validate_full_commit(&self.commit)? != self.commit {
            return Err(invalid("commit", "persisted commit is not canonical"));
        }
        if let Some(pr) = self.pull_request {
            positive_pr(&pr.to_string())?;
        }
        if let Some(head) = &self.pull_request_head
            && validate_full_commit(head)
                .map_err(|error| invalid("pull_request_head", error.message))?
                != *head
        {
            return Err(invalid(
                "pull_request_head",
                "persisted head is not canonical",
            ));
        }
        Ok(())
    }
}

fn paired(pr: bool, head: bool) -> Result<(), CorrelationError> {
    if pr != head {
        return Err(invalid(
            "pull_request",
            "pull_request and pull_request_head must appear together",
        ));
    }
    Ok(())
}

fn positive_pr(text: &str) -> Result<u64, CorrelationError> {
    if text.is_empty() || text.len() > 19 || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid(
            "pull_request",
            "expected a positive integer PR number",
        ));
    }
    text.parse::<u64>()
        .ok()
        .filter(|value| *value > 0 && i64::try_from(*value).is_ok())
        .ok_or_else(|| {
            invalid(
                "pull_request",
                "PR number is outside the supported integer range",
            )
        })
}

fn reference<'a>(text: &'a str, field: &'static str) -> Result<Option<&'a str>, CorrelationError> {
    if text.is_empty() || text.len() > 4096 {
        return Err(invalid(
            field,
            "expected a nonempty value of at most 4096 bytes",
        ));
    }
    if !text.contains("${") {
        return Ok(None);
    }
    let key = text
        .strip_prefix("${")
        .and_then(|text| text.strip_suffix('}'))
        .filter(|key| !key.contains(['{', '}']))
        .ok_or_else(|| invalid(field, "only one whole-value reference is allowed"))?;
    let input = key.strip_prefix("inputs.").is_some_and(|name| {
        !name.is_empty()
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    });
    if !input && !matches!(key, "repo.path" | "repo.name" | "repo.origin") {
        return Err(invalid(
            field,
            "only declared inputs and existing repo references are allowed",
        ));
    }
    Ok(Some(key))
}

fn resolve_value(text: &str, field: &'static str, vars: &Vars) -> Result<String, CorrelationError> {
    match reference(text, field)? {
        Some(key) => vars
            .resolve(key)
            .ok_or_else(|| invalid(field, "precollection reference has no value")),
        None => Ok(text.to_owned()),
    }
}

fn declaration(
    text: &str,
    field: &'static str,
    inputs: &BTreeMap<String, Input>,
    validate: impl FnOnce(&str) -> Result<String, CorrelationError>,
) -> Result<String, CorrelationError> {
    if let Some(key) = reference(text, field)? {
        if key
            .strip_prefix("inputs.")
            .is_some_and(|name| !inputs.contains_key(name))
        {
            return Err(invalid(field, "reference names an undeclared input"));
        }
        Ok(text.to_owned())
    } else {
        validate(text).map_err(|error| invalid(field, error.message))
    }
}

/// Accept a complete non-null SHA-1/SHA-256 object ID and normalize hex case.
/// This validates representation only; the daemon must verify associations.
pub fn validate_full_commit(text: &str) -> Result<String, CorrelationError> {
    if !matches!(text.len(), 40 | 64)
        || !text.bytes().all(|byte| byte.is_ascii_hexdigit())
        || text.bytes().all(|byte| byte == b'0')
    {
        return Err(invalid(
            "commit",
            "expected a full nonzero 40- or 64-digit hexadecimal commit",
        ));
    }
    Ok(text.to_ascii_lowercase())
}

/// Canonical HTTPS repository identity without guessed host/path equivalence.
/// Only ASCII DNS/IPv4 hosts and simple literal path segments are supported;
/// credentials, percent encoding, queries, fragments, IPv6 and SSH/SCP refuse.
pub fn canonical_repository_url(text: &str) -> Result<String, CorrelationError> {
    let error = || {
        invalid(
            "repository",
            "expected an unambiguous credential-free HTTPS repository URL",
        )
    };
    if text.len() > 4096 || !text.is_ascii() {
        return Err(error());
    }
    let tail = text
        .get(..8)
        .filter(|scheme| scheme.eq_ignore_ascii_case("https://"))
        .and_then(|_| text.get(8..))
        .ok_or_else(error)?;
    let (authority, path) = tail.split_once('/').ok_or_else(error)?;
    let (host, port) = match authority.split_once(':') {
        Some((host, port)) => {
            if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(error());
            }
            let port = port
                .parse::<u16>()
                .ok()
                .filter(|port| *port != 0)
                .ok_or_else(error)?;
            (host, (port != 443).then_some(port))
        }
        None => (authority, None),
    };
    if !valid_host(host)
        || path.is_empty()
        || path.split('/').count() > 32
        || path.split('/').any(|part| {
            part.is_empty()
                || part.len() > 255
                || matches!(part, "." | "..")
                || !part.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'~')
                })
        })
        || crate::looks_secret_like(text)
    {
        return Err(error());
    }
    let port = port.map_or_else(String::new, |port| format!(":{port}"));
    Ok(format!(
        "https://{}{port}/{path}",
        host.to_ascii_lowercase()
    ))
}

fn valid_host(host: &str) -> bool {
    if host.len() > 253 || !host.contains('.') {
        return false;
    }
    if host
        .bytes()
        .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        return host
            .parse::<std::net::Ipv4Addr>()
            .is_ok_and(|ip| ip.to_string() == host);
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label.as_bytes()[0].is_ascii_alphanumeric()
            && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}
