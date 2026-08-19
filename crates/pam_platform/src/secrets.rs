use std::{collections::HashMap, error::Error, fmt, sync::Arc};

use keyring_core::{CredentialStore, Entry, Error as KeyringError};
use pam_core::{CallerCredential, CallerId};
use sha2::{Digest, Sha256};

const LOCATOR_DOMAIN: &[u8] = b"pam-secret-locator-v1";
const LOCATOR_PREFIX: &str = "pam.caller.v1.";
const HEX: &[u8; 16] = b"0123456789abcdef";
const NATIVE_SECRET_SERVICE: &str = "dev.pam.caller-credential";
pub const MAX_SECRET_CONTEXT_BYTES: usize = 512;

/// An opaque, stable native-secret account key for one caller.
///
/// The source identifier is length-prefixed and domain-separated before
/// hashing. The caller ID itself never appears in the key handed to a native
/// credential store.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct SecretLocator(String);

impl SecretLocator {
    /// Derives a bounded native-secret account key from caller context.
    ///
    /// # Errors
    ///
    /// Returns [`SecretStoreErrorKind::InvalidLocator`] when the caller ID is
    /// empty or exceeds [`MAX_SECRET_CONTEXT_BYTES`].
    pub fn for_caller(caller_id: &CallerId) -> Result<Self, SecretStoreError> {
        let caller = validate_context(caller_id.as_str())?;
        let mut hasher = Sha256::new();
        hasher.update(LOCATOR_DOMAIN);
        hash_context(&mut hasher, caller);

        let digest = hasher.finalize();
        let mut key = String::with_capacity(LOCATOR_PREFIX.len() + digest.len() * 2);
        key.push_str(LOCATOR_PREFIX);
        for byte in digest {
            key.push(HEX[usize::from(byte >> 4)] as char);
            key.push(HEX[usize::from(byte & 0x0f)] as char);
        }
        Ok(Self(key))
    }

    /// Returns the opaque account key for a native credential-store backend.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretLocator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretLocator([REDACTED])")
    }
}

fn validate_context(value: &str) -> Result<&[u8], SecretStoreError> {
    if value.is_empty() || value.len() > MAX_SECRET_CONTEXT_BYTES {
        return Err(SecretStoreError::new(SecretStoreErrorKind::InvalidLocator));
    }
    Ok(value.as_bytes())
}

fn hash_context(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

/// Sanitized failures returned by a native credential-store backend.
///
/// This deliberately carries no backend diagnostic text: platform keyring
/// errors can include account identifiers, process details, or secret values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretBackendError {
    Unavailable,
    Denied,
}

impl fmt::Display for SecretBackendError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => formatter.write_str("native credential store unavailable"),
            Self::Denied => formatter.write_str("native credential store access denied"),
        }
    }
}

impl Error for SecretBackendError {}

/// OS-native caller credential storage.
///
/// Construct and call this adapter from a blocking boundary: native keyrings
/// may wait for desktop services or prompt the local user. Construction is
/// lazy and never falls back to a plaintext file.
pub struct NativeSecretBackend {
    store: Arc<CredentialStore>,
    explicit_target: bool,
}

impl NativeSecretBackend {
    /// Opens the current user's native credential store.
    ///
    /// # Errors
    ///
    /// Returns a sanitized failure without retaining platform error details.
    pub fn new() -> Result<Self, SecretBackendError> {
        #[cfg(target_os = "macos")]
        let store: Arc<CredentialStore> = apple_native_keyring_store::keychain::Store::new()
            .map_err(|error| map_keyring_error(&error))?;
        #[cfg(target_os = "windows")]
        let store: Arc<CredentialStore> = windows_native_keyring_store::Store::new()
            .map_err(|error| map_keyring_error(&error))?;
        #[cfg(target_os = "linux")]
        let store: Arc<CredentialStore> = zbus_secret_service_keyring_store::Store::new()
            .map_err(|error| map_keyring_error(&error))?;
        #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
        return Err(SecretBackendError::Unavailable);

        Ok(Self {
            store,
            explicit_target: cfg!(target_os = "windows"),
        })
    }

    #[cfg(test)]
    pub(crate) fn from_store(store: Arc<CredentialStore>) -> Self {
        Self {
            store,
            explicit_target: false,
        }
    }

    fn entry(&self, locator: &SecretLocator) -> Result<Entry, SecretBackendError> {
        if self.explicit_target {
            let modifiers = HashMap::from([("target", locator.as_str())]);
            self.store
                .build(NATIVE_SECRET_SERVICE, locator.as_str(), Some(&modifiers))
                .map_err(|error| map_keyring_error(&error))
        } else {
            self.store
                .build(NATIVE_SECRET_SERVICE, locator.as_str(), None)
                .map_err(|error| map_keyring_error(&error))
        }
    }
}

impl fmt::Debug for NativeSecretBackend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NativeSecretBackend([REDACTED])")
    }
}

impl SecretBackend for NativeSecretBackend {
    fn get(&self, locator: &SecretLocator) -> Result<Option<CallerCredential>, SecretBackendError> {
        match self.entry(locator)?.get_password() {
            Ok(secret) => Ok(Some(CallerCredential::new(secret))),
            Err(KeyringError::NoEntry) => Ok(None),
            Err(error) => Err(map_keyring_error(&error)),
        }
    }

    fn set(
        &self,
        locator: &SecretLocator,
        credential: &CallerCredential,
    ) -> Result<(), SecretBackendError> {
        self.entry(locator)?
            .set_password(credential.expose_secret())
            .map_err(|error| map_keyring_error(&error))
    }

    fn delete(&self, locator: &SecretLocator) -> Result<bool, SecretBackendError> {
        match self.entry(locator)?.delete_credential() {
            Ok(()) => Ok(true),
            Err(KeyringError::NoEntry) => Ok(false),
            Err(error) => Err(map_keyring_error(&error)),
        }
    }
}

fn map_keyring_error(error: &KeyringError) -> SecretBackendError {
    match error {
        KeyringError::NoStorageAccess(_) => SecretBackendError::Denied,
        _ => SecretBackendError::Unavailable,
    }
}

/// Injectable boundary implemented by an OS-native credential-store adapter.
///
/// Implementations must not fall back to plaintext files. `Ok(None)` and
/// `Ok(false)` represent a missing entry; callers receive a typed not-found
/// error from [`SecretStore`].
pub trait SecretBackend {
    /// Fetches a credential, if present.
    ///
    /// # Errors
    ///
    /// Returns a sanitized availability or access-denied failure.
    fn get(&self, locator: &SecretLocator) -> Result<Option<CallerCredential>, SecretBackendError>;

    /// Creates or replaces a credential.
    ///
    /// # Errors
    ///
    /// Returns a sanitized availability or access-denied failure.
    fn set(
        &self,
        locator: &SecretLocator,
        credential: &CallerCredential,
    ) -> Result<(), SecretBackendError>;

    /// Deletes a credential, returning whether it existed.
    ///
    /// # Errors
    ///
    /// Returns a sanitized availability or access-denied failure.
    fn delete(&self, locator: &SecretLocator) -> Result<bool, SecretBackendError>;
}

/// Caller-credential operations backed exclusively by an injected secret store.
pub struct SecretStore<B> {
    backend: B,
}

impl<B> SecretStore<B> {
    #[must_use]
    pub const fn new(backend: B) -> Self {
        Self { backend }
    }

    #[must_use]
    pub const fn backend(&self) -> &B {
        &self.backend
    }

    #[must_use]
    pub fn into_backend(self) -> B {
        self.backend
    }
}

impl<B: SecretBackend> SecretStore<B> {
    /// Loads a valid caller credential from the injected native backend.
    ///
    /// # Errors
    ///
    /// Returns a typed missing, unavailable, access-denied, or invalid-secret
    /// error without exposing the secret or backend diagnostic text.
    pub fn get(&self, locator: &SecretLocator) -> Result<CallerCredential, SecretStoreError> {
        let credential = self
            .backend
            .get(locator)
            .map_err(SecretStoreError::from)?
            .ok_or_else(|| SecretStoreError::new(SecretStoreErrorKind::NotFound))?;
        if !credential.is_valid() {
            return Err(SecretStoreError::new(
                SecretStoreErrorKind::InvalidCredential,
            ));
        }
        Ok(credential)
    }

    /// Creates or replaces a valid caller credential in the injected backend.
    ///
    /// # Errors
    ///
    /// Returns a typed invalid-secret, unavailable, or access-denied error.
    pub fn set(
        &self,
        locator: &SecretLocator,
        credential: &CallerCredential,
    ) -> Result<(), SecretStoreError> {
        if !credential.is_valid() {
            return Err(SecretStoreError::new(
                SecretStoreErrorKind::InvalidCredential,
            ));
        }
        self.backend
            .set(locator, credential)
            .map_err(SecretStoreError::from)
    }

    /// Deletes the caller credential from the injected backend.
    ///
    /// # Errors
    ///
    /// Returns a typed missing, unavailable, or access-denied error.
    pub fn delete(&self, locator: &SecretLocator) -> Result<(), SecretStoreError> {
        if self
            .backend
            .delete(locator)
            .map_err(SecretStoreError::from)?
        {
            Ok(())
        } else {
            Err(SecretStoreError::new(SecretStoreErrorKind::NotFound))
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretStoreErrorKind {
    InvalidLocator,
    InvalidCredential,
    Unavailable,
    NotFound,
    BackendDenied,
}

/// A user-safe secret-store error containing no platform diagnostic payload.
pub struct SecretStoreError {
    kind: SecretStoreErrorKind,
}

impl SecretStoreError {
    const fn new(kind: SecretStoreErrorKind) -> Self {
        Self { kind }
    }

    #[must_use]
    pub const fn kind(&self) -> SecretStoreErrorKind {
        self.kind
    }
}

impl From<SecretBackendError> for SecretStoreError {
    fn from(error: SecretBackendError) -> Self {
        let kind = match error {
            SecretBackendError::Unavailable => SecretStoreErrorKind::Unavailable,
            SecretBackendError::Denied => SecretStoreErrorKind::BackendDenied,
        };
        Self::new(kind)
    }
}

impl fmt::Debug for SecretStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretStoreError")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for SecretStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            SecretStoreErrorKind::InvalidLocator => {
                formatter.write_str("PAM refused an invalid native credential locator.")
            }
            SecretStoreErrorKind::InvalidCredential => {
                formatter.write_str("PAM refused an invalid caller credential.")
            }
            SecretStoreErrorKind::Unavailable => {
                formatter.write_str("PAM's native credential store is unavailable.")
            }
            SecretStoreErrorKind::NotFound => {
                formatter.write_str("PAM has no native caller credential for this caller.")
            }
            SecretStoreErrorKind::BackendDenied => {
                formatter.write_str("PAM was denied access to the native credential store.")
            }
        }
    }
}

impl Error for SecretStoreError {}
