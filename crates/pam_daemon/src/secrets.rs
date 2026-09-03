//! Keyring-backed credential store for connector secrets.
//!
//! Every connector row in `pam_store` (base URL, username, enabled flag,
//! test result) is safe to keep in `SQLite` because none of it is a secret;
//! the bearer token, personal access token, or password that actually
//! authenticates a call lives here instead, in the platform's native
//! credential store — macOS Keychain, the Windows Credential Manager, or
//! the Secret Service over D-Bus on Linux — never on disk in plaintext and
//! never in the `SQLite` database.
//!
//! [`SecretStore`] is the daemon-facing handle: it runs every backend call
//! under [`tokio::task::spawn_blocking`] (native keyrings may block on a
//! desktop service, or on macOS prompt the user) and only ever returns a
//! sanitized [`SecretError`] — the platform's own error text is logged
//! with [`tracing::warn!`] and goes no further, because it can carry
//! account identifiers or other detail a refusal must not leak.
//!
//! [`SecretBackend`] is the injectable boundary. [`NativeSecretBackend`]
//! is the real one, selected per target OS at compile time.
//! [`FakeSecretBackend`] is an in-memory stand-in the daemon's own tests
//! (and its `DaemonConfig::secret_backend` injection point) use instead —
//! no test in this codebase touches a real keychain.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use keyring_core::{CredentialStore, Entry, Error as KeyringError};

/// Native-credential-store service name every connector account is filed
/// under. One service, many accounts — one per connector.
pub const SECRET_SERVICE: &str = "dev.pam.connector";

/// Builds the native-credential-store account key for one connector.
///
/// The connector id (`github`, `jenkins`, ...) is a small static set owned
/// by `pam_flow::ConnectorId`, never user input, so it is embedded
/// verbatim rather than hashed: unlike a caller-supplied identifier, it
/// cannot leak anything the account key does not already say.
#[must_use]
pub fn account_for(connector_id: &str) -> String {
    format!("pam.connector.v1.{connector_id}")
}

/// A connector secret, held only long enough to be used.
///
/// The exposed value never appears in [`fmt::Debug`], and the backing
/// bytes are overwritten (not merely dropped) when the value goes out of
/// scope — best-effort zeroing without `unsafe`, since a `String`'s
/// buffer cannot be reached any other way in safe Rust.
pub struct Secret(String);

impl Secret {
    /// Wraps a secret value.
    #[must_use]
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// Returns the secret's exposed value.
    ///
    /// Named `expose` rather than implementing `Deref`/`AsRef`, so that
    /// every call site announces, at the point of use, that it is
    /// handling a secret.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        // `String` keeps no reachable raw pointer in safe Rust, so the
        // only way to overwrite its bytes without `unsafe_code` (denied
        // workspace-wide) is to replace its contents before the buffer is
        // freed. This is best-effort: it does not defend against a copy
        // the allocator or the OS made earlier, only against the specific
        // buffer this value owns.
        let len = self.0.len();
        self.0.clear();
        self.0.push_str(&"\0".repeat(len));
    }
}

/// Sanitized failures a secret-store operation can return.
///
/// Deliberately carries no platform diagnostic text: native keyring
/// errors can include account identifiers, process details, or even
/// secret material in some backends' error paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretError {
    /// The native credential store could not be reached at all (not
    /// installed, the session bus is down, ...).
    Unavailable,
    /// The native credential store refused access (the user denied a
    /// keychain prompt, a policy blocks it, ...).
    Denied,
}

impl SecretError {
    /// The machine-readable cause a refusal carries.
    #[must_use]
    pub fn cause(&self) -> &'static str {
        match self {
            Self::Unavailable => "store_unavailable",
            Self::Denied => "store_denied",
        }
    }

    /// A human recovery line naming the concrete fix, never a security
    /// command.
    #[must_use]
    pub fn recovery(&self) -> &'static str {
        match self {
            Self::Unavailable => {
                "Pam's native credential store is unavailable; open Pam \u{2192} Settings \u{2192} Connectors and try again once the OS keychain service is reachable."
            }
            Self::Denied => {
                "Pam was denied access to the native credential store; open Pam \u{2192} Settings \u{2192} Connectors \u{2192} the connector \u{2192} Set credential and allow the access prompt."
            }
        }
    }
}

impl fmt::Display for SecretError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => formatter.write_str("native credential store unavailable"),
            Self::Denied => formatter.write_str("native credential store access denied"),
        }
    }
}

impl std::error::Error for SecretError {}

/// Injectable boundary implemented by a credential-store adapter.
///
/// Implementations must not fall back to a plaintext file. `Ok(None)` and
/// `Ok(false)` represent a missing entry; there is no separate not-found
/// error at this layer.
pub trait SecretBackend: Send + Sync {
    /// Fetches a secret, if one is stored under `account`.
    fn get(&self, account: &str) -> Result<Option<String>, SecretError>;

    /// Creates or replaces the secret stored under `account`.
    fn set(&self, account: &str, secret: &str) -> Result<(), SecretError>;

    /// Deletes the secret stored under `account`, returning whether one
    /// existed.
    fn delete(&self, account: &str) -> Result<bool, SecretError>;
}

/// OS-native connector credential storage.
///
/// Construction opens the platform's credential store and is lazy beyond
/// that: it never falls back to a plaintext file. Every method blocks on
/// the underlying platform API, so callers must only reach it from a
/// blocking context (see [`SecretStore`]).
pub struct NativeSecretBackend {
    store: Arc<CredentialStore>,
    /// Windows has no single default keyring instance; the account is
    /// also passed as the credential's `target` modifier so the Windows
    /// backend can build the right generic-credential name.
    explicit_target: bool,
}

impl NativeSecretBackend {
    /// Opens the current user's native credential store for this
    /// platform.
    ///
    /// # Errors
    ///
    /// Returns a sanitized failure without retaining platform error
    /// details; the underlying error text goes to [`tracing::warn!`].
    pub fn open() -> Result<Self, SecretError> {
        #[cfg(target_os = "macos")]
        let store: Arc<CredentialStore> = apple_native_keyring_store::keychain::Store::new()
            .map_err(|error| map_keyring_error(&error, "open the macOS keychain store"))?;
        #[cfg(target_os = "windows")]
        let store: Arc<CredentialStore> = windows_native_keyring_store::Store::new()
            .map_err(|error| map_keyring_error(&error, "open the Windows credential store"))?;
        #[cfg(target_os = "linux")]
        let store: Arc<CredentialStore> = zbus_secret_service_keyring_store::Store::new()
            .map_err(|error| map_keyring_error(&error, "open the Secret Service store"))?;
        #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
        {
            tracing::warn!("no native credential store is implemented for this platform");
            return Err(SecretError::Unavailable);
        }

        #[cfg_attr(
            not(any(target_os = "macos", target_os = "windows", target_os = "linux")),
            allow(unreachable_code)
        )]
        Ok(Self {
            store,
            explicit_target: cfg!(target_os = "windows"),
        })
    }

    fn entry(&self, account: &str) -> Result<Entry, SecretError> {
        if self.explicit_target {
            let modifiers = std::collections::HashMap::from([("target", account)]);
            self.store
                .build(SECRET_SERVICE, account, Some(&modifiers))
                .map_err(|error| map_keyring_error(&error, "build a credential entry"))
        } else {
            self.store
                .build(SECRET_SERVICE, account, None)
                .map_err(|error| map_keyring_error(&error, "build a credential entry"))
        }
    }
}

impl fmt::Debug for NativeSecretBackend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NativeSecretBackend([REDACTED])")
    }
}

impl SecretBackend for NativeSecretBackend {
    fn get(&self, account: &str) -> Result<Option<String>, SecretError> {
        match self.entry(account)?.get_password() {
            Ok(secret) => Ok(Some(secret)),
            Err(KeyringError::NoEntry) => Ok(None),
            Err(error) => Err(map_keyring_error(&error, "read a credential")),
        }
    }

    fn set(&self, account: &str, secret: &str) -> Result<(), SecretError> {
        self.entry(account)?
            .set_password(secret)
            .map_err(|error| map_keyring_error(&error, "write a credential"))
    }

    fn delete(&self, account: &str) -> Result<bool, SecretError> {
        match self.entry(account)?.delete_credential() {
            Ok(()) => Ok(true),
            Err(KeyringError::NoEntry) => Ok(false),
            Err(error) => Err(map_keyring_error(&error, "delete a credential")),
        }
    }
}

/// Maps a platform keyring error to a sanitized [`SecretError`], logging
/// the platform's own text (which can carry account identifiers or other
/// detail a refusal must not leak) at `warn` level only.
fn map_keyring_error(error: &KeyringError, action: &str) -> SecretError {
    let kind = match error {
        KeyringError::NoStorageAccess(_) => SecretError::Denied,
        _ => SecretError::Unavailable,
    };
    tracing::warn!(action, cause = kind.cause(), %error, "native credential store call failed");
    kind
}

/// In-memory [`SecretBackend`] for tests.
///
/// `entries` is not `pub`: nothing outside this module should read or
/// write the map directly, since that would bypass the pretend network
/// boundary the fake exists to stand in for. `fail_with` is `pub` on
/// purpose — tests reach into it to force every operation to fail, the
/// way the real store can when the OS keychain is unreachable or denies
/// access.
#[derive(Default)]
pub struct FakeSecretBackend {
    entries: Mutex<BTreeMap<String, String>>,
    /// When set, every [`SecretBackend`] method returns this error instead
    /// of touching `entries`.
    pub fail_with: Mutex<Option<SecretError>>,
}

impl FakeSecretBackend {
    fn maybe_fail(&self) -> Result<(), SecretError> {
        if let Some(error) = *self.fail_with.lock().unwrap_or_else(|poison| {
            tracing::warn!("fake secret backend's fail_with lock was poisoned");
            poison.into_inner()
        }) {
            return Err(error);
        }
        Ok(())
    }

    fn entries(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, String>> {
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl fmt::Debug for FakeSecretBackend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FakeSecretBackend([REDACTED])")
    }
}

impl SecretBackend for FakeSecretBackend {
    fn get(&self, account: &str) -> Result<Option<String>, SecretError> {
        self.maybe_fail()?;
        Ok(self.entries().get(account).cloned())
    }

    fn set(&self, account: &str, secret: &str) -> Result<(), SecretError> {
        self.maybe_fail()?;
        self.entries().insert(account.to_owned(), secret.to_owned());
        Ok(())
    }

    fn delete(&self, account: &str) -> Result<bool, SecretError> {
        self.maybe_fail()?;
        Ok(self.entries().remove(account).is_some())
    }
}

/// The daemon's connector credential store.
///
/// Every method runs the injected backend under
/// [`tokio::task::spawn_blocking`]: a native keyring can wait on a
/// desktop service or, on macOS, prompt the user, and none of that
/// belongs on the runtime thread that is also serving the socket.
pub struct SecretStore {
    backend: Arc<dyn SecretBackend>,
}

impl SecretStore {
    /// Builds a store over an injected backend.
    #[must_use]
    pub fn new(backend: Arc<dyn SecretBackend>) -> Self {
        Self { backend }
    }

    /// Builds a store over the platform's native credential backend.
    ///
    /// # Errors
    ///
    /// Returns a sanitized failure when the native store cannot be
    /// opened; the daemon still boots in that case with
    /// `store_available = false` (see `ConnectorService`, task #49).
    pub fn native() -> Result<Self, SecretError> {
        Ok(Self::new(Arc::new(NativeSecretBackend::open()?)))
    }

    /// Fetches the secret stored for `connector_id`, if any.
    pub async fn get(&self, connector_id: &str) -> Result<Option<Secret>, SecretError> {
        let backend = Arc::clone(&self.backend);
        let account = account_for(connector_id);
        run_blocking(move || backend.get(&account))
            .await
            .map(|value| value.map(Secret::new))
    }

    /// Creates or replaces the secret stored for `connector_id`.
    pub async fn set(&self, connector_id: &str, secret: &str) -> Result<(), SecretError> {
        let backend = Arc::clone(&self.backend);
        let account = account_for(connector_id);
        let secret = secret.to_owned();
        run_blocking(move || backend.set(&account, &secret)).await
    }

    /// Deletes the secret stored for `connector_id`, returning whether one
    /// existed.
    pub async fn clear(&self, connector_id: &str) -> Result<bool, SecretError> {
        let backend = Arc::clone(&self.backend);
        let account = account_for(connector_id);
        run_blocking(move || backend.delete(&account)).await
    }

    /// Reports whether a secret is stored for `connector_id`, without
    /// exposing it.
    pub async fn present(&self, connector_id: &str) -> Result<bool, SecretError> {
        Ok(self.get(connector_id).await?.is_some())
    }

    /// Warms the native credential store at daemon start, macOS only.
    ///
    /// A cold macOS Keychain access can pause on the first real call
    /// (session unlock, a background daemon spin-up); doing one harmless
    /// `present` for a well-known connector id on a background task at
    /// boot means the first *real* connector call does not pay that
    /// latency. Every other platform's native backend answers promptly
    /// enough that a warm-up would just be a wasted round trip, so this
    /// is a no-op there.
    pub fn warm(self: &Arc<Self>) {
        #[cfg(target_os = "macos")]
        {
            let store = Arc::clone(self);
            tokio::task::spawn(async move {
                let started = std::time::Instant::now();
                match store.present("github").await {
                    Ok(_) => {
                        tracing::info!(
                            elapsed_ms = started.elapsed().as_millis(),
                            "warmed the macOS keychain credential store"
                        );
                    }
                    Err(error) => {
                        tracing::warn!(
                            cause = error.cause(),
                            elapsed_ms = started.elapsed().as_millis(),
                            "macOS keychain warm-up failed"
                        );
                    }
                }
            });
        }
    }
}

/// Runs a blocking backend call on the blocking pool, folding a join
/// failure (the task panicked or was cancelled) into [`SecretError::Unavailable`].
async fn run_blocking<F, T>(call: F) -> Result<T, SecretError>
where
    F: FnOnce() -> Result<T, SecretError> + Send + 'static,
    T: Send + 'static,
{
    match tokio::task::spawn_blocking(call).await {
        Ok(result) => result,
        Err(error) => {
            tracing::warn!(%error, "the secret store's blocking task did not finish");
            Err(SecretError::Unavailable)
        }
    }
}
