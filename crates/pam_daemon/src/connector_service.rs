//! The connector host: what the Connectors screen configures, and what a
//! flow step calls through.
//!
//! Three surfaces sit on one service. [`ConnectorService::list`] merges the
//! seven static descriptors (`pam_connectors`) with the rows a human has
//! saved (`pam_store`) and with what the OS keychain holds
//! ([`crate::secrets`]), so the GUI can draw the whole panel from one
//! answer. [`ConnectorService::configure`] writes a row and its credential.
//! [`ConnectorService::test`] proves the credential still works.
//! [`ConnectorService::invoke`] is what a flow step reaches — it is the only
//! one an agent can cause, and it never runs until the connector is
//! configured, enabled, and credentialed.
//!
//! # A secret is only ever borrowed
//!
//! The credential lives in the OS keychain and nowhere else. It is read for
//! the length of one call, converted straight into a
//! [`pam_connectors::Secret`] (which redacts its `Debug` and overwrites its
//! bytes on drop), handed to the transport as a header on stdin, and
//! dropped. It is never written to the store, an audit row, evidence, argv,
//! or the daemon log — the `configure` audit row records only *that* a
//! credential was set or cleared.
//!
//! # A missing piece degrades, it does not stop the daemon
//!
//! Neither the native credential store nor `curl` is a boot requirement.
//! When the keychain will not open, the service still lists and still says
//! `store_available: false` on every entry, and any operation that needs a
//! credential refuses with the keychain's own cause. When `curl` is not
//! installed, the service still lists and configures, and every operation
//! that would speak HTTP refuses with `connector_cli_missing` and the
//! platform's install line. AWS is the exception on that second path: it
//! drives the local `aws` CLI, not `curl`, so it keeps working.

use std::collections::BTreeMap;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use pam_connectors::{
    ArgValue, AuthKind, CallResult, Connection, ConnectorError, ConnectorId, HttpRequest,
    HttpResponse, HttpTransport, Secret as CallSecret, TransportError, descriptor,
    validate_base_url,
};
use pam_store::{ConnectorPatch, ConnectorRow, Store, StoreError};
use serde::Serialize;
use thiserror::Error;

use crate::secrets::{SecretBackend, SecretError, SecretStore};

/// How long a credential test may take before it counts as failed.
///
/// The GUI bridge allows 15 s for `admin.connectors.test`, so a test that
/// hits this bound still answers "failed, timed out" rather than dying on
/// the bridge's own deadline.
pub const CONNECTOR_TEST_DEADLINE: Duration = Duration::from_secs(10);

/// The refusal cause for a connector whose row says `enabled = 0`.
pub const CAUSE_CONNECTOR_DISABLED: &str = "connector_disabled";

/// The refusal cause for a connector with no stored credential.
pub const CAUSE_CREDENTIAL_MISSING: &str = "credential_missing";

/// The refusal cause for a connector with no base URL saved.
pub const CAUSE_BASE_URL_MISSING: &str = "base_url_missing";

/// The refusal cause for a base URL that is not a usable service root.
pub const CAUSE_BAD_URL: &str = "bad_url";

/// The refusal cause for a connector whose row is missing a field its
/// authentication needs (a Jenkins user, a Confluence account email).
pub const CAUSE_NOT_CONFIGURED: &str = "connector_not_configured";

/// The refusal cause for an HTTP connector on a daemon with no `curl`.
pub const CAUSE_CLI_MISSING: &str = "connector_cli_missing";

/// The refusal cause for a bookkeeping failure inside the connector host.
pub const CAUSE_INTERNAL: &str = "internal_error";

/// Recovery line for a store failure inside the connector host.
const RECOVERY_INTERNAL: &str = "Retry; if it persists, restart the daemon from the PAM GUI.";

/// One connector as the GUI draws it: its static shape, the row a human
/// saved, and what the credential store says about it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConnectorSummary {
    /// The connector id (`github`, `jenkins`, ...).
    pub id: String,
    /// The name a human reads, in the vendor's own spelling.
    pub name: &'static str,
    /// How pam authenticates: `bearer`, `basic_user_secret`,
    /// `token_as_user`, or `aws_profile`.
    pub auth: &'static str,
    /// What this connector's `username` means, when it means anything —
    /// the label the GUI puts on the field.
    pub username_label: Option<&'static str>,
    /// Whether a base URL must be saved before the connector works.
    pub needs_base_url: bool,
    /// Whether a flow step may call it.
    pub enabled: bool,
    /// The saved base URL, normalized when it was saved.
    pub base_url: Option<String>,
    /// The saved user name, account email, or AWS profile.
    pub username: Option<String>,
    /// What the OS credential store said about this connector. Flattened
    /// into the entry the GUI reads, as `credential_present` and
    /// `store_available`.
    #[serde(flatten)]
    pub credential: CredentialStatus,
    /// The last credential test, when one has run.
    pub last_test: Option<LastTest>,
}

/// What the OS credential store said when this connector was summarized.
///
/// The two answers travel together because they are only meaningful
/// together: `present: false` means "no credential stored" when the store
/// answered, and "pam could not look" when it did not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CredentialStatus {
    /// Whether the credential store holds a secret for this connector.
    /// Never an error: an unreachable store answers `false` here and
    /// `false` for [`Self::store_available`] too.
    #[serde(rename = "credential_present")]
    pub present: bool,
    /// Whether the OS credential store answered at all.
    pub store_available: bool,
}

/// The verdict of the last [`ConnectorService::test`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LastTest {
    /// `passed` or `failed`.
    pub status: String,
    /// The one line the test produced: who pam is over there, or why it
    /// failed.
    pub detail: String,
    /// Unix seconds when the test ran.
    pub ts: i64,
}

/// What a configure asks of the stored credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialAction {
    /// Write this secret, replacing any existing one.
    Set(String),
    /// Delete the stored secret.
    Clear,
}

impl CredentialAction {
    /// The word the audit row records — never the secret itself.
    #[must_use]
    pub fn audit_word(action: Option<&Self>) -> &'static str {
        match action {
            Some(Self::Set(_)) => "set",
            Some(Self::Clear) => "cleared",
            None => "unchanged",
        }
    }
}

/// A partial change to one connector: a field left as `None` is untouched,
/// and `Some(None)` clears the field.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConfigurePatch {
    /// New `enabled` value, when given.
    pub enabled: Option<bool>,
    /// New base URL, when given; `Some(None)` clears it.
    pub base_url: Option<Option<String>>,
    /// New user name, when given; `Some(None)` clears it.
    pub username: Option<Option<String>>,
    /// What to do with the stored credential, when anything.
    pub credential: Option<CredentialAction>,
}

/// Why a connector operation could not run, or did not finish.
///
/// Every variant answers the three questions a pam refusal must answer:
/// [`cause`](Self::cause) is the stable machine name,
/// [`detail`](Self::detail) says what happened, and
/// [`recovery`](Self::recovery) names the Connectors screen or the concrete
/// edit that fixes it — never a security command.
#[derive(Debug, Error)]
pub enum InvokeError {
    /// The connector's row says it is disabled.
    #[error("the connector is disabled")]
    Disabled,
    /// No credential is stored for the connector.
    #[error("no credential is stored for the connector")]
    CredentialMissing,
    /// The connector needs a base URL and none is saved.
    #[error("the connector has no base URL saved")]
    BaseUrlMissing,
    /// The base URL is not a usable service root.
    #[error("{0}")]
    BadUrl(String),
    /// The row is missing a field this connector's authentication needs.
    #[error("{0}")]
    NotConfigured(String),
    /// The OS credential store could not answer.
    #[error("{0}")]
    Secret(#[from] SecretError),
    /// The connector itself refused, or the service did.
    #[error("{0}")]
    Connector(#[from] ConnectorError),
    /// This daemon has no `curl`, so no HTTP connector can run.
    #[error("curl is not installed, or not on the daemon's PATH")]
    CurlMissing,
    /// The daemon's own bookkeeping failed.
    #[error("connector bookkeeping failed: {0}")]
    Store(#[from] StoreError),
}

impl InvokeError {
    /// The stable machine name of this refusal.
    #[must_use]
    pub fn cause(&self) -> &'static str {
        match self {
            Self::Disabled => CAUSE_CONNECTOR_DISABLED,
            Self::CredentialMissing => CAUSE_CREDENTIAL_MISSING,
            Self::BaseUrlMissing => CAUSE_BASE_URL_MISSING,
            Self::BadUrl(_) => CAUSE_BAD_URL,
            Self::NotConfigured(_) => CAUSE_NOT_CONFIGURED,
            Self::Secret(error) => error.cause(),
            Self::Connector(error) => error.cause(),
            Self::CurlMissing => CAUSE_CLI_MISSING,
            Self::Store(_) => CAUSE_INTERNAL,
        }
    }

    /// One sentence saying what happened. Carries no secret: the
    /// credential never reaches an error path, and connector detail is
    /// built by `pam_connectors` from the response, not from the request.
    #[must_use]
    pub fn detail(&self) -> String {
        self.to_string()
    }

    /// The concrete fix, naming the connector by the name a human reads.
    ///
    /// A flow refusal carries this text verbatim; the admin surface uses
    /// [`Self::recovery_line`], which is the same text for every refusal a
    /// human can actually cause from the Connectors screen.
    #[must_use]
    pub fn recovery(&self, id: ConnectorId) -> String {
        match self {
            Self::Connector(error) => error.recovery(id),
            other => other.recovery_line(id).to_owned(),
        }
    }

    /// [`Self::recovery`] as a `'static` line, which is what the admin
    /// surface's refusals carry.
    ///
    /// Only [`Self::Connector`] differs from [`Self::recovery`]: a
    /// connector error's own recovery can embed a rate-limit wait, so this
    /// falls back to the connector's Test line. That path is a flow's, not
    /// the GUI's — no admin op makes a connector call whose failure becomes
    /// a refusal ([`ConnectorService::test`] records failures instead).
    #[must_use]
    pub fn recovery_line(&self, id: ConnectorId) -> &'static str {
        let lines = recoveries(id);
        match self {
            Self::Disabled => &lines.disabled,
            Self::CredentialMissing => &lines.credential_missing,
            Self::BaseUrlMissing | Self::BadUrl(_) => &lines.base_url,
            Self::NotConfigured(_) => &lines.not_configured,
            Self::Secret(error) => error.recovery(),
            Self::Connector(_) => &lines.test,
            Self::CurlMissing => pam_model::download::curl_recovery_line(),
            Self::Store(_) => RECOVERY_INTERNAL,
        }
    }
}

/// The recovery lines for one connector, built once.
///
/// Each names the Connectors screen and the connector, which is where every
/// one of these is fixed. They are owned by a `static` so the admin surface
/// (whose refusals carry `&'static str`) can hand them out directly.
struct Recoveries {
    disabled: String,
    credential_missing: String,
    base_url: String,
    not_configured: String,
    test: String,
}

/// The per-connector recovery lines, in [`ConnectorId::ALL`] order.
static RECOVERIES: LazyLock<[Recoveries; 7]> = LazyLock::new(|| ConnectorId::ALL.map(build_lines));

/// This connector's recovery lines.
fn recoveries(id: ConnectorId) -> &'static Recoveries {
    let index = ConnectorId::ALL
        .iter()
        .position(|candidate| *candidate == id)
        .expect("every ConnectorId is in ConnectorId::ALL");
    &RECOVERIES[index]
}

/// Writes one connector's recovery lines.
fn build_lines(id: ConnectorId) -> Recoveries {
    let shape = descriptor(id);
    let name = shape.name;
    let field = shape.username_label.unwrap_or("user name");
    Recoveries {
        disabled: format!("open Pam → Settings → Connectors → {name} → enable it"),
        credential_missing: format!(
            "open Pam → Settings → Connectors → {name} → set the credential and Test"
        ),
        base_url: format!(
            "open Pam → Settings → Connectors → {name} → type the service root as https://host/ and Save"
        ),
        not_configured: format!("open Pam → Settings → Connectors → {name} → fill in the {field}"),
        test: format!("open Pam → Settings → Connectors → {name} → Test"),
    }
}

/// The connector host: rows, credentials, and the transport, in one place.
pub struct ConnectorService {
    store: Arc<Store>,
    secrets: Arc<SecretStore>,
    transport: Arc<dyn HttpTransport>,
    /// Whether the OS credential store opened at boot. `false` makes every
    /// credential read refuse with the keychain's own cause, and every
    /// summary say so.
    store_available: bool,
    /// Whether `curl` is missing, which refuses every HTTP connector before
    /// the transport is touched (AWS drives its own CLI and is exempt).
    curl_missing: bool,
}

impl std::fmt::Debug for ConnectorService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConnectorService")
            .field("store_available", &self.store_available)
            .field("curl_missing", &self.curl_missing)
            .finish_non_exhaustive()
    }
}

impl ConnectorService {
    /// Builds the service with both of its dependencies present.
    #[must_use]
    pub fn new(
        store: Arc<Store>,
        secrets: Arc<SecretStore>,
        transport: Arc<dyn HttpTransport>,
    ) -> Self {
        Self {
            store,
            secrets,
            transport,
            store_available: true,
            curl_missing: false,
        }
    }

    /// Builds the service from whatever the daemon actually has.
    ///
    /// This is the boot path: a keychain that will not open, or a machine
    /// with no `curl`, leaves the daemon serving and the Connectors screen
    /// answering — with refusals that name the missing piece, rather than a
    /// daemon that will not start (see the module docs).
    #[must_use]
    pub fn from_parts(
        store: Arc<Store>,
        secrets: Option<Arc<SecretStore>>,
        transport: Option<Arc<dyn HttpTransport>>,
    ) -> Self {
        let store_available = secrets.is_some();
        let curl_missing = transport.is_none();
        Self {
            store,
            secrets: secrets
                .unwrap_or_else(|| Arc::new(SecretStore::new(Arc::new(UnavailableBackend)))),
            transport: transport.unwrap_or_else(|| Arc::new(MissingCurl)),
            store_available,
            curl_missing,
        }
    }

    /// Every connector, static shape merged with its row and its
    /// credential's presence, in [`ConnectorId::ALL`] order.
    pub async fn list(&self) -> Result<Vec<ConnectorSummary>, StoreError> {
        let rows = self.store.list_connectors().await?;
        let mut summaries = Vec::with_capacity(ConnectorId::ALL.len());
        for id in ConnectorId::ALL {
            let row = rows.iter().find(|row| row.id == id.as_str());
            summaries.push(self.summarize(id, row).await);
        }
        Ok(summaries)
    }

    /// One connector's summary.
    pub async fn get(&self, id: ConnectorId) -> Result<ConnectorSummary, StoreError> {
        let row = self.store.get_connector(id.as_str()).await?;
        Ok(self.summarize(id, row.as_ref()).await)
    }

    /// Saves a connector's configuration.
    ///
    /// The base URL is validated before anything is written, so a typo
    /// leaves the stored configuration exactly as it was. The credential
    /// goes first and the row second: a keychain that refuses the write
    /// must not leave a row claiming a credential that is not there.
    pub async fn configure(
        &self,
        id: ConnectorId,
        patch: ConfigurePatch,
    ) -> Result<ConnectorSummary, InvokeError> {
        // A change to the base URL is checked before anything is written;
        // a value that trims to nothing clears the field.
        let base_url = match patch.base_url.as_ref() {
            None => None,
            Some(None) => Some(None),
            Some(Some(raw)) => Some(normalize_base_url(id, raw)?),
        };

        match patch.credential.as_ref() {
            Some(CredentialAction::Set(secret)) => self.secrets.set(id.as_str(), secret).await?,
            Some(CredentialAction::Clear) => {
                self.secrets.clear(id.as_str()).await?;
            }
            None => {}
        }

        let username = patch
            .username
            .as_ref()
            .map(|value| value.as_deref().map(str::trim).filter(|v| !v.is_empty()));
        self.store
            .upsert_connector(
                id.as_str(),
                ConnectorPatch {
                    enabled: patch.enabled,
                    base_url: base_url.as_ref().map(|value| value.as_deref()),
                    username,
                },
            )
            .await?;
        Ok(self.get(id).await?)
    }

    /// Proves the stored credential still works, and records the verdict.
    ///
    /// A connector does not have to be enabled to be tested — testing
    /// before enabling is the order the Connectors screen asks for. The
    /// verdict is recorded whether it passed or failed, so the panel can
    /// show "failed, 401" without the human having to watch the call.
    pub async fn test(&self, id: ConnectorId) -> Result<(bool, String), InvokeError> {
        let row = self.store.get_connector(id.as_str()).await?;
        let connection = self.connection(id, row.as_ref()).await?;
        self.ensure_transport(id)?;

        let deadline = Instant::now() + CONNECTOR_TEST_DEADLINE;
        let verify = pam_connectors::verify(id, &connection, self.transport.as_ref(), deadline);
        let (passed, detail) = match tokio::time::timeout(CONNECTOR_TEST_DEADLINE, verify).await {
            Ok(Ok(report)) => (true, report.detail),
            Ok(Err(error)) => (false, error.detail()),
            Err(_elapsed) => (false, ConnectorError::Timeout.detail()),
        };
        self.store
            .record_connector_test(id.as_str(), passed, &detail)
            .await?;
        Ok((passed, detail))
    }

    /// Runs one connector call on behalf of a flow step.
    ///
    /// Everything a human must fix — disabled, no credential, no base URL,
    /// an unreachable keychain, a missing `curl` — refuses here, before the
    /// transport is touched. Only a fully configured, enabled connector
    /// ever reaches the network.
    pub async fn invoke(
        &self,
        id: ConnectorId,
        call: &str,
        args: &BTreeMap<String, ArgValue>,
        deadline: Instant,
    ) -> Result<CallResult, InvokeError> {
        let row = self.store.get_connector(id.as_str()).await?;
        if !row.as_ref().is_some_and(|row| row.enabled) {
            return Err(InvokeError::Disabled);
        }
        let connection = self.connection(id, row.as_ref()).await?;
        self.ensure_transport(id)?;
        Ok(pam_connectors::call(
            id,
            &connection,
            call,
            args,
            self.transport.as_ref(),
            deadline,
        )
        .await?)
    }

    /// Builds the connection one call runs over, refusing whatever the
    /// human has not filled in yet.
    async fn connection(
        &self,
        id: ConnectorId,
        row: Option<&ConnectorRow>,
    ) -> Result<Connection, InvokeError> {
        let shape = descriptor(id);
        let base_url = if shape.needs_base_url {
            let raw = row
                .and_then(|row| row.base_url.as_deref())
                .map(str::trim)
                .filter(|raw| !raw.is_empty())
                .ok_or(InvokeError::BaseUrlMissing)?;
            validate_base_url(id, raw).map_err(|error| InvokeError::BadUrl(error.detail()))?
        } else {
            validate_base_url(id, "").map_err(|error| InvokeError::BadUrl(error.detail()))?
        };

        let username = row
            .and_then(|row| row.username.as_deref())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned);
        if shape.auth == AuthKind::BasicUserSecret && username.is_none() {
            let label = shape.username_label.unwrap_or("user name");
            return Err(InvokeError::NotConfigured(format!(
                "the connector needs a {label} alongside its credential"
            )));
        }

        let secret = if shape.auth == AuthKind::AwsProfile {
            None
        } else {
            // The daemon's own `Secret` is held for exactly as long as the
            // conversion takes, then dropped (and overwritten).
            let stored = self
                .secrets
                .get(id.as_str())
                .await?
                .ok_or(InvokeError::CredentialMissing)?;
            Some(CallSecret::new(stored.expose().to_owned()))
        };

        Ok(Connection {
            base_url,
            username,
            secret,
        })
    }

    /// Refuses an HTTP connector when this daemon has no `curl`.
    fn ensure_transport(&self, id: ConnectorId) -> Result<(), InvokeError> {
        if self.curl_missing && descriptor(id).auth != AuthKind::AwsProfile {
            return Err(InvokeError::CurlMissing);
        }
        Ok(())
    }

    /// Merges one connector's static shape, its row, and its credential.
    async fn summarize(&self, id: ConnectorId, row: Option<&ConnectorRow>) -> ConnectorSummary {
        let shape = descriptor(id);
        // AWS stores no credential, so the keychain is never asked about it
        // — a needless prompt on macOS, and a false "missing" line.
        let credential = if shape.auth == AuthKind::AwsProfile {
            CredentialStatus {
                present: false,
                store_available: self.store_available,
            }
        } else {
            match self.secrets.present(id.as_str()).await {
                Ok(present) => CredentialStatus {
                    present,
                    store_available: self.store_available,
                },
                Err(error) => {
                    tracing::warn!(
                        connector = id.as_str(),
                        cause = error.cause(),
                        "could not read the connector's credential"
                    );
                    CredentialStatus {
                        present: false,
                        store_available: false,
                    }
                }
            }
        };
        ConnectorSummary {
            id: id.as_str().to_owned(),
            name: shape.name,
            auth: auth_str(shape.auth),
            username_label: shape.username_label,
            needs_base_url: shape.needs_base_url,
            enabled: row.is_some_and(|row| row.enabled),
            base_url: row.and_then(|row| row.base_url.clone()),
            username: row.and_then(|row| row.username.clone()),
            credential,
            last_test: row.and_then(last_test),
        }
    }
}

/// Checks one base-URL value on its way into the row, answering what to
/// store — `None` when it trims to nothing, which clears the field.
///
/// A connector with no base URL of its own (AWS resolves endpoints through
/// the local CLI) is exempt from validation: whatever its row carries there
/// is never dialed.
fn normalize_base_url(id: ConnectorId, raw: &str) -> Result<Option<String>, InvokeError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if !descriptor(id).needs_base_url {
        return Ok(Some(trimmed.to_owned()));
    }
    let url =
        validate_base_url(id, trimmed).map_err(|error| InvokeError::BadUrl(error.detail()))?;
    Ok(Some(url.to_string()))
}

/// The `auth` word the GUI switches its credential fields on.
fn auth_str(kind: AuthKind) -> &'static str {
    match kind {
        AuthKind::Bearer => "bearer",
        AuthKind::BasicUserSecret => "basic_user_secret",
        AuthKind::TokenAsUser => "token_as_user",
        AuthKind::AwsProfile => "aws_profile",
    }
}

/// The row's last-test triple, when it has all three parts.
fn last_test(row: &ConnectorRow) -> Option<LastTest> {
    Some(LastTest {
        status: row.last_test_status.clone()?,
        detail: row.last_test_detail.clone().unwrap_or_default(),
        ts: row.last_test_ts?,
    })
}

/// The credential backend a daemon whose keychain would not open runs on:
/// every call refuses the way the real store does when it is unreachable.
struct UnavailableBackend;

impl SecretBackend for UnavailableBackend {
    fn get(&self, _account: &str) -> Result<Option<String>, SecretError> {
        Err(SecretError::Unavailable)
    }

    fn set(&self, _account: &str, _secret: &str) -> Result<(), SecretError> {
        Err(SecretError::Unavailable)
    }

    fn delete(&self, _account: &str) -> Result<bool, SecretError> {
        Err(SecretError::Unavailable)
    }
}

/// The transport a daemon with no `curl` runs on.
///
/// Nothing should ever reach it — [`ConnectorService::ensure_transport`]
/// refuses first, with the platform's install line — so its one job is to
/// fail loudly rather than pretend a network exists.
struct MissingCurl;

impl HttpTransport for MissingCurl {
    fn send<'a>(
        &'a self,
        _request: HttpRequest,
        _deadline: Instant,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<HttpResponse, TransportError>> + Send + 'a>,
    > {
        Box::pin(async {
            Err(TransportError::Spawn(
                "curl is not installed, or not on the daemon's PATH".to_owned(),
            ))
        })
    }
}
