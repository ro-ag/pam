//! The network half of the admin surface: `admin.network.get`, `.set` and `.test`.
//!
//! Ordinary admin ops — see [`crate::admin`] for the security model: GUI tripwire, request row,
//! single terminal audit row, deadline, structural guard (no [`crate::policy::classify`] entry,
//! never a capability, never grantable). No `pam` subcommand builds these envelopes. The
//! settings themselves are [`crate::network_service`]'s; this module is the door, the patch
//! grammar, and the Test.
//!
//! [`OP_NETWORK_SET`] takes a patch (absent keeps, `null` clears, a value sets), validates it
//! whole before any effect, and applies effects in an order that leaves the old configuration
//! intact on a failure: the CA bundle's private copy is written first (content-addressed, so
//! nothing in use is overwritten), then the keychain password, then the document — with a
//! compare-and-swap on the exact prior bytes, so two saves cannot lose each other's change —
//! then one [`ACTION_NETWORK_CONFIGURE`] audit row naming what changed, then unreferenced CA
//! copies are removed. The password crosses the socket once into the keychain and appears in no
//! row, reply or log line; the audit row says only `set`, `cleared` or `unchanged`.
//!
//! [`OP_NETWORK_TEST`] probes configured targets only — the base URL of a connector, the pinned
//! engine asset, the models host — with a bare `HEAD`, no credentials and no custom headers, so
//! it cannot be used to reach an address the human did not already configure. A probe that
//! fails is an answer (`ok: false` with the launcher's cause, sentence and recovery), not a
//! refusal; only settings that cannot be used at all refuse. The daemon bounds the whole run at
//! [`NETWORK_TEST_DEADLINE`]; the GUI bridge waits 25 s.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use pam_connectors::ConnectorId;
use pam_net::{Method, NetFailure, NetSettings, ProxyAuth, ProxyPassword, TrustedCurl, Url};
use pam_proto::Outcome;
use pam_store::{Actor, Decision};
use serde_json::{Value, json};

use crate::admin::{
    AdminOk, AdminRefusal, AdminService, CAUSE_INVALID_ADMIN_ARGS, RECOVERY_FIX_ARGS,
    RECOVERY_INTERNAL,
};
use crate::connector_service::CredentialAction;
use crate::daemon::CAUSE_INTERNAL_ERROR;
use crate::network_service::{
    CaBundleEntry, CaImportError, Field, Loaded, NetworkDocument, ProxyEntry, Source, ignored_env,
};

/// `admin.network.get {}` → the settings, where each came from, the curl
/// probe, and the ignored environment names.
pub const OP_NETWORK_GET: &str = "admin.network.get";

/// `admin.network.set { proxy?, credential?, no_proxy?, ca_bundle?,
/// engine_mirror?, models_mirror? }` → the same body as `get`, after the
/// save.
pub const OP_NETWORK_SET: &str = "admin.network.set";

/// `admin.network.test { target? }` → `{ results: [...] }`, one entry per
/// probed target.
pub const OP_NETWORK_TEST: &str = "admin.network.test";

/// Every op this module answers — the GUI bridge's whitelist reads it so
/// the two can never drift.
pub const NETWORK_ADMIN_OPS: &[&str] = &[OP_NETWORK_GET, OP_NETWORK_SET, OP_NETWORK_TEST];

/// `audit.action` recording a network settings change, written in
/// addition to the op's terminal [`crate::admin::ACTION_ADMIN`] row.
pub const ACTION_NETWORK_CONFIGURE: &str = "network.configure";

/// Refusal cause for a patch that touches a field the policy owns.
pub const CAUSE_SETTING_LOCKED: &str = "setting_locked";

/// Refusal cause when the document changed under a save.
pub const CAUSE_NETWORK_CONFLICT: &str = "network_settings_conflict";

/// Refusal cause for a value the network rules refuse, and for a stored
/// document that cannot be used (the launcher's `network_settings_invalid`).
pub const CAUSE_NETWORK_INVALID: &str = "network_settings_invalid";

/// Refusal cause for a CA bundle that could not be imported.
pub const CAUSE_CA_IMPORT_REFUSED: &str = "ca_bundle_refused";

/// How long the daemon gives the whole Test; the bridge waits 25 s.
pub const NETWORK_TEST_DEADLINE: Duration = Duration::from_secs(20);

/// curl's own limit per probe, seconds.
const PROBE_MAX_TIME: u64 = 8;

/// curl's connect limit per probe, seconds.
const PROBE_CONNECT_TIMEOUT: u64 = 5;

/// The hard bound on one probe process.
const PROBE_LIMIT: Duration = Duration::from_secs(12);

/// At most this many targets are probed per Test.
const MAX_TARGETS: usize = 12;

/// Probes run this many at a time.
const PROBE_PARALLELISM: usize = 4;

/// The target names for the engine and models hosts.
const TARGET_ENGINE: &str = "engine";
const TARGET_MODELS: &str = "models";

const RECOVERY_LOCKED: &str = "Managed by your organisation's policy; ask your administrator.";
const RECOVERY_CONFLICT: &str = "The network settings changed since this screen loaded; reload Settings › Network and apply the change again.";
const RECOVERY_RELOAD: &str = "Open Settings › Network, correct the value and save again.";
const RECOVERY_CA: &str = "Give the path of a PEM file of certificates that you or root own and that other users cannot write, then import again.";
const RECOVERY_SAVE_AGAIN: &str = "Open Settings › Network and save the settings again; until then connector calls and downloads are refused.";

impl AdminService {
    /// Answers one `admin.network.*` op, or `None` when the capability
    /// belongs to another part of the admin surface.
    ///
    /// `envelope_id` is the admin request's own id: the
    /// [`ACTION_NETWORK_CONFIGURE`] row hangs off it.
    pub(crate) async fn dispatch_network(
        &self,
        envelope_id: &str,
        op: &str,
        args: &Value,
    ) -> Option<Result<AdminOk, AdminRefusal>> {
        Some(match op {
            OP_NETWORK_GET => self.network_get(args).await,
            OP_NETWORK_SET => self.network_set(envelope_id, args).await,
            OP_NETWORK_TEST => self.network_test(args).await,
            _ => return None,
        })
    }

    /// The settings as the Network screen draws them.
    async fn network_get(&self, args: &Value) -> Result<AdminOk, AdminRefusal> {
        refuse_unknown_keys(args, &[], OP_NETWORK_GET)?;
        let body = self.network_body().await?;
        Ok(AdminOk {
            outcome: Outcome::Verified,
            body,
            audit: json!({ "op": OP_NETWORK_GET }),
        })
    }

    /// The `get` body: settings, sources, the curl probe, ignored names.
    /// A corrupt stored document is reported as the defaults plus a
    /// `document` notice, so the screen can still draw and a save can
    /// replace it; every consumer stays refused until then.
    async fn network_body(&self) -> Result<Value, AdminRefusal> {
        let (loaded, notice) = match self.network.load().await? {
            Ok(loaded) => (loaded, None),
            Err(invalid) => {
                tracing::warn!(
                    detail = %invalid.detail,
                    "the stored network settings cannot be used; connector calls and downloads \
                     are refused until they are saved again"
                );
                let fallback =
                    self.network
                        .check(&NetworkDocument::default())
                        .map_err(|detail| AdminRefusal {
                            cause: CAUSE_NETWORK_INVALID,
                            detail,
                            recovery: RECOVERY_SAVE_AGAIN,
                        })?;
                (fallback, Some(invalid.detail))
            }
        };
        let document = &loaded.resolved.document;
        let (present, store_available) = self.network.credential_present().await;
        let ca_bundle = match &document.ca_bundle {
            None => Value::Null,
            Some(bundle) => {
                let mut value = bundle_json(bundle);
                if let Some(changed) = self.network.source_changed(bundle).await {
                    value["source_changed"] = json!(changed);
                }
                value
            }
        };
        let allowed = &loaded.resolved.mirror_allowed_hosts;
        let mut effective = serde_json::Map::new();
        for field in Field::ALL {
            let source = loaded.resolved.source(field);
            effective.insert(field.as_str().to_owned(), source_json(source));
        }
        // The password has no field of its own in the document; it is
        // locked exactly when the proxy is.
        effective.insert(
            "credential".to_owned(),
            source_json(loaded.resolved.source(Field::Proxy)),
        );
        let curl = curl_probe().await;
        let mut body = json!({
            "settings": {
                "proxy": document.proxy.as_ref().map(proxy_json),
                "no_proxy": document.no_proxy,
                "ca_bundle": ca_bundle,
                "engine_mirror": document.engine_mirror,
                "models_mirror": document.models_mirror,
                "credential": { "present": present, "store_available": store_available },
                "mirror_allowed_hosts": if allowed.is_empty() { Value::Null } else { json!(allowed) },
            },
            "effective": effective,
            "curl": curl,
            "ignored_env": ignored_env(),
        });
        if let Some(detail) = notice {
            body["document"] = json!({
                "valid": false,
                "cause": CAUSE_NETWORK_INVALID,
                "detail": detail,
                "recovery": RECOVERY_SAVE_AGAIN,
            });
        }
        Ok(body)
    }

    /// Applies a patch (see the module docs for the order of effects).
    async fn network_set(&self, envelope_id: &str, args: &Value) -> Result<AdminOk, AdminRefusal> {
        let mut patch = Patch::parse(args)?;
        if patch.is_empty() {
            return Err(AdminRefusal {
                cause: CAUSE_INVALID_ADMIN_ARGS,
                detail: format!("{OP_NETWORK_SET} was given nothing to change"),
                recovery: RECOVERY_FIX_ARGS,
            });
        }
        // The stored document, or the defaults when it is corrupt: a save
        // is how the human replaces a document nothing can read, and the
        // compare-and-swap below still covers the exact prior bytes.
        let (raw, user, resolved) = match self.network.load().await? {
            Ok(loaded) => (loaded.raw, loaded.user, loaded.resolved),
            Err(invalid) => {
                let defaults =
                    self.network
                        .check(&NetworkDocument::default())
                        .map_err(|detail| AdminRefusal {
                            cause: CAUSE_NETWORK_INVALID,
                            detail,
                            recovery: RECOVERY_SAVE_AGAIN,
                        })?;
                (invalid.raw, NetworkDocument::default(), defaults.resolved)
            }
        };
        let locked: Vec<&str> = patch
            .fields()
            .into_iter()
            .filter(|field| resolved.source(*field).locked())
            .map(Field::as_str)
            .collect();
        if !locked.is_empty() {
            return Err(AdminRefusal {
                cause: CAUSE_SETTING_LOCKED,
                detail: format!(
                    "{} {} set by your organisation's policy; nothing was changed",
                    locked.join(", "),
                    if locked.len() == 1 { "is" } else { "are" }
                ),
                recovery: RECOVERY_LOCKED,
            });
        }
        let changed = patch.changed_names();
        let credential_word = CredentialAction::audit_word(patch.credential.as_ref());

        // 1. The whole document the patch produces, validated before any
        //    effect. The CA import is part of validation: it reads the
        //    source, and its private copy is content-addressed.
        let credential = validated_credential(patch.credential.take())?;
        let next = self.patched_document(&user, &patch).await?;
        let checked: Loaded = self.network.check(&next).map_err(|detail| AdminRefusal {
            cause: CAUSE_NETWORK_INVALID,
            detail,
            recovery: RECOVERY_RELOAD,
        })?;

        // 2. The keychain.
        match credential {
            Some(CredentialAction::Set(secret)) => {
                self.network
                    .set_credential(secret)
                    .await
                    .map_err(secret_refusal)?;
            }
            Some(CredentialAction::Clear) => {
                self.network
                    .clear_credential()
                    .await
                    .map_err(secret_refusal)?;
            }
            None => {}
        }

        // 3. The document, on the exact prior bytes.
        let written = self.network.save(raw.as_deref(), &next).await?;
        if !written {
            return Err(AdminRefusal {
                cause: CAUSE_NETWORK_CONFLICT,
                detail: "another save changed the network settings first; this one was not \
                         applied"
                    .to_owned(),
                recovery: RECOVERY_CONFLICT,
            });
        }

        // 4. The change, on this request; then the copies nothing names.
        let detail = configure_detail(&changed, credential_word, &checked).to_string();
        self.store
            .append_audit(
                envelope_id,
                ACTION_NETWORK_CONFIGURE,
                Decision::Allow,
                Actor::Human,
                Some(&detail),
            )
            .await?;
        self.network
            .prune_ca_copies(next.ca_bundle.as_ref().map(|bundle| bundle.sha256.as_str()));

        Ok(AdminOk {
            outcome: Outcome::Changed,
            body: self.network_body().await?,
            audit: json!({ "op": OP_NETWORK_SET, "changed": changed }),
        })
    }

    /// The user's document with the patch applied; a CA import happens
    /// here, so the record names a private copy that already exists.
    async fn patched_document(
        &self,
        user: &NetworkDocument,
        patch: &Patch,
    ) -> Result<NetworkDocument, AdminRefusal> {
        let mut next = user.clone();
        patch.proxy.apply_to(&mut next.proxy);
        if let Some(no_proxy) = &patch.no_proxy {
            next.no_proxy.clone_from(no_proxy);
        }
        patch.engine_mirror.apply_to(&mut next.engine_mirror);
        patch.models_mirror.apply_to(&mut next.models_mirror);
        match &patch.ca_bundle {
            Change::Keep => {}
            Change::Clear => next.ca_bundle = None,
            Change::Set(source) => {
                let entry = self
                    .network
                    .import_ca(source)
                    .await
                    .map_err(|error| ca_refusal(&error))?;
                next.ca_bundle = Some(entry);
            }
        }
        Ok(next)
    }

    /// Probes the configured targets with the saved settings.
    async fn network_test(&self, args: &Value) -> Result<AdminOk, AdminRefusal> {
        refuse_unknown_keys(args, &["target"], OP_NETWORK_TEST)?;
        let target = match args.get("target") {
            None | Some(Value::Null) => None,
            Some(Value::String(name)) if !name.is_empty() => Some(name.as_str()),
            Some(other) => {
                return Err(AdminRefusal {
                    cause: CAUSE_INVALID_ADMIN_ARGS,
                    detail: format!(
                        "{OP_NETWORK_TEST} needs \"target\" to be a connector id, \"engine\" or \
                         \"models\", not {other}"
                    ),
                    recovery: RECOVERY_FIX_ARGS,
                });
            }
        };
        // Settings that cannot be used refuse the whole Test: there is no
        // profile to probe under, and a direct probe would prove nothing.
        let settings = self
            .network
            .resolve_settings()
            .await
            .map_err(|failure| net_refusal(&failure))?;
        let (engine_mirror, models_mirror) = self
            .network
            .mirrors()
            .await
            .map_err(|failure| net_refusal(&failure))?;
        let curl = curl_probe_resolve()
            .await
            .map_err(|failure| net_refusal(&failure))?;
        let targets = self
            .probe_targets(target, engine_mirror.as_ref(), models_mirror.as_ref())
            .await?;

        let plain_http = self.network.plain_http_probes();
        let results = tokio::time::timeout(
            NETWORK_TEST_DEADLINE,
            probe_all(curl, Arc::clone(&settings), targets.clone(), plain_http),
        )
        .await
        .unwrap_or_default();
        // Targets the deadline cut off are answered too, as a failure.
        let mut answered: Vec<Value> = Vec::with_capacity(targets.len());
        for (name, url) in &targets {
            let found = results
                .iter()
                .find(|value| value["target"] == *name)
                .cloned();
            answered.push(found.unwrap_or_else(|| {
                let failure = NetFailure::Deadline;
                result_json(name, url, settings.route_for(url).as_str(), Err(&failure))
            }));
        }
        let failed: Vec<String> = answered
            .iter()
            .filter(|value| value["ok"] != true)
            .map(|value| {
                format!(
                    "{}:{}",
                    value["target"].as_str().unwrap_or_default(),
                    value["cause"].as_str().unwrap_or_default()
                )
            })
            .collect();
        Ok(AdminOk {
            outcome: Outcome::Verified,
            body: json!({ "results": answered }),
            audit: json!({
                "op": OP_NETWORK_TEST,
                "targets": targets.iter().map(|(name, _)| name.clone()).collect::<Vec<_>>(),
                "failed": failed,
            }),
        })
    }

    /// The `(name, url)` pairs a Test probes: one named target, or every
    /// enabled connector with a base URL plus the engine and models hosts
    /// when they would be fetched from. Nothing free-form.
    async fn probe_targets(
        &self,
        target: Option<&str>,
        engine_mirror: Option<&pam_net::MirrorBase>,
        models_mirror: Option<&pam_net::MirrorBase>,
    ) -> Result<Vec<(String, Url)>, AdminRefusal> {
        let engine_url = || -> Option<Url> {
            let target = pam_model::engine::Target::current()?;
            let release = pam_model::engine::EngineRelease::pinned(target);
            release
                .url(engine_mirror)
                .ok()
                .and_then(|url| Url::parse(&url).ok())
        };
        let models_url = || -> Option<Url> {
            let base = models_mirror.map_or(pam_model::catalog::UPSTREAM_PREFIX, |m| m.as_str());
            Url::parse(base).ok()
        };
        let mut targets: Vec<(String, Url)> = Vec::new();
        match target {
            Some(TARGET_ENGINE) => {
                let url = engine_url().ok_or(AdminRefusal {
                    cause: CAUSE_INVALID_ADMIN_ARGS,
                    detail: "this platform has no pinned engine release to test".to_owned(),
                    recovery: RECOVERY_FIX_ARGS,
                })?;
                targets.push((TARGET_ENGINE.to_owned(), url));
            }
            Some(TARGET_MODELS) => {
                let url = models_url().ok_or(AdminRefusal {
                    cause: CAUSE_INTERNAL_ERROR,
                    detail: "the models host address does not parse".to_owned(),
                    recovery: RECOVERY_INTERNAL,
                })?;
                targets.push((TARGET_MODELS.to_owned(), url));
            }
            Some(name) => {
                let id = ConnectorId::parse(name).ok_or_else(|| AdminRefusal {
                    cause: CAUSE_INVALID_ADMIN_ARGS,
                    detail: format!(
                        "{name:?} is not a connector, \"engine\" or \"models\"; nothing was probed"
                    ),
                    recovery: RECOVERY_FIX_ARGS,
                })?;
                let summary = self.connectors.get(id).await?;
                let url = summary
                    .base_url
                    .as_deref()
                    .and_then(|raw| Url::parse(raw).ok())
                    .ok_or_else(|| AdminRefusal {
                        cause: CAUSE_INVALID_ADMIN_ARGS,
                        detail: format!(
                            "{} has no base URL to test; save one in Settings › Connectors first",
                            summary.name
                        ),
                        recovery: RECOVERY_FIX_ARGS,
                    })?;
                targets.push((id.as_str().to_owned(), url));
            }
            None => {
                for summary in self.connectors.list().await? {
                    if !summary.enabled {
                        continue;
                    }
                    if let Some(url) = summary
                        .base_url
                        .as_deref()
                        .and_then(|raw| Url::parse(raw).ok())
                    {
                        targets.push((summary.id.clone(), url));
                    }
                }
                let engine_installed =
                    pam_model::engine::status(&self.models.engine_base()).installed;
                if (engine_mirror.is_some() || !engine_installed)
                    && let Some(url) = engine_url()
                {
                    targets.push((TARGET_ENGINE.to_owned(), url));
                }
                if models_mirror.is_some()
                    && let Some(url) = models_url()
                {
                    targets.push((TARGET_MODELS.to_owned(), url));
                }
            }
        }
        targets.truncate(MAX_TARGETS);
        Ok(targets)
    }
}

/// Runs the probes, [`PROBE_PARALLELISM`] at a time, answering whatever
/// finished (in any order).
async fn probe_all(
    curl: TrustedCurl,
    settings: Arc<NetSettings>,
    targets: Vec<(String, Url)>,
    plain_http: bool,
) -> Vec<Value> {
    let gate = Arc::new(tokio::sync::Semaphore::new(PROBE_PARALLELISM));
    let mut set = tokio::task::JoinSet::new();
    for (name, url) in targets {
        let gate = Arc::clone(&gate);
        let curl = curl.clone();
        let settings = Arc::clone(&settings);
        set.spawn(async move {
            let _slot = gate.acquire().await;
            probe(&curl, &settings, &name, &url, plain_http).await
        });
    }
    let mut results = Vec::new();
    while let Some(joined) = set.join_next().await {
        if let Ok(value) = joined {
            results.push(value);
        }
    }
    results
}

/// One probe: a bare `HEAD` of `url` under `settings`, in diagnostic mode
/// so a TLS failure can name the issuer where the backend prints it.
async fn probe(
    curl: &TrustedCurl,
    settings: &NetSettings,
    name: &str,
    url: &Url,
    plain_http: bool,
) -> Value {
    let route = settings.route_for(url);
    let request = curl
        .request(settings, url)
        .method(Method::Head)
        .include_headers()
        .diagnostic()
        .max_time(PROBE_MAX_TIME)
        .connect_timeout(PROBE_CONNECT_TIMEOUT);
    #[cfg(test)]
    let request = if plain_http {
        request.allow_http_for_tests()
    } else {
        request
    };
    #[cfg(not(test))]
    let _ = plain_http;
    let outcome = request.run(PROBE_LIMIT).await;
    match &outcome {
        Ok(output) => result_json(name, url, route.as_str(), Ok(output.http_code)),
        Err(failure) => result_json(name, url, route.as_str(), Err(failure)),
    }
}

/// One result row as the GUI reads it. `stage` is where the probe got to:
/// `http` when a status came back; on a failure, the stage the failure
/// belongs to — `proxy` for reaching the proxy or making the first
/// connection, `tls` for the handshake, `http` for anything after it.
fn result_json(
    name: &str,
    url: &Url,
    route: &str,
    outcome: Result<Option<u16>, &NetFailure>,
) -> Value {
    let host = url.host_str().unwrap_or_default();
    match outcome {
        Ok(status) => json!({
            "target": name,
            "host": host,
            "route": route,
            "stage": "http",
            "ok": true,
            "http_status": status,
        }),
        Err(failure) => json!({
            "target": name,
            "host": host,
            "route": route,
            "stage": failure_stage(failure),
            "ok": false,
            "http_status": match failure { NetFailure::HttpStatus { status } => *status, _ => None },
            "cause": failure.cause(),
            "detail": failure.sentence(),
            "recovery": failure.recovery(),
        }),
    }
}

/// The stage a failure belongs to (see [`result_json`]).
fn failure_stage(failure: &NetFailure) -> &'static str {
    match failure {
        NetFailure::TlsUntrustedIssuer { .. }
        | NetFailure::TlsHostnameMismatch { .. }
        | NetFailure::TlsExpired { .. }
        | NetFailure::TlsRevocationUnavailable { .. }
        | NetFailure::TlsFailed { .. }
        | NetFailure::CaBundleUnreadable
        | NetFailure::CaBundleTampered => "tls",
        NetFailure::Timeout
        | NetFailure::Deadline
        | NetFailure::TooLarge { .. }
        | NetFailure::HttpStatus { .. }
        | NetFailure::WriteFailed
        | NetFailure::TransferInterrupted { .. }
        | NetFailure::ResumeUnsupported
        | NetFailure::Other { .. } => "http",
        _ => "proxy",
    }
}

/// The curl probe for the `get` body, `null` when there is no trusted curl.
async fn curl_probe() -> Value {
    match curl_probe_resolve().await {
        Ok(curl) => {
            let info = curl.info();
            json!({
                "version": info.version_text(),
                "backend": info.backend.to_string(),
                "supports_proxy": info.supports_proxy(),
                "supports_cidr_no_proxy": info.supports_cidr_no_proxy(),
            })
        }
        Err(_) => Value::Null,
    }
}

/// [`TrustedCurl::resolve`] off the async threads: its first call runs
/// `curl --version`.
async fn curl_probe_resolve() -> Result<TrustedCurl, NetFailure> {
    crate::blocking_jobs::run(
        crate::blocking_jobs::Kind::ModelFilesystem,
        TrustedCurl::resolve,
    )
    .await
    .map_err(|error| NetFailure::Spawn(error.to_string()))?
}

/// A launcher failure as an admin refusal.
fn net_refusal(failure: &NetFailure) -> AdminRefusal {
    AdminRefusal {
        cause: failure.cause(),
        detail: failure.sentence(),
        recovery: failure.recovery(),
    }
}

/// A credential change with the password checked by the rules the
/// launcher applies when it reads it back, trimmed as it will be stored.
fn validated_credential(
    credential: Option<CredentialAction>,
) -> Result<Option<CredentialAction>, AdminRefusal> {
    match credential {
        Some(CredentialAction::Set(secret)) => {
            ProxyPassword::new(secret.expose()).map_err(|error| AdminRefusal {
                cause: CAUSE_INVALID_ADMIN_ARGS,
                detail: format!("{OP_NETWORK_SET}: {}; nothing was stored", error.detail),
                recovery: "Type the proxy password again as a single line, then save.",
            })?;
            Ok(Some(CredentialAction::Set(crate::secrets::Secret::new(
                secret.expose().trim().to_owned(),
            ))))
        }
        other => Ok(other),
    }
}

/// The [`ACTION_NETWORK_CONFIGURE`] detail: what changed and the
/// non-secret values now in force. The password is a word, never a value.
fn configure_detail(changed: &[&str], credential: &str, checked: &Loaded) -> Value {
    let effective = &checked.resolved.document;
    json!({
        "changed": changed,
        "proxy": checked.valid.proxy.as_ref().map(|proxy| json!({
            "host": proxy.host(),
            "port": proxy.port(),
            "scheme": proxy.scheme().as_str(),
            "auth": proxy.auth().as_str(),
            "username": proxy.username(),
        })),
        "credential": credential,
        "no_proxy": effective.no_proxy,
        "ca_bundle": effective.ca_bundle.as_ref().map(|bundle| json!({
            "sha256": bundle.sha256,
            "certificates": bundle.certificates,
            "source_path": bundle.source_path,
        })),
        "engine_mirror_host": checked.valid.engine_mirror.as_ref().map(|m| m.host().to_owned()),
        "models_mirror_host": checked.valid.models_mirror.as_ref().map(|m| m.host().to_owned()),
        "locked_by_policy": checked
            .resolved
            .locked_fields()
            .iter()
            .map(|field| field.as_str())
            .collect::<Vec<_>>(),
    })
}

/// A keychain failure as an admin refusal.
fn secret_refusal(error: crate::secrets::SecretError) -> AdminRefusal {
    AdminRefusal {
        cause: error.cause(),
        detail: format!("the proxy password was not changed: {error}"),
        recovery: error.recovery(),
    }
}

/// A CA import failure as an admin refusal.
fn ca_refusal(error: &CaImportError) -> AdminRefusal {
    AdminRefusal {
        cause: match error {
            CaImportError::Copy(_) => CAUSE_INTERNAL_ERROR,
            CaImportError::Source(_) | CaImportError::Content(_) => CAUSE_CA_IMPORT_REFUSED,
        },
        detail: error.to_string(),
        recovery: match error {
            CaImportError::Copy(_) => RECOVERY_INTERNAL,
            CaImportError::Source(_) | CaImportError::Content(_) => RECOVERY_CA,
        },
    }
}

/// `{ source, locked }` for one field.
fn source_json(source: Source) -> Value {
    json!({ "source": source.as_str(), "locked": source.locked() })
}

fn proxy_json(proxy: &ProxyEntry) -> Value {
    json!({ "url": proxy.url, "auth": proxy.auth, "username": proxy.username })
}

fn bundle_json(bundle: &CaBundleEntry) -> Value {
    json!({
        "sha256": bundle.sha256,
        "certificates": bundle.certificates,
        "source_path": bundle.source_path,
        "imported_ts": bundle.imported_ts,
    })
}

/// Refuses any key not in `allowed`, so no argument can smuggle a digest,
/// a tag or a raw CA string in.
fn refuse_unknown_keys(args: &Value, allowed: &[&str], op: &str) -> Result<(), AdminRefusal> {
    let Some(object) = args.as_object() else {
        if args.is_null() {
            return Ok(());
        }
        return Err(AdminRefusal {
            cause: CAUSE_INVALID_ADMIN_ARGS,
            detail: format!("{op} takes an object of arguments, not {args}"),
            recovery: RECOVERY_FIX_ARGS,
        });
    };
    if let Some(unknown) = object.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(AdminRefusal {
            cause: CAUSE_INVALID_ADMIN_ARGS,
            detail: format!("{op} does not take an argument named {unknown:?}"),
            recovery: RECOVERY_FIX_ARGS,
        });
    }
    Ok(())
}

/// What one patch key asks of the field it names.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Change<T> {
    /// The key was absent: leave the stored value alone.
    Keep,
    /// The key was `null`: clear the stored value.
    Clear,
    /// The key carried a value: store it.
    Set(T),
}

impl<T> Change<T> {
    fn is_keep(&self) -> bool {
        matches!(self, Self::Keep)
    }

    /// Writes the change into `slot`, when there is one.
    fn apply_to(&self, slot: &mut Option<T>)
    where
        T: Clone,
    {
        match self {
            Self::Keep => {}
            Self::Clear => *slot = None,
            Self::Set(value) => *slot = Some(value.clone()),
        }
    }
}

/// What `admin.network.set` was asked to change.
struct Patch {
    proxy: Change<ProxyEntry>,
    credential: Option<CredentialAction>,
    no_proxy: Option<Vec<String>>,
    /// `Clear` removes the bundle; `Set(path)` imports one.
    ca_bundle: Change<PathBuf>,
    engine_mirror: Change<String>,
    models_mirror: Change<String>,
}

impl Patch {
    const KEYS: [&'static str; 6] = [
        "proxy",
        "credential",
        "no_proxy",
        "ca_bundle",
        "engine_mirror",
        "models_mirror",
    ];

    fn parse(args: &Value) -> Result<Self, AdminRefusal> {
        refuse_unknown_keys(args, &Self::KEYS, OP_NETWORK_SET)?;
        let invalid = |detail: String| AdminRefusal {
            cause: CAUSE_INVALID_ADMIN_ARGS,
            detail,
            recovery: RECOVERY_FIX_ARGS,
        };
        let proxy = match args.get("proxy") {
            None => Change::Keep,
            Some(Value::Null) => Change::Clear,
            Some(value) => Change::Set(proxy_arg(value)?),
        };
        let no_proxy = match args.get("no_proxy") {
            None => None,
            Some(Value::Array(entries)) => Some(
                entries
                    .iter()
                    .map(|entry| {
                        entry.as_str().map(str::to_owned).ok_or_else(|| {
                            invalid(format!(
                                "{OP_NETWORK_SET} needs every no_proxy entry to be a string, not \
                                 {entry}"
                            ))
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            Some(other) => {
                return Err(invalid(format!(
                    "{OP_NETWORK_SET} needs \"no_proxy\" to be a list of strings, not {other}"
                )));
            }
        };
        let ca_bundle = match args.get("ca_bundle") {
            None => Change::Keep,
            Some(Value::Null) => Change::Clear,
            Some(value) => {
                let path = value
                    .as_object()
                    .filter(|object| object.len() == 1)
                    .and_then(|object| object.get("path"))
                    .and_then(Value::as_str)
                    .filter(|path| !path.is_empty())
                    .ok_or_else(|| {
                        invalid(format!(
                            "{OP_NETWORK_SET} needs \"ca_bundle\" to be null or \
                             {{\"path\": \"<file>\"}}"
                        ))
                    })?;
                Change::Set(PathBuf::from(path))
            }
        };
        // Stored normalized (lowercase host, trailing slash): what the
        // document reads back is what the download paths will use. The
        // policy's allowlist is the document validation's.
        let mirror = |key: &'static str| -> Result<Change<String>, AdminRefusal> {
            match args.get(key) {
                None => Ok(Change::Keep),
                Some(Value::Null) => Ok(Change::Clear),
                Some(Value::String(url)) => pam_net::MirrorBase::parse(url, key)
                    .map(|base| Change::Set(base.as_str().to_owned()))
                    .map_err(|error| AdminRefusal {
                        cause: CAUSE_NETWORK_INVALID,
                        detail: error.to_string(),
                        recovery: RECOVERY_RELOAD,
                    }),
                Some(other) => Err(invalid(format!(
                    "{OP_NETWORK_SET} needs {key:?} to be a string or null, not {other}"
                ))),
            }
        };
        Ok(Self {
            proxy,
            credential: credential_arg(args)?,
            no_proxy,
            ca_bundle,
            engine_mirror: mirror("engine_mirror")?,
            models_mirror: mirror("models_mirror")?,
        })
    }

    fn is_empty(&self) -> bool {
        self.proxy.is_keep()
            && self.credential.is_none()
            && self.no_proxy.is_none()
            && self.ca_bundle.is_keep()
            && self.engine_mirror.is_keep()
            && self.models_mirror.is_keep()
    }

    /// The document fields this patch touches. The credential counts as
    /// the proxy's: it is locked with it.
    fn fields(&self) -> Vec<Field> {
        let mut fields = Vec::new();
        if !self.proxy.is_keep() || self.credential.is_some() {
            fields.push(Field::Proxy);
        }
        if self.no_proxy.is_some() {
            fields.push(Field::NoProxy);
        }
        if !self.ca_bundle.is_keep() {
            fields.push(Field::CaBundle);
        }
        if !self.engine_mirror.is_keep() {
            fields.push(Field::EngineMirror);
        }
        if !self.models_mirror.is_keep() {
            fields.push(Field::ModelsMirror);
        }
        fields
    }

    /// The names the audit rows carry, in patch order.
    fn changed_names(&self) -> Vec<&'static str> {
        let mut names = Vec::new();
        if !self.proxy.is_keep() {
            names.push("proxy");
        }
        if self.credential.is_some() {
            names.push("credential");
        }
        if self.no_proxy.is_some() {
            names.push("no_proxy");
        }
        if !self.ca_bundle.is_keep() {
            names.push("ca_bundle");
        }
        if !self.engine_mirror.is_keep() {
            names.push("engine_mirror");
        }
        if !self.models_mirror.is_keep() {
            names.push("models_mirror");
        }
        names
    }
}

/// `{ url, auth, username? }` as a stored entry, shape-checked here and
/// value-checked by the document validation.
fn proxy_arg(value: &Value) -> Result<ProxyEntry, AdminRefusal> {
    let malformed = |detail: String| AdminRefusal {
        cause: CAUSE_INVALID_ADMIN_ARGS,
        detail,
        recovery: RECOVERY_FIX_ARGS,
    };
    let object = value.as_object().ok_or_else(|| {
        malformed(format!(
            "{OP_NETWORK_SET} needs \"proxy\" to be null or {{\"url\", \"auth\", \"username\"}}"
        ))
    })?;
    if let Some(unknown) = object
        .keys()
        .find(|key| !["url", "auth", "username"].contains(&key.as_str()))
    {
        return Err(malformed(format!(
            "{OP_NETWORK_SET}: \"proxy\" does not take a field named {unknown:?}"
        )));
    }
    let url = object
        .get("url")
        .and_then(Value::as_str)
        .ok_or_else(|| malformed(format!("{OP_NETWORK_SET}: \"proxy.url\" must be a string")))?;
    let auth = match object.get("auth") {
        None | Some(Value::Null) => ProxyAuth::None,
        Some(Value::String(word)) => ProxyAuth::parse(word)
            .map_err(|error| malformed(format!("{OP_NETWORK_SET}: {}", error.detail)))?,
        Some(other) => {
            return Err(malformed(format!(
                "{OP_NETWORK_SET}: \"proxy.auth\" must be none, basic or anyauth, not {other}"
            )));
        }
    };
    let username = match object.get("username") {
        None | Some(Value::Null) => None,
        Some(Value::String(name)) if name.trim().is_empty() => None,
        Some(Value::String(name)) => Some(name.trim().to_owned()),
        Some(other) => {
            return Err(malformed(format!(
                "{OP_NETWORK_SET}: \"proxy.username\" must be a string or null, not {other}"
            )));
        }
    };
    // Stored normalized: what `Proxy::parse` accepts is what is kept, so
    // the document reads back exactly as the launcher will render it.
    let parsed =
        pam_net::Proxy::parse(url, auth, username.as_deref()).map_err(|error| AdminRefusal {
            cause: CAUSE_NETWORK_INVALID,
            detail: error.to_string(),
            recovery: RECOVERY_RELOAD,
        })?;
    Ok(ProxyEntry {
        url: parsed.url(),
        auth: auth.as_str().to_owned(),
        username: parsed.username().map(str::to_owned),
    })
}

/// The optional `credential` argument: `{ "set": "…" }` stores a password,
/// `{ "clear": true }` deletes one, absent leaves it alone. Same rules as a
/// connector credential: trimmed, one line, never empty.
fn credential_arg(args: &Value) -> Result<Option<CredentialAction>, AdminRefusal> {
    let malformed = || AdminRefusal {
        cause: CAUSE_INVALID_ADMIN_ARGS,
        detail: format!(
            "{OP_NETWORK_SET} needs \"credential\" to be {{\"set\": \"<password>\"}} or \
             {{\"clear\": true}}"
        ),
        recovery: RECOVERY_FIX_ARGS,
    };
    let value = match args.get("credential") {
        None | Some(Value::Null) => return Ok(None),
        Some(value) => value,
    };
    let object = value.as_object().ok_or_else(malformed)?;
    if object.len() != 1 {
        return Err(malformed());
    }
    if let Some(secret) = object.get("set") {
        let secret = secret.as_str().ok_or_else(malformed)?;
        let secret = secret.trim();
        if secret.is_empty() {
            return Err(malformed());
        }
        if secret.chars().any(char::is_control) {
            return Err(AdminRefusal {
                cause: CAUSE_INVALID_ADMIN_ARGS,
                detail: format!(
                    "{OP_NETWORK_SET}: the proxy password contains a control character or line \
                     break; nothing was stored"
                ),
                recovery: "Type the proxy password again as a single line, then save.",
            });
        }
        return Ok(Some(CredentialAction::Set(crate::secrets::Secret::new(
            secret.to_owned(),
        ))));
    }
    if object.get("clear").and_then(Value::as_bool) == Some(true) {
        return Ok(Some(CredentialAction::Clear));
    }
    Err(malformed())
}
