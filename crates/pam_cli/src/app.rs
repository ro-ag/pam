use std::{
    io::{self, Write},
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use pam_core::{
    ApprovalId, CallerCredential, CallerId, EvidenceHandle, GrantId, IdempotencyKey, ProjectId,
    RequestId,
};
use pam_daemon::{ClientExchange, StatusError};
use pam_model::{
    ImportRequest, LicenseConsent, LicenseSnapshot, ModelDescriptor, ModelKey, import_existing,
};
use pam_platform::{
    CallerKind, IdentityError, LocalEndpoint, ProjectIdentity, caller_id, discover_project,
    discover_project_id, user_data_dir,
};
use pam_policy::{
    ApprovalRequirement, CapabilityName, Effect, Grant, ResourceName, ResourceScope,
    redact_audit_detail,
};
use pam_protocol::{ModelMessage, ModelRole, ResultBody, ResultPayload};
use pam_store::{
    AppendAuditEvent, ApprovalDecision, ApprovalDecisionOutcome, AuditPruneOutcome,
    AuthorizationAudit, AuthorizationOutcome, AuthorizationRequest, CallerAuthentication,
    CallerRevocation, EvidencePruneOutcome, EvidenceRetention, GrantRevocation, PutGrant, Store,
};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::{
    audit::encode_audit_export,
    command::{CallerKindArg, RetentionScopeArg},
    evidence::{EvidenceError, download_evidence, write_new_output},
    flow::{FlowCatalog, FlowCatalogError},
    render::{
        EXIT_OPERATION_FAILED, EXIT_PENDING, Presentation, escape_text, present_result,
        render_events,
    },
    request::{
        NativeCredentialError, RequestContext, RequestContextError, delete_native_credential,
        load_native_credential, store_native_credential,
    },
};

const STATUS_TIMEOUT: Duration = Duration::from_secs(2);
const READ_TIMEOUT: Duration = Duration::from_secs(5);
const AUDIT_RETENTION_MS: u64 = 30 * 24 * 60 * 60 * 1_000;
const APPROVAL_LIFETIME_MS: u64 = 5 * 60 * 1_000;

fn open_local_administrative_store() -> Result<(ProjectId, CallerId, Store), i32> {
    let project_id = discover_project_id(".").map_err(|error| {
        report_identity_error(&error);
        EXIT_OPERATION_FAILED
    })?;
    let caller_id = caller_id(CallerKind::Cli).map_err(|error| {
        report_identity_error(&error);
        EXIT_OPERATION_FAILED
    })?;
    let data_dir = user_data_dir().map_err(|error| {
        report_identity_error(&error);
        EXIT_OPERATION_FAILED
    })?;
    let store =
        Store::open(data_dir.join("state.sqlite3")).map_err(|error| report_store_error(&error))?;
    Ok((project_id, caller_id, store))
}

pub(crate) async fn audit_export(
    output: &Path,
    after_sequence: u64,
    through_sequence: Option<u64>,
    approval_id: Option<ApprovalId>,
    limit: usize,
) -> i32 {
    if through_sequence.is_some_and(|through| through < after_sequence) {
        eprintln!("Audit high-water sequence cannot precede the after sequence.");
        return EXIT_OPERATION_FAILED;
    }
    if i64::try_from(after_sequence).is_err()
        || through_sequence.is_some_and(|through| i64::try_from(through).is_err())
    {
        eprintln!("Audit sequence exceeds the supported storage range.");
        return EXIT_OPERATION_FAILED;
    }
    let (project_id, caller_id, store) = match open_local_administrative_store() {
        Ok(context) => context,
        Err(exit_code) => return exit_code,
    };
    let resource = ResourceName::parse(format!(
        "audit:export:after={after_sequence}:through={}:limit={limit}",
        through_sequence.map_or_else(|| "capture".to_owned(), |value| value.to_string())
    ))
    .expect("bounded numeric audit export resource is valid");
    if let Err(exit_code) = authorize_local_operation(
        &store,
        &caller_id,
        &project_id,
        CapabilityName::parse("audit.export").expect("static capability is valid"),
        resource,
        approval_id,
        "audit.export",
    )
    .await
    {
        let _ = store.shutdown().await;
        return exit_code;
    }
    let page = match store
        .export_audit_events(
            project_id.clone(),
            after_sequence,
            through_sequence,
            u32::try_from(limit).expect("CLI audit limit fits u32"),
        )
        .await
    {
        Ok(page) => page,
        Err(error) => {
            let _ = store.shutdown().await;
            return report_store_error(&error);
        }
    };
    let bytes = encode_audit_export(&page);
    if let Err(error) = write_new_output(output, &bytes) {
        let _ = store.shutdown().await;
        eprintln!("{}", escape_text(&error.to_string()));
        if let Some(source) = std::error::Error::source(&error) {
            eprintln!("Details: {}", escape_text(&source.to_string()));
        }
        return EXIT_OPERATION_FAILED;
    }
    if let Err(error) = store.shutdown().await {
        return report_store_error(&error);
    }
    println!(
        "Wrote {} redacted audit events to {} (through_sequence={}, next_after_sequence={}, has_more={}).",
        page.events.len(),
        escape_text(&output.display().to_string()),
        page.through_sequence,
        page.next_after_sequence,
        page.has_more
    );
    0
}

pub(crate) async fn retention_prune(
    scope: RetentionScopeArg,
    created_before_unix_ms: u64,
    approval_id: Option<ApprovalId>,
    limit: usize,
) -> i32 {
    if i64::try_from(created_before_unix_ms).is_err() {
        eprintln!("Retention cutoff exceeds the supported storage range.");
        return EXIT_OPERATION_FAILED;
    }
    let (project_id, caller_id, store) = match open_local_administrative_store() {
        Ok(context) => context,
        Err(exit_code) => return exit_code,
    };
    let now = now_ms();
    let retention = match scope {
        RetentionScopeArg::Session => EvidenceRetention::Session,
        RetentionScopeArg::Project => EvidenceRetention::Project,
    };
    let limit = u32::try_from(limit).expect("CLI retention limit fits u32");
    let resource = ResourceName::parse(format!(
        "retention:evidence:scope={}:before={created_before_unix_ms}:limit={limit}",
        retention_label(retention)
    ))
    .expect("bounded numeric retention resource is valid");
    if let Err(exit_code) = authorize_local_operation(
        &store,
        &caller_id,
        &project_id,
        CapabilityName::parse("retention.prune").expect("static capability is valid"),
        resource,
        approval_id,
        "retention.prune",
    )
    .await
    {
        let _ = store.shutdown().await;
        return exit_code;
    }
    let evidence = match store
        .prune_evidence(project_id.clone(), retention, created_before_unix_ms, limit)
        .await
    {
        Ok(outcome) => outcome,
        Err(error) => {
            let _ = store.shutdown().await;
            return report_store_error(&error);
        }
    };
    if let Err(error) = record_evidence_retention(
        &store,
        project_id.clone(),
        caller_id.clone(),
        retention,
        created_before_unix_ms,
        evidence,
    )
    .await
    {
        eprintln!(
            "Evidence retention changed {} handles and removed {} blobs; {} blobs remain pending safe cleanup (cleanup_unresolved={}).",
            evidence.handles_deleted,
            evidence.blobs_deleted,
            evidence.blobs_pending,
            evidence.cleanup_unresolved
        );
        let _ = store.shutdown().await;
        return report_store_error(&error);
    }
    let audit = match store
        .prune_audit_events(project_id.clone(), now, limit)
        .await
    {
        Ok(outcome) => outcome,
        Err(error) => {
            eprintln!(
                "Evidence retention completed (handles_deleted={}, blobs_deleted={}, blobs_pending={}, cleanup_unresolved={}), but audit retention did not complete.",
                evidence.handles_deleted,
                evidence.blobs_deleted,
                evidence.blobs_pending,
                evidence.cleanup_unresolved
            );
            let _ = store.shutdown().await;
            return report_store_error(&error);
        }
    };
    if let Err(error) = record_audit_retention(&store, project_id, caller_id, audit).await {
        eprintln!(
            "Retention completed (handles_deleted={}, blobs_deleted={}, blobs_pending={}, cleanup_unresolved={}, expired_audit_events_deleted={}), but PAM could not append the completion event.",
            evidence.handles_deleted,
            evidence.blobs_deleted,
            evidence.blobs_pending,
            evidence.cleanup_unresolved,
            audit.deleted
        );
        let _ = store.shutdown().await;
        return report_store_error(&error);
    }
    if let Err(error) = store.shutdown().await {
        return report_store_error(&error);
    }
    report_retention_outcome(evidence, audit)
}

fn report_retention_outcome(evidence: EvidencePruneOutcome, audit: AuditPruneOutcome) -> i32 {
    let summary = format!(
        "Pruned {} evidence handles, removed {} unreferenced blobs, left {} blobs pending safe cleanup, and pruned {} expired audit events (cleanup_unresolved={}, has_more={}).",
        evidence.handles_deleted,
        evidence.blobs_deleted,
        evidence.blobs_pending,
        audit.deleted,
        evidence.cleanup_unresolved,
        evidence.has_more || audit.has_more
    );
    if evidence.cleanup_unresolved {
        eprintln!("{summary}");
        eprintln!("Recovery: retry the same bounded retention command.");
        EXIT_OPERATION_FAILED
    } else {
        println!("{summary}");
        0
    }
}

async fn record_evidence_retention(
    store: &Store,
    project_id: ProjectId,
    caller_id: CallerId,
    retention: EvidenceRetention,
    created_before_unix_ms: u64,
    outcome: EvidencePruneOutcome,
) -> Result<(), pam_store::StoreError> {
    let detail = format!(
        "scope={} created_before_unix_ms={created_before_unix_ms} handles_deleted={} blobs_deleted={} blobs_pending={} cleanup_unresolved={} has_more={}",
        retention_label(retention),
        outcome.handles_deleted,
        outcome.blobs_deleted,
        outcome.blobs_pending,
        outcome.cleanup_unresolved,
        outcome.has_more
    );
    store
        .append_audit_event(audit_event(
            project_id,
            caller_id,
            "retention.evidence_pruned",
            "apply",
            if outcome.cleanup_unresolved {
                "cleanup_unresolved"
            } else if outcome.blobs_pending > 0 {
                "cleanup_pending"
            } else if outcome.handles_deleted == 0 && outcome.blobs_deleted == 0 {
                "unchanged"
            } else {
                "changed"
            },
            &detail,
            now_ms(),
        ))
        .await?;
    Ok(())
}

async fn record_audit_retention(
    store: &Store,
    project_id: ProjectId,
    caller_id: CallerId,
    outcome: AuditPruneOutcome,
) -> Result<(), pam_store::StoreError> {
    let detail = format!(
        "expired_events_deleted={} has_more={}",
        outcome.deleted, outcome.has_more
    );
    store
        .append_audit_event(audit_event(
            project_id,
            caller_id,
            "retention.audit_pruned",
            "apply",
            if outcome.deleted == 0 {
                "unchanged"
            } else {
                "changed"
            },
            &detail,
            now_ms(),
        ))
        .await?;
    Ok(())
}

async fn authorize_local_operation(
    store: &Store,
    caller_id: &CallerId,
    project_id: &ProjectId,
    capability: CapabilityName,
    resource: ResourceName,
    approval_id: Option<ApprovalId>,
    action: &str,
) -> Result<(), i32> {
    let credential = match load_native_credential(caller_id.clone()).await {
        Ok(credential) => credential,
        Err(error) => {
            record_local_authentication_failure(
                store,
                caller_id.clone(),
                project_id.clone(),
                action,
                &capability,
                &resource,
                "credential_unavailable",
            )
            .await
            .map_err(|audit_error| report_store_error(&audit_error))?;
            return Err(report_native_credential_error(&error));
        }
    };
    let authentication = store
        .authenticate_caller(caller_id.clone(), credential)
        .await
        .map_err(|error| report_store_error(&error))?;
    if authentication != CallerAuthentication::Authenticated {
        record_local_authentication_failure(
            store,
            caller_id.clone(),
            project_id.clone(),
            action,
            &capability,
            &resource,
            "unauthenticated",
        )
        .await
        .map_err(|error| report_store_error(&error))?;
        eprintln!("Caller authentication failed.");
        eprintln!("Recovery: pam caller register");
        return Err(EXIT_OPERATION_FAILED);
    }

    let now = now_ms();
    let detail = format!(
        "capability={} resource={} detail=local administrative policy evaluated",
        capability.as_str(),
        resource.as_str()
    );
    let outcome = store
        .authorize_audited(
            AuthorizationRequest {
                caller_id: caller_id.clone(),
                project_id: project_id.clone(),
                capability: capability.clone(),
                resource: resource.clone(),
                approval_id,
            },
            AuthorizationAudit {
                event_id: Uuid::new_v4().to_string(),
                action: action.to_owned(),
                redacted_detail: redact_audit_detail(detail.as_bytes()),
                retain_until_ms: now.saturating_add(AUDIT_RETENTION_MS).min(i64::MAX as u64),
            },
            now,
            APPROVAL_LIFETIME_MS,
        )
        .await
        .map_err(|error| report_store_error(&error))?;
    match outcome {
        AuthorizationOutcome::Allowed => Ok(()),
        AuthorizationOutcome::Denied => {
            eprintln!(
                "Project policy denied {}.",
                escape_text(capability.as_str())
            );
            eprintln!(
                "Recovery: pam access grant {} --resource {}",
                escape_text(capability.as_str()),
                escape_text(resource.as_str())
            );
            Err(EXIT_OPERATION_FAILED)
        }
        AuthorizationOutcome::ApprovalRequired { approval_id, .. } => {
            eprintln!("This exact operation requires approval {approval_id}.");
            eprintln!(
                "Recovery: pam approval approve {approval_id}, then retry with --approval-id {approval_id}"
            );
            Err(EXIT_OPERATION_FAILED)
        }
        AuthorizationOutcome::ApprovalDenied => {
            eprintln!("The exact-effect approval was denied.");
            Err(EXIT_OPERATION_FAILED)
        }
        AuthorizationOutcome::ApprovalExpired => {
            eprintln!("The exact-effect approval expired.");
            Err(EXIT_OPERATION_FAILED)
        }
    }
}

async fn record_local_authentication_failure(
    store: &Store,
    caller_id: CallerId,
    project_id: ProjectId,
    action: &str,
    capability: &CapabilityName,
    resource: &ResourceName,
    outcome: &str,
) -> Result<(), pam_store::StoreError> {
    let occurred_at_ms = now_ms();
    let detail = format!(
        "capability={} resource={} detail=local administrative authentication failed",
        capability.as_str(),
        resource.as_str()
    );
    store
        .append_audit_event(audit_event(
            project_id,
            caller_id,
            action,
            "deny",
            outcome,
            &detail,
            occurred_at_ms,
        ))
        .await?;
    Ok(())
}

pub(crate) async fn caller_register(kind: CallerKindArg) -> i32 {
    let caller_id = match caller_id(caller_kind(kind)) {
        Ok(caller_id) => caller_id,
        Err(error) => {
            report_identity_error(&error);
            return EXIT_OPERATION_FAILED;
        }
    };
    let data_dir = match user_data_dir() {
        Ok(data_dir) => data_dir,
        Err(error) => {
            report_identity_error(&error);
            return EXIT_OPERATION_FAILED;
        }
    };
    let credential = CallerCredential::new(format!(
        "pam_{}_{}",
        Uuid::new_v4().simple(),
        Uuid::new_v4().simple()
    ));
    let store = match Store::open(data_dir.join("state.sqlite3")) {
        Ok(store) => store,
        Err(error) => return report_store_error(&error),
    };
    let previous_credential = match load_native_credential(caller_id.clone()).await {
        Ok(credential) => Some(credential),
        Err(error) if error.is_not_found() => None,
        Err(error) => {
            let _ = store.shutdown().await;
            return report_native_credential_error(&error);
        }
    };
    if let Err(error) = store_native_credential(caller_id.clone(), credential.clone()).await {
        let _ = store.shutdown().await;
        return report_native_credential_error(&error);
    }
    let result = store
        .register_caller(caller_id.clone(), credential.clone(), now_ms())
        .await;
    let shutdown = store.shutdown().await;
    let registration = match result {
        Ok(registration) => registration,
        Err(error) => {
            restore_native_credential(caller_id, previous_credential).await;
            return report_store_error(&error);
        }
    };
    if let Err(error) = shutdown {
        return report_store_error(&error);
    }

    println!("Registered caller {}.", registration.caller_id);
    println!("Credential stored in the operating system's native credential store.");
    0
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn model_import(
    key: ModelKey,
    path: &Path,
    digest: pam_core::ContentDigest,
    size_bytes: u64,
    license_id: String,
    license_url: String,
    license_notice_digest: pam_core::ContentDigest,
    accept_license: bool,
    approval_id: Option<ApprovalId>,
) -> i32 {
    if !accept_license {
        eprintln!("Model import requires --accept-license for the exact supplied metadata.");
        return EXIT_OPERATION_FAILED;
    }
    let Some(filename) = path.file_name().and_then(std::ffi::OsStr::to_str) else {
        eprintln!("Model path must end in a Unicode GGUF filename.");
        return EXIT_OPERATION_FAILED;
    };
    let license = match LicenseSnapshot::new(license_id, license_url, license_notice_digest) {
        Ok(license) => license,
        Err(error) => {
            eprintln!("{}", escape_text(&error.to_string()));
            return EXIT_OPERATION_FAILED;
        }
    };
    let descriptor = match ModelDescriptor::new(
        key,
        filename.to_owned(),
        digest.clone(),
        size_bytes,
        license,
    ) {
        Ok(descriptor) => descriptor,
        Err(error) => {
            eprintln!("{}", escape_text(&error.to_string()));
            return EXIT_OPERATION_FAILED;
        }
    };
    let (project_id, caller_id, store) = match open_local_administrative_store() {
        Ok(context) => context,
        Err(exit_code) => return exit_code,
    };
    let resource = model_import_resource(&descriptor);
    if let Err(exit_code) = authorize_local_operation(
        &store,
        &caller_id,
        &project_id,
        CapabilityName::parse("model.import").expect("static capability is valid"),
        resource,
        approval_id,
        "model.import",
    )
    .await
    {
        let _ = store.shutdown().await;
        return exit_code;
    }
    let consent = LicenseConsent::accept(&descriptor);
    let import_request = ImportRequest {
        descriptor,
        consent,
        path: path.to_path_buf(),
        registered_at_ms: now_ms(),
    };
    let imported = match tokio::task::spawn_blocking(move || import_existing(import_request)).await
    {
        Ok(Ok(imported)) => imported,
        Ok(Err(error)) => {
            let _ = store.shutdown().await;
            eprintln!("{}", escape_text(&error.to_string()));
            return EXIT_OPERATION_FAILED;
        }
        Err(_) => {
            let _ = store.shutdown().await;
            eprintln!("PAM could not complete model verification.");
            return EXIT_OPERATION_FAILED;
        }
    };
    let registered = match store.put_model(imported).await {
        Ok(registered) => registered,
        Err(error) => {
            let _ = store.shutdown().await;
            return report_store_error(&error);
        }
    };
    if let Err(error) = store.shutdown().await {
        return report_store_error(&error);
    }
    println!(
        "Registered verified model {} ({} bytes, {}).",
        registered.key, registered.size_bytes, registered.digest
    );
    0
}

pub(crate) fn model_import_resource(descriptor: &ModelDescriptor) -> ResourceName {
    let mut hasher = Sha256::new();
    hash_model_import_field(&mut hasher, b"pam-model-import-effect-v1");
    hash_model_import_field(&mut hasher, descriptor.key.vendor().as_bytes());
    hash_model_import_field(&mut hasher, descriptor.key.name().as_bytes());
    hash_model_import_field(&mut hasher, descriptor.filename.as_bytes());
    hasher.update(descriptor.expected_size_bytes.to_le_bytes());
    hash_model_import_field(&mut hasher, descriptor.expected_digest.as_str().as_bytes());
    hash_model_import_field(&mut hasher, descriptor.license.identifier().as_bytes());
    hash_model_import_field(&mut hasher, descriptor.license.notice_url().as_bytes());
    hash_model_import_field(
        &mut hasher,
        descriptor.license.notice_digest().as_str().as_bytes(),
    );
    let digest = pam_core::ContentDigest::from_sha256(hasher.finalize().into());
    ResourceName::parse(format!(
        "model:{}:import-effect={digest}",
        descriptor.key.id()
    ))
    .expect("validated model descriptor forms a bounded policy resource")
}

fn hash_model_import_field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(bytes);
}

pub(crate) async fn model_generate(
    model: ModelKey,
    prompt: String,
    system: Option<String>,
    max_output_tokens: u32,
    timeout: Duration,
    approval_id: Option<ApprovalId>,
) -> i32 {
    let mut messages = Vec::with_capacity(usize::from(system.is_some()) + 1);
    if let Some(system) = system {
        match ModelMessage::new(ModelRole::System, system) {
            Ok(message) => messages.push(message),
            Err(error) => {
                eprintln!("{}", escape_text(&error.to_string()));
                return EXIT_OPERATION_FAILED;
            }
        }
    }
    match ModelMessage::new(ModelRole::User, prompt) {
        Ok(message) => messages.push(message),
        Err(error) => {
            eprintln!("{}", escape_text(&error.to_string()));
            return EXIT_OPERATION_FAILED;
        }
    }
    let Some(context) = discover_context(approval_id).await else {
        return EXIT_OPERATION_FAILED;
    };
    let deadline_unix_ms =
        now_ms().saturating_add(u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX));
    let request =
        match context.model_infer(model.id(), messages, max_output_tokens, deadline_unix_ms) {
            Ok(request) => request,
            Err(error) => {
                eprintln!("{}", escape_text(&error.to_string()));
                return EXIT_OPERATION_FAILED;
            }
        };
    match exchange(&request, timeout).await {
        Ok(exchange) if !exchange.events.is_empty() => unexpected_events("model inference"),
        Ok(exchange)
            if matches!(
                exchange.result.body,
                ResultBody::Success {
                    payload: ResultPayload::ModelGeneration(_),
                    ..
                } | ResultBody::Failure(_)
            ) =>
        {
            emit(present_result(&exchange.result.body))
        }
        Ok(_) => unexpected_result("model inference"),
        Err(error) => report_exchange_error(&error),
    }
}

pub(crate) async fn caller_revoke(kind: CallerKindArg) -> i32 {
    let caller_id = match caller_id(caller_kind(kind)) {
        Ok(caller_id) => caller_id,
        Err(error) => {
            report_identity_error(&error);
            return EXIT_OPERATION_FAILED;
        }
    };
    let data_dir = match user_data_dir() {
        Ok(data_dir) => data_dir,
        Err(error) => {
            report_identity_error(&error);
            return EXIT_OPERATION_FAILED;
        }
    };
    let store = match Store::open(data_dir.join("state.sqlite3")) {
        Ok(store) => store,
        Err(error) => return report_store_error(&error),
    };
    let result = store.revoke_caller(caller_id.clone(), now_ms()).await;
    let shutdown = store.shutdown().await;
    let revocation = match result {
        Ok(revocation) => revocation,
        Err(error) => return report_store_error(&error),
    };
    if let Err(error) = shutdown {
        return report_store_error(&error);
    }
    match revocation {
        CallerRevocation::Revoked => {
            println!("Revoked caller {caller_id}.");
            delete_revoked_native_credential(caller_id).await
        }
        CallerRevocation::AlreadyRevoked => {
            println!("Caller {caller_id} is already revoked.");
            delete_revoked_native_credential(caller_id).await
        }
        CallerRevocation::UnknownCaller => {
            eprintln!("Caller {caller_id} is not registered.");
            EXIT_OPERATION_FAILED
        }
    }
}

pub(crate) async fn access_grant(
    kind: CallerKindArg,
    capability: CapabilityName,
    resource: Option<ResourceName>,
    deny: bool,
    require_approval: bool,
    expires_at_ms: Option<u64>,
) -> i32 {
    let caller_id = match caller_id(caller_kind(kind)) {
        Ok(caller_id) => caller_id,
        Err(error) => {
            report_identity_error(&error);
            return EXIT_OPERATION_FAILED;
        }
    };
    let project_id = match discover_project_id(".") {
        Ok(project_id) => project_id,
        Err(error) => {
            report_identity_error(&error);
            return EXIT_OPERATION_FAILED;
        }
    };
    let data_dir = match user_data_dir() {
        Ok(data_dir) => data_dir,
        Err(error) => {
            report_identity_error(&error);
            return EXIT_OPERATION_FAILED;
        }
    };
    let store = match Store::open(data_dir.join("state.sqlite3")) {
        Ok(store) => store,
        Err(error) => return report_store_error(&error),
    };
    let grant_id = GrantId::new(Uuid::new_v4().to_string());
    let created_at_ms = now_ms();
    let result = store
        .put_grant(PutGrant {
            grant: Grant {
                id: grant_id.clone(),
                caller: caller_id,
                project: project_id,
                capability,
                resource: resource.map_or(ResourceScope::Any, ResourceScope::Exact),
                effect: if deny { Effect::Deny } else { Effect::Allow },
                approval: if require_approval {
                    ApprovalRequirement::Once
                } else {
                    ApprovalRequirement::None
                },
                expires_at_ms,
                revoked_at_ms: None,
            },
            created_at_ms,
        })
        .await;
    let shutdown = store.shutdown().await;
    let policy = match result {
        Ok(policy) => policy,
        Err(error) => return report_store_error(&error),
    };
    if let Err(error) = shutdown {
        return report_store_error(&error);
    }
    println!(
        "Added grant {grant_id} to project policy version {}.",
        policy.version
    );
    0
}

pub(crate) async fn access_revoke(grant_id: GrantId) -> i32 {
    let data_dir = match user_data_dir() {
        Ok(data_dir) => data_dir,
        Err(error) => {
            report_identity_error(&error);
            return EXIT_OPERATION_FAILED;
        }
    };
    let store = match Store::open(data_dir.join("state.sqlite3")) {
        Ok(store) => store,
        Err(error) => return report_store_error(&error),
    };
    let result = store.revoke_grant(grant_id.clone(), now_ms()).await;
    let shutdown = store.shutdown().await;
    let revocation = match result {
        Ok(revocation) => revocation,
        Err(error) => return report_store_error(&error),
    };
    if let Err(error) = shutdown {
        return report_store_error(&error);
    }
    match revocation {
        GrantRevocation::Revoked => println!("Revoked grant {grant_id}."),
        GrantRevocation::AlreadyRevoked => println!("Grant {grant_id} is already revoked."),
        GrantRevocation::UnknownGrant => {
            eprintln!("Grant {grant_id} does not exist.");
            return EXIT_OPERATION_FAILED;
        }
    }
    0
}

pub(crate) async fn approval_decide(approval_id: ApprovalId, decision: ApprovalDecision) -> i32 {
    let approver_id = match caller_id(CallerKind::Cli) {
        Ok(caller_id) => caller_id,
        Err(error) => {
            report_identity_error(&error);
            return EXIT_OPERATION_FAILED;
        }
    };
    let data_dir = match user_data_dir() {
        Ok(data_dir) => data_dir,
        Err(error) => {
            report_identity_error(&error);
            return EXIT_OPERATION_FAILED;
        }
    };
    let store = match Store::open(data_dir.join("state.sqlite3")) {
        Ok(store) => store,
        Err(error) => return report_store_error(&error),
    };
    let result = store
        .decide_approval(approval_id.clone(), approver_id, decision, now_ms())
        .await;
    let shutdown = store.shutdown().await;
    let outcome = match result {
        Ok(outcome) => outcome,
        Err(error) => return report_store_error(&error),
    };
    if let Err(error) = shutdown {
        return report_store_error(&error);
    }
    match outcome {
        ApprovalDecisionOutcome::Approved => println!("Approved {approval_id}."),
        ApprovalDecisionOutcome::Denied => println!("Denied {approval_id}."),
        ApprovalDecisionOutcome::Expired => {
            eprintln!("Approval {approval_id} expired before the decision.");
            return EXIT_OPERATION_FAILED;
        }
    }
    0
}

pub(crate) async fn status(approval_id: Option<ApprovalId>) -> i32 {
    let Some(context) = discover_context(approval_id).await else {
        return EXIT_OPERATION_FAILED;
    };
    match exchange(&context.status(), STATUS_TIMEOUT).await {
        Ok(exchange)
            if matches!(
                exchange.result.body,
                ResultBody::Success {
                    payload: ResultPayload::Status(_),
                    ..
                } | ResultBody::Failure(_)
            ) =>
        {
            emit(present_result(&exchange.result.body))
        }
        Ok(_) => unexpected_result("status"),
        Err(error) => report_exchange_error(&error),
    }
}

pub(crate) async fn brief(approval_id: Option<ApprovalId>) -> i32 {
    let Some(context) = discover_context(approval_id).await else {
        return EXIT_OPERATION_FAILED;
    };
    match exchange(&context.brief(), READ_TIMEOUT).await {
        Ok(exchange) if !exchange.events.is_empty() => unexpected_events("brief"),
        Ok(exchange)
            if matches!(
                exchange.result.body,
                ResultBody::Success {
                    payload: ResultPayload::Brief(_),
                    ..
                } | ResultBody::Failure(_)
            ) =>
        {
            emit(present_result(&exchange.result.body))
        }
        Ok(_) => unexpected_result("brief"),
        Err(error) => report_exchange_error(&error),
    }
}

pub(crate) async fn network_diagnostics(approval_id: Option<ApprovalId>) -> i32 {
    let Some(context) = discover_context(approval_id).await else {
        return EXIT_OPERATION_FAILED;
    };
    match exchange(&context.network_diagnostics(), READ_TIMEOUT).await {
        Ok(exchange) if !exchange.events.is_empty() => unexpected_events("network diagnostics"),
        Ok(exchange)
            if matches!(
                exchange.result.body,
                ResultBody::Success {
                    payload: ResultPayload::NetworkDiagnostics(_),
                    ..
                } | ResultBody::Failure(_)
            ) =>
        {
            emit(present_result(&exchange.result.body))
        }
        Ok(_) => unexpected_result("network diagnostics"),
        Err(error) => report_exchange_error(&error),
    }
}

pub(crate) async fn wait(
    request_id: RequestId,
    after: u64,
    timeout: Duration,
    approval_id: Option<ApprovalId>,
) -> i32 {
    let Some(context) = discover_context(approval_id).await else {
        return EXIT_OPERATION_FAILED;
    };
    let request = context.wait(request_id, after);
    match exchange(&request, timeout).await {
        Ok(exchange) => {
            print!("{}", render_events(&exchange.events));
            emit(present_result(&exchange.result.body))
        }
        Err(error) => report_exchange_error(&error),
    }
}

pub(crate) async fn result(request_id: RequestId, approval_id: Option<ApprovalId>) -> i32 {
    let Some(context) = discover_context(approval_id).await else {
        return EXIT_OPERATION_FAILED;
    };
    match exchange(&context.result(request_id), READ_TIMEOUT).await {
        Ok(exchange) if !exchange.events.is_empty() => unexpected_events("result"),
        Ok(exchange) => emit(present_result(&exchange.result.body)),
        Err(error) => report_exchange_error(&error),
    }
}

pub(crate) async fn flow_run(
    selector: &str,
    run_id: Option<RequestId>,
    idempotency_key: Option<IdempotencyKey>,
    timeout: Duration,
    approval_id: Option<ApprovalId>,
) -> i32 {
    let Some((project, catalog)) = discover_flow_catalog(Path::new(".")) else {
        return EXIT_OPERATION_FAILED;
    };
    let Some(entry) = select_flow(&catalog, selector) else {
        return EXIT_OPERATION_FAILED;
    };
    let Some(context) = discover_context_for_project(&project, approval_id).await else {
        return EXIT_OPERATION_FAILED;
    };
    let request = match context.flow_run(entry.source, run_id, idempotency_key, project.root()) {
        Ok(request) => request,
        Err(error) => {
            eprintln!("PAM could not construct the bounded flow request.");
            eprintln!("Details: {}", escape_text(&error.to_string()));
            return EXIT_OPERATION_FAILED;
        }
    };
    let durable_run_id = request.request_id.clone();
    let retry = flow_run_retry(
        entry.definition.id(),
        &durable_run_id,
        &request.idempotency_key,
    );
    println!("run_id={durable_run_id}");
    let _ = io::stdout().flush();
    stream_flow_exchange(
        &request,
        timeout,
        &durable_run_id,
        FlowResponseKind::Run,
        Some(&retry),
        Some(&retry),
    )
    .await
}

pub(crate) fn flow_run_retry(
    definition_id: &str,
    run_id: &RequestId,
    idempotency_key: &IdempotencyKey,
) -> String {
    format!("pam flow run {definition_id} --run-id {run_id} --idempotency-key {idempotency_key}")
}

pub(crate) fn flow_list() -> i32 {
    let Some((_, catalog)) = discover_flow_catalog(Path::new(".")) else {
        return EXIT_OPERATION_FAILED;
    };
    for entry in catalog.entries() {
        println!(
            "id={} revision={} name={} file={}",
            escape_text(entry.definition.id()),
            entry.definition.revision(),
            escape_text(entry.definition.name()),
            escape_text(&entry.file_name)
        );
    }
    0
}

pub(crate) fn flow_show(selector: &str) -> i32 {
    let Some((_, catalog)) = discover_flow_catalog(Path::new(".")) else {
        return EXIT_OPERATION_FAILED;
    };
    let Some(entry) = select_flow(&catalog, selector) else {
        return EXIT_OPERATION_FAILED;
    };
    print!("{}", entry.normalized);
    0
}

pub(crate) fn flow_validate(selector: Option<&str>) -> i32 {
    let Some((_, catalog)) = discover_flow_catalog(Path::new(".")) else {
        return EXIT_OPERATION_FAILED;
    };
    let entries = if let Some(selector) = selector {
        match catalog.select(selector) {
            Ok(entry) => std::slice::from_ref(entry),
            Err(error) => return report_flow_catalog_error(&error),
        }
    } else {
        catalog.entries()
    };
    for entry in entries {
        println!(
            "Validated {} (id={}, revision={}).",
            escape_text(&entry.file_name),
            escape_text(entry.definition.id()),
            entry.definition.revision()
        );
    }
    0
}

pub(crate) async fn flow_cancel(run_id: RequestId, approval_id: Option<ApprovalId>) -> i32 {
    let Some(context) = discover_context(approval_id).await else {
        return EXIT_OPERATION_FAILED;
    };
    let request = context.flow_cancel(run_id.clone());
    let retry = format!("pam flow cancel {run_id}");
    stream_flow_exchange(
        &request,
        READ_TIMEOUT,
        &run_id,
        FlowResponseKind::Cancellation,
        Some(&retry),
        Some(&retry),
    )
    .await
}

pub(crate) async fn flow_logs(
    run_id: RequestId,
    after: u64,
    approval_id: Option<ApprovalId>,
) -> i32 {
    let Some(context) = discover_context(approval_id).await else {
        return EXIT_OPERATION_FAILED;
    };
    let request = context.flow_logs(run_id.clone(), after);
    let retry = format!("pam flow logs {run_id} --after {after}");
    stream_flow_exchange(
        &request,
        READ_TIMEOUT,
        &run_id,
        FlowResponseKind::Replay,
        Some(&retry),
        None,
    )
    .await
}

pub(crate) async fn flow_wait(
    run_id: RequestId,
    after: u64,
    timeout: Duration,
    approval_id: Option<ApprovalId>,
) -> i32 {
    let Some(context) = discover_context(approval_id).await else {
        return EXIT_OPERATION_FAILED;
    };
    let request = context.flow_wait(run_id.clone(), after);
    let retry = format!("pam flow wait {run_id} --after {after}");
    stream_flow_exchange(
        &request,
        timeout,
        &run_id,
        FlowResponseKind::Wait,
        Some(&retry),
        None,
    )
    .await
}

pub(crate) async fn flow_result(run_id: RequestId, approval_id: Option<ApprovalId>) -> i32 {
    let Some(context) = discover_context(approval_id).await else {
        return EXIT_OPERATION_FAILED;
    };
    let request = context.flow_result(run_id.clone());
    let retry = format!("pam flow result {run_id}");
    stream_flow_exchange(
        &request,
        READ_TIMEOUT,
        &run_id,
        FlowResponseKind::Result,
        Some(&retry),
        None,
    )
    .await
}

pub(crate) fn discover_flow_catalog(start: &Path) -> Option<(ProjectIdentity, FlowCatalog)> {
    let project = match discover_project(start) {
        Ok(project) => project,
        Err(error) => {
            report_identity_error(&error);
            return None;
        }
    };
    let catalog = match FlowCatalog::load(project.root()) {
        Ok(catalog) => catalog,
        Err(error) => {
            report_flow_catalog_error(&error);
            return None;
        }
    };
    Some((project, catalog))
}

pub(crate) fn select_flow(
    catalog: &FlowCatalog,
    selector: &str,
) -> Option<crate::flow::CatalogFlow> {
    match catalog.select(selector) {
        Ok(entry) => Some(entry.clone()),
        Err(error) => {
            report_flow_catalog_error(&error);
            None
        }
    }
}

async fn stream_flow_exchange(
    request: &pam_protocol::RequestEnvelope,
    timeout: Duration,
    run_id: &RequestId,
    response_kind: FlowResponseKind,
    approval_retry: Option<&str>,
    ambiguous_retry: Option<&str>,
) -> i32 {
    let mut unexpected_event = false;
    let result = pam_daemon::request_exchange_streaming(
        &LocalEndpoint::default_for_user(),
        request,
        timeout,
        |event| {
            if response_kind.allows_events() {
                print!("{}", render_events(std::slice::from_ref(event)));
                let _ = io::stdout().flush();
            } else {
                unexpected_event = true;
            }
        },
    )
    .await;
    match result {
        Ok(exchange) if unexpected_event => report_flow_observation_unknown(
            run_id,
            exchange.last_sequence,
            "daemon returned unexpected events for this flow command",
            response_kind,
            ambiguous_retry,
        ),
        Ok(exchange) if !flow_response_matches(&exchange.result.body, response_kind) => {
            report_flow_observation_unknown(
                run_id,
                exchange.last_sequence,
                "daemon returned a correlated but unexpected result payload",
                response_kind,
                ambiguous_retry,
            )
        }
        Ok(exchange) => present_expected_flow_result(
            &exchange.result.body,
            response_kind,
            response_kind.operation_name(),
            approval_retry,
        ),
        Err(error) if error.request_may_have_been_sent() => report_flow_observation_unknown(
            run_id,
            error.last_sequence(),
            &error.error().to_string(),
            response_kind,
            ambiguous_retry,
        ),
        Err(error) => report_exchange_error(error.error()),
    }
}

fn report_flow_observation_unknown(
    run_id: &RequestId,
    last_sequence: u64,
    detail: &str,
    response_kind: FlowResponseKind,
    ambiguous_retry: Option<&str>,
) -> i32 {
    let last_sequence = flow_recovery_cursor(response_kind, last_sequence);
    let run_id = escape_text(run_id.as_str());
    eprintln!(
        "Flow observation is pending or unknown after local submission; run_id={run_id}; last_sequence={last_sequence}."
    );
    eprintln!("Details: {}", escape_text(detail));
    if let Some(retry) = ambiguous_retry {
        let label = if matches!(response_kind, FlowResponseKind::Cancellation) {
            "Idempotent cancel retry"
        } else {
            "Exact submission retry"
        };
        eprintln!("{label}: {retry}");
    }
    eprintln!("Result: pam flow result {run_id}");
    eprintln!("Recovery: pam flow wait {run_id} --after {last_sequence}");
    eprintln!("Logs: pam flow logs {run_id} --after {last_sequence}");
    EXIT_PENDING
}

pub(crate) const fn flow_recovery_cursor(
    response_kind: FlowResponseKind,
    received_sequence: u64,
) -> u64 {
    if response_kind.allows_events() {
        received_sequence
    } else {
        0
    }
}

#[derive(Clone, Copy)]
pub(crate) enum FlowResponseKind {
    Run,
    Wait,
    Result,
    Replay,
    Cancellation,
}

impl FlowResponseKind {
    const fn allows_events(self) -> bool {
        matches!(self, Self::Run | Self::Wait | Self::Replay)
    }

    const fn operation_name(self) -> &'static str {
        match self {
            Self::Run => "flow run",
            Self::Wait => "flow wait",
            Self::Result => "flow result",
            Self::Replay => "flow logs",
            Self::Cancellation => "flow cancel",
        }
    }
}

fn present_expected_flow_result(
    body: &ResultBody,
    expected: FlowResponseKind,
    operation: &str,
    approval_retry: Option<&str>,
) -> i32 {
    if !flow_response_matches(body, expected) {
        return unexpected_result(operation);
    }
    let retry_approval = match body {
        ResultBody::Failure(failure) => failure.approval.as_ref(),
        ResultBody::Success { .. } => None,
    };
    let exit_code = emit(present_result(body));
    if let (Some(retry), Some(approval)) = (approval_retry, retry_approval) {
        eprintln!(
            "Flow retry: {retry} --approval-id {}",
            escape_text(approval.approval_id.as_str())
        );
    }
    exit_code
}

pub(crate) fn flow_response_matches(body: &ResultBody, expected: FlowResponseKind) -> bool {
    matches!(body, ResultBody::Failure(_))
        || matches!(
            (expected, body),
            (
                FlowResponseKind::Run | FlowResponseKind::Wait | FlowResponseKind::Result,
                ResultBody::Success {
                    payload: ResultPayload::FlowRun(_),
                    ..
                }
            ) | (
                FlowResponseKind::Replay,
                ResultBody::Success {
                    payload: ResultPayload::Replay(_),
                    ..
                }
            ) | (
                FlowResponseKind::Cancellation,
                ResultBody::Success {
                    payload: ResultPayload::Cancellation(_),
                    ..
                }
            )
        )
}

fn report_flow_catalog_error(error: &FlowCatalogError) -> i32 {
    eprintln!("{}", escape_text(&error.to_string()));
    EXIT_OPERATION_FAILED
}

pub(crate) async fn evidence_show(handle: EvidenceHandle, raw: bool, output: Option<&Path>) -> i32 {
    let Some(context) = discover_context(None).await else {
        return EXIT_OPERATION_FAILED;
    };
    let download = match download_evidence(
        &LocalEndpoint::default_for_user(),
        &context,
        handle,
        READ_TIMEOUT,
    )
    .await
    {
        Ok(download) => download,
        Err(error) => return report_evidence_error(&error),
    };

    if raw {
        let mut stdout = io::stdout().lock();
        if let Err(error) = stdout
            .write_all(&download.bytes)
            .and_then(|()| stdout.flush())
        {
            eprintln!("PAM could not write verified evidence to standard output.");
            eprintln!("Details: {}", escape_text(&error.to_string()));
            return EXIT_OPERATION_FAILED;
        }
        return 0;
    }

    if let Some(path) = output {
        if let Err(error) = write_new_output(path, &download.bytes) {
            eprintln!("{}", escape_text(&error.to_string()));
            if let Some(source) = std::error::Error::source(&error) {
                eprintln!("Details: {}", escape_text(&source.to_string()));
            }
            return EXIT_OPERATION_FAILED;
        }
        println!(
            "Wrote {} verified bytes to {} (truth={})",
            download.bytes.len(),
            escape_text(&path.display().to_string()),
            crate::render::truth_label(&download.truth)
        );
        return 0;
    }

    print!(
        "{}",
        crate::render::render_evidence_preview(
            &download.metadata,
            &download.bytes,
            &download.truth,
        )
    );
    0
}

async fn exchange(
    request: &pam_protocol::RequestEnvelope,
    timeout: Duration,
) -> Result<ClientExchange, StatusError> {
    pam_daemon::request_exchange(&LocalEndpoint::default_for_user(), request, timeout).await
}

async fn discover_context(approval_id: Option<ApprovalId>) -> Option<RequestContext> {
    match RequestContext::discover(approval_id).await {
        Ok(context) => Some(context),
        Err(RequestContextError::Identity(error)) => {
            report_identity_error(&error);
            None
        }
        Err(RequestContextError::Credential(error)) => {
            report_native_credential_error(&error);
            None
        }
    }
}

async fn discover_context_for_project(
    project: &ProjectIdentity,
    approval_id: Option<ApprovalId>,
) -> Option<RequestContext> {
    match RequestContext::discover_for_project(project, approval_id).await {
        Ok(context) => Some(context),
        Err(RequestContextError::Identity(error)) => {
            report_identity_error(&error);
            None
        }
        Err(RequestContextError::Credential(error)) => {
            report_native_credential_error(&error);
            None
        }
    }
}

async fn restore_native_credential(caller_id: CallerId, previous: Option<CallerCredential>) {
    let result = match previous {
        Some(credential) => store_native_credential(caller_id, credential).await,
        None => delete_native_credential(caller_id).await,
    };
    if let Err(error) = result
        && !error.is_not_found()
    {
        eprintln!(
            "PAM could not restore the previous native credential after registration failed."
        );
        eprintln!("Details: {}", escape_text(&error.to_string()));
    }
}

async fn delete_revoked_native_credential(caller_id: CallerId) -> i32 {
    match delete_native_credential(caller_id).await {
        Ok(()) => 0,
        Err(error) if error.is_not_found() => 0,
        Err(error) => report_native_credential_error(&error),
    }
}

fn report_native_credential_error(error: &NativeCredentialError) -> i32 {
    eprintln!("{}", escape_text(&error.to_string()));
    EXIT_OPERATION_FAILED
}

fn report_identity_error(error: &IdentityError) {
    eprintln!("{}", escape_text(&error.to_string()));
    eprintln!("Details: {}", escape_text(error.diagnostic()));
}

fn report_store_error(error: &pam_store::StoreError) -> i32 {
    eprintln!("{}", escape_text(&error.to_string()));
    EXIT_OPERATION_FAILED
}

const fn caller_kind(kind: CallerKindArg) -> CallerKind {
    match kind {
        CallerKindArg::Cli => CallerKind::Cli,
        CallerKindArg::Gui => CallerKind::Gui,
        CallerKindArg::CodingAgent => CallerKind::CodingAgent,
        CallerKindArg::LocalApplication => CallerKind::LocalApplication,
    }
}

const fn retention_label(retention: EvidenceRetention) -> &'static str {
    match retention {
        EvidenceRetention::Session => "session",
        EvidenceRetention::Project => "project",
        EvidenceRetention::Persistent => "persistent",
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn audit_event(
    project_id: ProjectId,
    caller_id: CallerId,
    action: &str,
    decision: &str,
    outcome: &str,
    detail: &str,
    occurred_at_ms: u64,
) -> AppendAuditEvent {
    AppendAuditEvent {
        event_id: Uuid::new_v4().to_string(),
        project_id,
        caller_id,
        action: action.to_owned(),
        decision: decision.to_owned(),
        outcome: outcome.to_owned(),
        redacted_detail: redact_audit_detail(detail.as_bytes()),
        occurred_at_ms,
        retain_until_ms: occurred_at_ms
            .saturating_add(AUDIT_RETENTION_MS)
            .min(i64::MAX as u64),
    }
}

fn report_exchange_error(error: &StatusError) -> i32 {
    eprintln!("{}", escape_text(&error.to_string()));
    if let Some(recovery) = error.recovery_action() {
        eprintln!("Recovery: {}", escape_text(recovery));
    }
    EXIT_OPERATION_FAILED
}

fn report_evidence_error(error: &EvidenceError) -> i32 {
    eprintln!("{}", escape_text(&error.to_string()));
    if let Some(recovery) = error.recovery_action() {
        eprintln!("Recovery: {}", escape_text(recovery));
    }
    EXIT_OPERATION_FAILED
}

fn emit(presentation: Presentation) -> i32 {
    let Presentation {
        stdout,
        stderr,
        exit_code,
    } = presentation;
    if !stdout.is_empty() {
        print!("{stdout}");
    }
    if !stderr.is_empty() {
        eprint!("{stderr}");
    }
    exit_code
}

fn unexpected_events(operation: &str) -> i32 {
    eprintln!(
        "PAM daemon returned unexpected events for the {} request.",
        escape_text(operation)
    );
    EXIT_OPERATION_FAILED
}

fn unexpected_result(operation: &str) -> i32 {
    eprintln!(
        "PAM daemon returned an unexpected result for the {} request.",
        escape_text(operation)
    );
    EXIT_OPERATION_FAILED
}
