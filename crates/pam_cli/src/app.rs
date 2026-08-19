use std::{
    io::{self, Write},
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use pam_core::{ApprovalId, CallerCredential, EvidenceHandle, GrantId, RequestId};
use pam_daemon::{ClientExchange, StatusError};
use pam_platform::{
    CallerKind, IdentityError, LocalEndpoint, caller_id, discover_project_id, user_data_dir,
};
use pam_policy::{ApprovalRequirement, CapabilityName, Effect, Grant, ResourceName, ResourceScope};
use pam_protocol::{ResultBody, ResultPayload};
use pam_store::{
    ApprovalDecision, ApprovalDecisionOutcome, CallerRevocation, GrantRevocation, PutGrant, Store,
};
use uuid::Uuid;

use crate::{
    command::CallerKindArg,
    evidence::{EvidenceError, download_evidence, write_new_output},
    render::{EXIT_OPERATION_FAILED, Presentation, escape_text, present_result, render_events},
    request::{
        NativeCredentialError, RequestContext, RequestContextError, delete_native_credential,
        load_native_credential, store_native_credential,
    },
};

const STATUS_TIMEOUT: Duration = Duration::from_secs(2);
const READ_TIMEOUT: Duration = Duration::from_secs(5);

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

pub(crate) async fn status() -> i32 {
    let Some(context) = discover_context().await else {
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

pub(crate) async fn brief() -> i32 {
    let Some(context) = discover_context().await else {
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

pub(crate) async fn network_diagnostics() -> i32 {
    let Some(context) = discover_context().await else {
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

pub(crate) async fn wait(request_id: RequestId, after: u64, timeout: Duration) -> i32 {
    let Some(context) = discover_context().await else {
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

pub(crate) async fn result(request_id: RequestId) -> i32 {
    let Some(context) = discover_context().await else {
        return EXIT_OPERATION_FAILED;
    };
    match exchange(&context.result(request_id), READ_TIMEOUT).await {
        Ok(exchange) if !exchange.events.is_empty() => unexpected_events("result"),
        Ok(exchange) => emit(present_result(&exchange.result.body)),
        Err(error) => report_exchange_error(&error),
    }
}

pub(crate) async fn evidence_show(handle: EvidenceHandle, raw: bool, output: Option<&Path>) -> i32 {
    let Some(context) = discover_context().await else {
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

async fn discover_context() -> Option<RequestContext> {
    match RequestContext::discover().await {
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

async fn restore_native_credential(
    caller_id: pam_core::CallerId,
    previous: Option<CallerCredential>,
) {
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

async fn delete_revoked_native_credential(caller_id: pam_core::CallerId) -> i32 {
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

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
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
