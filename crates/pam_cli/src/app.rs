use std::{
    io::{self, Write},
    path::Path,
    time::Duration,
};

use pam_core::{EvidenceHandle, RequestId};
use pam_daemon::{ClientExchange, StatusError};
use pam_platform::{IdentityError, LocalEndpoint};
use pam_protocol::{ResultBody, ResultPayload};

use crate::{
    evidence::{EvidenceError, download_evidence, write_new_output},
    render::{EXIT_OPERATION_FAILED, Presentation, escape_text, present_result, render_events},
    request::RequestContext,
};

const STATUS_TIMEOUT: Duration = Duration::from_secs(2);
const READ_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) async fn status() -> i32 {
    let Some(context) = discover_context() else {
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
    let Some(context) = discover_context() else {
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

pub(crate) async fn wait(request_id: RequestId, after: u64, timeout: Duration) -> i32 {
    let Some(context) = discover_context() else {
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
    let Some(context) = discover_context() else {
        return EXIT_OPERATION_FAILED;
    };
    match exchange(&context.result(request_id), READ_TIMEOUT).await {
        Ok(exchange) if !exchange.events.is_empty() => unexpected_events("result"),
        Ok(exchange) => emit(present_result(&exchange.result.body)),
        Err(error) => report_exchange_error(&error),
    }
}

pub(crate) async fn evidence_show(handle: EvidenceHandle, raw: bool, output: Option<&Path>) -> i32 {
    let Some(context) = discover_context() else {
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

fn discover_context() -> Option<RequestContext> {
    match RequestContext::discover() {
        Ok(context) => Some(context),
        Err(error) => {
            report_identity_error(&error);
            None
        }
    }
}

fn report_identity_error(error: &IdentityError) {
    eprintln!("{}", escape_text(&error.to_string()));
    eprintln!("Details: {}", escape_text(error.diagnostic()));
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
