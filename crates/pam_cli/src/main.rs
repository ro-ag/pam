mod app;
mod audit;
mod command;
mod evidence;
mod render;
mod request;

#[cfg(test)]
mod app_test;
#[cfg(test)]
mod audit_test;
#[cfg(test)]
mod command_test;
#[cfg(test)]
mod evidence_test;
#[cfg(test)]
mod render_test;
#[cfg(test)]
mod request_test;

use clap::Parser;
use command::{Cli, Mode};

#[tokio::main]
#[allow(clippy::too_many_lines)]
async fn main() {
    let exit_code = match Cli::parse().mode() {
        Mode::Client => {
            println!("PAM client ready. Run `pam status` to inspect the daemon.");
            0
        }
        Mode::Status { approval_id } => app::status(approval_id).await,
        Mode::Brief { approval_id } => app::brief(approval_id).await,
        Mode::Wait {
            request_id,
            after,
            timeout,
            approval_id,
        } => app::wait(request_id, after, timeout, approval_id).await,
        Mode::Result {
            request_id,
            approval_id,
        } => app::result(request_id, approval_id).await,
        Mode::EvidenceShow {
            handle,
            raw,
            output,
        } => app::evidence_show(handle, raw, output.as_deref()).await,
        Mode::CallerRegister { kind } => app::caller_register(kind).await,
        Mode::CallerRevoke { kind } => app::caller_revoke(kind).await,
        Mode::ModelImport {
            model,
            path,
            digest,
            size_bytes,
            license_id,
            license_url,
            license_notice_digest,
            accept_license,
            approval_id,
        } => {
            app::model_import(
                model,
                &path,
                digest,
                size_bytes,
                license_id,
                license_url,
                license_notice_digest,
                accept_license,
                approval_id,
            )
            .await
        }
        Mode::ModelGenerate {
            model,
            prompt,
            system,
            tokens,
            timeout,
            approval_id,
        } => app::model_generate(model, prompt, system, tokens, timeout, approval_id).await,
        Mode::AccessGrant {
            capability,
            resource,
            deny,
            require_approval,
            expires_at_unix_ms,
            kind,
        } => {
            app::access_grant(
                kind,
                capability,
                resource,
                deny,
                require_approval,
                expires_at_unix_ms,
            )
            .await
        }
        Mode::AccessRevoke { grant_id } => app::access_revoke(grant_id).await,
        Mode::ApprovalApprove { approval_id } => {
            app::approval_decide(approval_id, pam_store::ApprovalDecision::Approve).await
        }
        Mode::ApprovalDeny { approval_id } => {
            app::approval_decide(approval_id, pam_store::ApprovalDecision::Deny).await
        }
        Mode::NetworkDiagnostics { approval_id } => app::network_diagnostics(approval_id).await,
        Mode::AuditExport {
            output,
            after,
            through,
            approval_id,
            limit,
        } => app::audit_export(&output, after, through, approval_id, limit).await,
        Mode::RetentionPrune {
            scope,
            before_unix_ms,
            approval_id,
            limit,
        } => app::retention_prune(scope, before_unix_ms, approval_id, limit).await,
        Mode::Daemon { recover, model } => match pam_daemon::run(recover, model).await {
            Ok(()) => 0,
            Err(error) => {
                eprintln!("{error}");
                1
            }
        },
        Mode::Gui => {
            pam_gui::run();
            0
        }
    };

    std::process::exit(exit_code);
}
