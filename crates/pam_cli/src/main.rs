mod app;
mod audit;
mod command;
mod evidence;
mod flow;
mod gui;
mod render;
mod request;
mod skills;

#[cfg(test)]
mod app_test;
#[cfg(test)]
mod audit_test;
#[cfg(test)]
mod command_test;
#[cfg(test)]
mod evidence_test;
#[cfg(test)]
mod flow_test;
#[cfg(test)]
mod gui_test;
#[cfg(test)]
mod render_test;
#[cfg(test)]
mod request_test;
#[cfg(test)]
mod skill_round_trip_test;
#[cfg(test)]
mod skills_test;

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
        Mode::FlowRun {
            selector,
            run_id,
            idempotency_key,
            timeout,
            approval_id,
        } => app::flow_run(&selector, run_id, idempotency_key, timeout, approval_id).await,
        Mode::FlowList => app::flow_list(),
        Mode::FlowShow { selector } => app::flow_show(&selector),
        Mode::FlowValidate { selector } => app::flow_validate(selector.as_deref()),
        Mode::FlowCancel {
            run_id,
            approval_id,
        } => app::flow_cancel(run_id, approval_id).await,
        Mode::FlowLogs {
            run_id,
            after,
            approval_id,
        } => app::flow_logs(run_id, after, approval_id).await,
        Mode::FlowWait {
            run_id,
            after,
            timeout,
            approval_id,
        } => app::flow_wait(run_id, after, timeout, approval_id).await,
        Mode::FlowResult {
            run_id,
            approval_id,
        } => app::flow_result(run_id, approval_id).await,
        Mode::EvidenceShow {
            handle,
            raw,
            output,
        } => app::evidence_show(handle, raw, output.as_deref()).await,
        Mode::SkillsList { json } => skills::list(json).await,
        Mode::SkillsShow { artifact_id, json } => skills::show(artifact_id, json).await,
        Mode::SkillsAudit { json } => skills::audit(json).await,
        Mode::SkillsLibraryList { json } => skills::library_list(json),
        Mode::SkillsAdopt {
            entry_id,
            artifact_id,
            json,
        } => skills::adopt(entry_id, artifact_id, json),
        Mode::SkillsInstall {
            entry_id,
            source,
            json,
        } => skills::install(entry_id, source, json),
        Mode::SkillsEnable {
            entry_id,
            version,
            agent,
            json,
        } => skills::enable(entry_id, version, agent, json),
        Mode::SkillsDisable {
            entry_id,
            version,
            agent,
            root,
            json,
        } => skills::disable(entry_id, version, agent, root, json),
        Mode::SkillsMaterialize {
            entry_id,
            version,
            agent,
            root,
            apply,
            json,
        } => skills::materialize(entry_id, version, agent, root, apply, json),
        Mode::SkillsDrift {
            entry_id,
            version,
            agent,
            root,
            json,
        } => skills::drift(entry_id, version, agent, root, json),
        Mode::SkillsResync {
            entry_id,
            version,
            agent,
            root,
            apply,
            json,
        } => skills::resync(entry_id, version, agent, root, apply, json),
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
        Mode::Gui => gui::run(),
    };

    std::process::exit(exit_code);
}
