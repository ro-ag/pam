mod command;

#[cfg(test)]
mod command_test;

use clap::Parser;
use command::{Cli, Mode};
use pam_core::{CallerId, IdempotencyKey, ProjectId, RequestId};
use pam_platform::LocalEndpoint;
use pam_protocol::{RequestEnvelope, ResultBody, ResultPayload};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[tokio::main]
async fn main() {
    let exit_code = match Cli::parse().mode() {
        Mode::Client => {
            println!("PAM client ready. Run `pam status` to inspect the daemon.");
            0
        }
        Mode::Status => report_status().await,
        Mode::Daemon { recover } => match pam_daemon::run(recover).await {
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

async fn report_status() -> i32 {
    let request = status_request();
    match pam_daemon::request_status(
        &LocalEndpoint::default_for_user(),
        &request,
        Duration::from_secs(2),
    )
    .await
    {
        Ok(exchange) => match exchange.result.body {
            ResultBody::Success {
                truth,
                payload: ResultPayload::Status(status),
            } => {
                println!(
                    "ready={} healthy={} daemon_version={} protocol_version={} queue_depth={} truth={truth:?}",
                    status.ready,
                    status.healthy,
                    status.daemon_version,
                    status.protocol_version,
                    status.queue_depth
                );
                0
            }
            ResultBody::Failure(failure) => {
                eprintln!("{}", failure.message);
                if let Some(recovery) = failure.recovery {
                    eprintln!("Recovery: {recovery}");
                }
                2
            }
        },
        Err(error) => {
            eprintln!("{error}");
            2
        }
    }
}

fn status_request() -> RequestEnvelope {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let token = format!("{}-{now}", std::process::id());
    let project = std::env::current_dir().map_or_else(
        |_| "current-project".to_owned(),
        |path| path.display().to_string(),
    );

    RequestEnvelope::status(
        RequestId::new(format!("status-{token}")),
        CallerId::from("pam-cli"),
        ProjectId::new(project),
        IdempotencyKey::new(format!("status-{token}")),
    )
}
