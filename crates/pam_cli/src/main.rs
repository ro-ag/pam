mod app;
mod command;
mod evidence;
mod render;
mod request;

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
async fn main() {
    let exit_code = match Cli::parse().mode() {
        Mode::Client => {
            println!("PAM client ready. Run `pam status` to inspect the daemon.");
            0
        }
        Mode::Status => app::status().await,
        Mode::Brief => app::brief().await,
        Mode::Wait {
            request_id,
            after,
            timeout,
        } => app::wait(request_id, after, timeout).await,
        Mode::Result { request_id } => app::result(request_id).await,
        Mode::EvidenceShow {
            handle,
            raw,
            output,
        } => app::evidence_show(handle, raw, output.as_deref()).await,
        Mode::CallerRegister { kind } => app::caller_register(kind).await,
        Mode::CallerRevoke { kind } => app::caller_revoke(kind).await,
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
