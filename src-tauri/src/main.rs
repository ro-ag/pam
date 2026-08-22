#![forbid(unsafe_code)]
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! The single `pam` binary runs in three modes:
//! - client (default): every CLI subcommand, delegated to `pam_cli`
//! - gui control: `pam gui`, or a bare launch from inside an app bundle
//! - ipc daemon: `pam daemon`, also delegated through `pam_cli`

fn main() {
    let mut args = std::env::args().skip(1);
    let wants_gui = match args.next().as_deref() {
        Some("gui") => args.next().is_none(),
        None => launched_from_app_bundle(),
        Some(_) => false,
    };
    if wants_gui {
        if let Err(error) = pam_desktop::run() {
            eprintln!("PAM could not start: {error}");
            std::process::exit(1);
        }
        return;
    }
    std::process::exit(pam_cli::run());
}

/// A bare launch from inside a macOS app bundle opens the GUI; a bare
/// terminal launch stays in client mode.
fn launched_from_app_bundle() -> bool {
    #[cfg(target_os = "macos")]
    {
        std::env::current_exe().is_ok_and(|exe| {
            exe.components()
                .any(|part| part.as_os_str().to_string_lossy().ends_with(".app"))
        })
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}
