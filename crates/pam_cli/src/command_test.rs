use clap::Parser;

use super::command::{Cli, Mode};

#[test]
fn no_subcommand_selects_client_mode() {
    assert_eq!(Cli::try_parse_from(["pam"]).unwrap().mode(), Mode::Client);
}

#[test]
fn explicit_subcommands_select_runtime_modes() {
    assert_eq!(
        Cli::try_parse_from(["pam", "status"]).unwrap().mode(),
        Mode::Status
    );
    assert_eq!(
        Cli::try_parse_from(["pam", "daemon", "--recover"])
            .unwrap()
            .mode(),
        Mode::Daemon { recover: true }
    );
    assert_eq!(
        Cli::try_parse_from(["pam", "gui"]).unwrap().mode(),
        Mode::Gui
    );
}
