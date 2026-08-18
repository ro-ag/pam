use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "pam", version, about = "Local project continuity companion")]
pub(crate) struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Report daemon health through the local protocol.
    Status,
    /// Run the foreground daemon.
    Daemon {
        /// Recover an endpoint left behind by an interrupted daemon.
        #[arg(long)]
        recover: bool,
    },
    /// Open the native control-center shell.
    Gui,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum Mode {
    Client,
    Status,
    Daemon { recover: bool },
    Gui,
}

impl Cli {
    pub(crate) fn mode(self) -> Mode {
        match self.command {
            None => Mode::Client,
            Some(Command::Status) => Mode::Status,
            Some(Command::Daemon { recover }) => Mode::Daemon { recover },
            Some(Command::Gui) => Mode::Gui,
        }
    }
}
