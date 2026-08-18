use std::{path::PathBuf, time::Duration};

use clap::{Parser, Subcommand};
use pam_core::{EvidenceHandle, RequestId};

const DEFAULT_WAIT_TIMEOUT: &str = "30s";
const MAX_WAIT_TIMEOUT: Duration = Duration::from_hours(24);

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
    /// Print a compact, provenance-backed project handoff.
    Brief,
    /// Replay a request and wait for its durable result.
    Wait {
        /// Durable request to observe.
        #[arg(value_parser = parse_request_id)]
        request_id: RequestId,
        /// Replay events strictly after this sequence number.
        #[arg(long, default_value_t = 0)]
        after: u64,
        /// Stop observing after this bounded duration (for example, 500ms, 30s, 5m, or 1h).
        #[arg(long, default_value = DEFAULT_WAIT_TIMEOUT, value_parser = parse_wait_timeout)]
        timeout: Duration,
    },
    /// Print a request's durable result without waiting.
    Result {
        /// Durable request to inspect.
        #[arg(value_parser = parse_request_id)]
        request_id: RequestId,
    },
    /// Inspect retained project evidence.
    Evidence {
        #[command(subcommand)]
        command: EvidenceCommand,
    },
    /// Run the foreground daemon.
    Daemon {
        /// Recover an endpoint left behind by an interrupted daemon.
        #[arg(long)]
        recover: bool,
    },
    /// Open the native control-center shell.
    Gui,
}

#[derive(Debug, Subcommand)]
enum EvidenceCommand {
    /// Show evidence metadata and content.
    Show {
        /// Canonical evidence handle to inspect.
        #[arg(value_parser = parse_evidence_handle)]
        handle: EvidenceHandle,
        /// Write only exact evidence bytes to standard output.
        #[arg(long, conflicts_with = "output")]
        raw: bool,
        /// Write exact evidence bytes to this platform-native path.
        #[arg(long, value_name = "PATH")]
        output: Option<PathBuf>,
    },
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum Mode {
    Client,
    Status,
    Brief,
    Wait {
        request_id: RequestId,
        after: u64,
        timeout: Duration,
    },
    Result {
        request_id: RequestId,
    },
    EvidenceShow {
        handle: EvidenceHandle,
        raw: bool,
        output: Option<PathBuf>,
    },
    Daemon {
        recover: bool,
    },
    Gui,
}

impl Cli {
    pub(crate) fn mode(self) -> Mode {
        match self.command {
            None => Mode::Client,
            Some(Command::Status) => Mode::Status,
            Some(Command::Brief) => Mode::Brief,
            Some(Command::Wait {
                request_id,
                after,
                timeout,
            }) => Mode::Wait {
                request_id,
                after,
                timeout,
            },
            Some(Command::Result { request_id }) => Mode::Result { request_id },
            Some(Command::Evidence {
                command:
                    EvidenceCommand::Show {
                        handle,
                        raw,
                        output,
                    },
            }) => Mode::EvidenceShow {
                handle,
                raw,
                output,
            },
            Some(Command::Daemon { recover }) => Mode::Daemon { recover },
            Some(Command::Gui) => Mode::Gui,
        }
    }
}

fn parse_request_id(value: &str) -> Result<RequestId, String> {
    if value.is_empty()
        || value
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(
            "request ID must be non-empty and contain no whitespace or controls".to_owned(),
        );
    }
    Ok(RequestId::from(value.to_owned()))
}

fn parse_evidence_handle(value: &str) -> Result<EvidenceHandle, String> {
    EvidenceHandle::parse(value.to_owned()).map_err(|error| error.to_string())
}

fn parse_wait_timeout(value: &str) -> Result<Duration, String> {
    let (number, unit) = if let Some(number) = value.strip_suffix("ms") {
        (number, TimeoutUnit::Milliseconds)
    } else if let Some(number) = value.strip_suffix('s') {
        (number, TimeoutUnit::Seconds)
    } else if let Some(number) = value.strip_suffix('m') {
        (number, TimeoutUnit::Minutes)
    } else if let Some(number) = value.strip_suffix('h') {
        (number, TimeoutUnit::Hours)
    } else {
        return Err("duration must use one of: ms, s, m, or h".to_owned());
    };
    let amount = number.parse::<u64>().map_err(|_| {
        "duration must be a whole non-negative number followed by a unit".to_owned()
    })?;
    let duration = match unit {
        TimeoutUnit::Milliseconds => Duration::from_millis(amount),
        TimeoutUnit::Seconds => Duration::from_secs(amount),
        TimeoutUnit::Minutes => {
            if amount > u64::MAX / 60 {
                return Err("duration is too large".to_owned());
            }
            Duration::from_mins(amount)
        }
        TimeoutUnit::Hours => {
            if amount > u64::MAX / (60 * 60) {
                return Err("duration is too large".to_owned());
            }
            Duration::from_hours(amount)
        }
    };
    if duration.is_zero() {
        return Err("duration must be greater than zero".to_owned());
    }
    if duration > MAX_WAIT_TIMEOUT {
        return Err("duration must not exceed 24h".to_owned());
    }
    Ok(duration)
}

#[derive(Clone, Copy)]
enum TimeoutUnit {
    Milliseconds,
    Seconds,
    Minutes,
    Hours,
}
