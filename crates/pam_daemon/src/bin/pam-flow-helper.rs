//! A deliberately boring child process the flow-engine tests drive.
//!
//! `pam_daemon::flow_exec::run_command` has four endings a real program
//! has to produce for the tests to mean anything —
//! a clean exit, a non-zero exit, a process that outlives its timeout, and
//! one that writes more than the output cap — and no portable system
//! command produces all four. This binary does, in four lines of logic:
//!
//! ```text
//! pam-flow-helper sleep <ms>        # runs for <ms> and exits 0
//! pam-flow-helper spew <bytes>      # writes <bytes> to stdout and exits 0
//! pam-flow-helper exit <code>       # exits with <code>
//! pam-flow-helper echo-env <NAME>   # prints the value of $NAME, or nothing
//! ```
//!
//! # Why it is always built
//!
//! The obvious shape is a `[[bin]]` gated behind `required-features =
//! ["testing"]`, but Cargo only sets `CARGO_BIN_EXE_pam-flow-helper` for an
//! integration test when the binary is actually built, and a plain
//! `cargo test --workspace` does not turn that feature on — the tests would
//! not compile. Being always built costs the shipped product nothing:
//! `pam_daemon` is a library dependency of `pam`, and Cargo never builds a
//! dependency's binary targets, so `pam-flow-helper` exists only in a
//! workspace build of this crate.

use std::io::Write;
use std::process::ExitCode;

/// Bytes written per `spew` iteration.
const CHUNK: usize = 64 * 1024;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = args.first().map_or("", String::as_str);
    let argument = args.get(1).map_or("", String::as_str);
    match command {
        "sleep" => {
            std::thread::sleep(std::time::Duration::from_millis(number(argument)));
            ExitCode::SUCCESS
        }
        "spew" => {
            spew(usize::try_from(number(argument)).unwrap_or(usize::MAX));
            ExitCode::SUCCESS
        }
        "exit" => ExitCode::from(u8::try_from(number(argument)).unwrap_or(u8::MAX)),
        "echo-env" => {
            println!("{}", std::env::var(argument).unwrap_or_default());
            ExitCode::SUCCESS
        }
        other => {
            eprintln!(
                "pam-flow-helper: unknown command {other:?}; \
                 expected sleep, spew, exit or echo-env"
            );
            ExitCode::from(2)
        }
    }
}

/// Parses a numeric argument, defaulting to zero so the helper never
/// panics in a test that mistyped one.
fn number(raw: &str) -> u64 {
    raw.parse().unwrap_or(0)
}

/// Writes `bytes` bytes of printable filler to stdout.
fn spew(bytes: usize) {
    let chunk = vec![b'x'; CHUNK];
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let mut written = 0;
    while written < bytes {
        let take = CHUNK.min(bytes - written);
        if out.write_all(&chunk[..take]).is_err() {
            return;
        }
        written += take;
    }
    let _ = out.flush();
}
