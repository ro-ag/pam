//! One binary, mode by subcommand: client by default, `pam daemon` for the
//! background service, `pam gui` for the desktop control center.

fn main() {
    println!(
        "pam {} (protocol v{})",
        env!("CARGO_PKG_VERSION"),
        pam_proto::PROTOCOL_VERSION
    );
}
