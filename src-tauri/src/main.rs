#![forbid(unsafe_code)]
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    if let Err(error) = pam_desktop::run() {
        eprintln!("PAM could not start: {error}");
        std::process::exit(1);
    }
}
