/// GUI mode is dispatched by the single `pam` binary before the CLI parser
/// runs (see `src-tauri/src/main.rs`). Reaching this handler means the host
/// binary was built without the desktop shell.
pub(crate) fn run() -> i32 {
    eprintln!("This build of PAM does not embed the desktop shell.");
    eprintln!("Run the packaged `pam` binary: pam gui");
    1
}
