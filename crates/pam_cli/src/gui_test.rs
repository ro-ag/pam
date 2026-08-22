use super::gui;

#[test]
fn gui_mode_reports_missing_desktop_shell_without_launching() {
    // The single `pam` binary intercepts `pam gui` before clap; this fallback
    // must fail fast instead of spawning anything.
    assert_eq!(gui::run(), 1);
}
