//! Which frontend the window loads, and the opt-in for the development one.
//!
//! A `pam gui` built without the embedded frontend loads the Vite development server,
//! `http://127.0.0.1:1420`, and the window it opens holds the full admin bridge. Anything that
//! binds that port first would be served to a window that can administer the daemon, so the
//! development frontend is never a default: without the embedded frontend the GUI refuses to
//! start unless [`DEV_SWITCH`] is set to `1`. The check runs in Rust before the window exists
//! ([`crate::run`]). Release builds (`gui-embed`, or `tauri build`) are unaffected: they carry
//! their own assets and never read the switch.

use std::ffi::OsStr;

/// The environment variable that turns the development frontend on.
pub const DEV_SWITCH: &str = "PAM_GUI_DEV";

/// Where the development frontend is served (`devUrl` in `tauri.conf.json`).
pub const DEV_URL: &str = "http://127.0.0.1:1420";

/// What the window will load.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Frontend {
    /// The frontend compiled into this binary.
    Embedded,
    /// The Vite dev server, by explicit request.
    Development,
}

/// Why the GUI refused to start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevFrontendRefused;

impl std::fmt::Display for DevFrontendRefused {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "this pam binary was built without its embedded frontend, so its window would load \
             {DEV_URL} with full control of the daemon, and whatever is listening on that port \
             would get it. To load the development server on purpose, set {DEV_SWITCH}=1 and start \
             `pam gui` again; otherwise use a release build (`npm --prefix frontend run gui:build`)"
        )
    }
}

impl std::error::Error for DevFrontendRefused {}

/// Decides what the window may load: `dev_build` is whether this binary lacks the embedded
/// frontend, `switch` the value of [`DEV_SWITCH`]. Only the exact value `1` opts in.
///
/// # Errors
///
/// [`DevFrontendRefused`] for a development build without the switch.
pub fn choose(dev_build: bool, switch: Option<&OsStr>) -> Result<Frontend, DevFrontendRefused> {
    if !dev_build {
        return Ok(Frontend::Embedded);
    }
    if switch == Some(OsStr::new("1")) {
        return Ok(Frontend::Development);
    }
    Err(DevFrontendRefused)
}
