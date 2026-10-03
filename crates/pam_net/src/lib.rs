//! The one hardened curl launcher, and the network settings it runs under.
//!
//! pam links no TLS stack: every HTTPS request it makes — a connector call, a
//! model or engine download, a network test — is the operating system's own
//! `curl`, started as a child process. This crate is the only place that
//! starts it. A caller gets the verified executable ([`TrustedCurl`]),
//! describes one request ([`CurlRequest`]) under the profile the human set
//! ([`NetSettings`]), and receives either the output ([`CurlOutput`]) or a
//! named failure ([`NetFailure`]).
//!
//! What the launcher guarantees is listed in [`launch`]; the short form is
//! that the argument vector is a constant, everything else travels on
//! standard input through one escaping function, the environment is empty,
//! and the proxy and certificate trust come from [`NetSettings`] and from
//! nowhere else.
//!
//! A connector call:
//!
//! ```no_run
//! # async fn example() -> Result<(), pam_net::NetFailure> {
//! use std::time::Duration;
//! use pam_net::{Method, NetSettings, TrustedCurl};
//!
//! let settings = NetSettings::direct(); // in the daemon: `source.settings().await?`
//! let url = pam_net::Url::parse("https://api.github.com/user").expect("a URL");
//! let output = TrustedCurl::resolve()?
//!     .request(&settings, &url)
//!     .method(Method::Get)
//!     .header("Authorization", "Bearer …")
//!     .include_headers()
//!     .max_time(30)
//!     .capture_limit(1024 * 1024)
//!     .run(Duration::from_secs(35))
//!     .await?;
//! assert!(output.stdout.starts_with(b"HTTP/"));
//! # Ok(())
//! # }
//! ```
//!
//! A resumable download, driven by the caller so it can watch for a cancel:
//!
//! ```no_run
//! # async fn example(part: &std::path::Path, etag: &std::path::Path) -> Result<(), pam_net::NetFailure> {
//! use pam_net::{NetSettings, TrustedCurl};
//!
//! let settings = NetSettings::direct();
//! let url = pam_net::Url::parse("https://huggingface.co/org/model/resolve/main/model.gguf")
//!     .expect("a URL");
//! let mut child = TrustedCurl::resolve()?
//!     .request(&settings, &url)
//!     .fail_on_http_error()
//!     .follow_https_redirects(10)
//!     .connect_timeout(30)
//!     .stall_limit(1024, 60)
//!     .output(part)
//!     .etag_save(etag)
//!     .resume()
//!     .spawn()
//!     .await?;
//! // `child.wait()` is cancel-safe: select it against a cancel signal and
//! // call `child.kill()` when the human cancels.
//! child.wait().await?;
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]

pub mod ca;
pub mod config;
pub mod failure;
pub mod launch;
pub mod mirror;
pub mod settings;
pub mod trusted;

/// Loopback fixtures real curl is driven against: an HTTP origin, a fake
/// forward proxy, and an `openssl s_server` TLS origin with a private test
/// CA. Compiled for this crate's tests and for anyone who turns on the
/// `testing` feature.
#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use ca::{CaError, NormalizedBundle, normalize_pem};
pub use config::{EscapeError, escape};
pub use failure::{Diagnostics, NetFailure, curl_install_line};
pub use launch::{CURL_ARGV, CurlChild, CurlOutput, CurlRequest, DEFAULT_CAPTURE_BYTES, Method};
pub use mirror::MirrorBase;
pub use settings::{
    NetSettings, NetworkSource, NoProxyRule, Proxy, ProxyAuth, ProxyPassword, ProxyScheme, Route,
    SettingsError, is_loopback, parse_no_proxy,
};
pub use trusted::{CurlInfo, TlsBackend, TrustedCurl, WINDOWS_KEPT_ENV};
pub use url::Url;

#[cfg(test)]
mod ca_test;
#[cfg(test)]
mod config_test;
#[cfg(test)]
mod failure_test;
#[cfg(test)]
mod launch_test;
#[cfg(test)]
mod mirror_test;
#[cfg(test)]
mod settings_test;
#[cfg(test)]
mod source_scan_test;
#[cfg(test)]
mod trusted_test;
