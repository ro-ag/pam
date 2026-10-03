//! The one curl pam may run: the operating system's own, by absolute path.
//!
//! pam links no TLS stack; it starts the curl the platform ships and
//! services. Which file that is must not be something an agent can choose:
//! `PATH` is never searched, and the fixed path is checked on every
//! [`TrustedCurl::resolve`] so a binary replaced while the daemon runs is
//! caught at the next spawn.
//!
//! The environment policy lives here too, because the version probe and
//! every request spawn share it: the child's environment is empty, except on
//! Windows for the handful of system variables without which a process
//! cannot initialize networking.

use std::fmt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use crate::failure::NetFailure;

/// How long `curl --version` may take before it is killed.
const PROBE_LIMIT: Duration = Duration::from_secs(10);

/// The only variables a curl child keeps, and only on Windows: what the
/// process needs to load its network and crypto stack. No proxy variable, no
/// CA variable, no key-log file, no home directory, no `PATH`.
pub const WINDOWS_KEPT_ENV: [&str; 6] = [
    "SystemRoot",
    "SystemDrive",
    "windir",
    "COMSPEC",
    "TEMP",
    "TMP",
];

/// The TLS library the trusted curl verifies certificates with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsBackend {
    /// `LibreSSL`: Apple's curl on macOS.
    LibreSsl,
    /// OpenSSL or a fork that reports itself as such.
    OpenSsl,
    /// The Windows TLS stack: Microsoft's curl.
    Schannel,
    /// Apple's legacy TLS stack.
    SecureTransport,
    /// Anything else, by the name curl printed.
    Other(String),
}

impl fmt::Display for TlsBackend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::LibreSsl => "LibreSSL",
            Self::OpenSsl => "OpenSSL",
            Self::Schannel => "Schannel",
            Self::SecureTransport => "SecureTransport",
            Self::Other(name) => name,
        })
    }
}

/// What `curl --version` says about the trusted curl.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurlInfo {
    /// `(major, minor, patch)`.
    pub version: (u32, u32, u32),
    /// The active TLS backend.
    pub backend: TlsBackend,
    /// The first line of the version output, for display.
    pub banner: String,
    /// Whether this build can talk to an `https://` proxy.
    pub https_proxy: bool,
}

impl CurlInfo {
    /// Reads `curl --version` output. `None` when the first line is not a
    /// curl version banner.
    #[must_use]
    pub fn parse(output: &str) -> Option<Self> {
        let banner = output.lines().next()?.trim();
        let mut words = banner.split_whitespace();
        if words.next()? != "curl" {
            return None;
        }
        let version = parse_version(words.next()?)?;
        // After `libcurl/x.y.z` come the libraries; a TLS library in
        // parentheses is compiled in but not the one in use.
        let backend = words
            .skip_while(|word| !word.starts_with("libcurl/"))
            .skip(1)
            .filter(|word| !word.starts_with('('))
            .find_map(backend_named)
            .unwrap_or_else(|| TlsBackend::Other("unknown".to_owned()));
        let https_proxy = output
            .lines()
            .find_map(|line| line.strip_prefix("Features:"))
            .is_some_and(|features| features.split_whitespace().any(|f| f == "HTTPS-proxy"));
        Some(Self {
            version,
            backend,
            banner: banner.to_owned(),
            https_proxy,
        })
    }

    /// The version as `major.minor.patch`.
    #[must_use]
    pub fn version_text(&self) -> String {
        let (major, minor, patch) = self.version;
        format!("{major}.{minor}.{patch}")
    }

    /// Whether this curl can be given a proxy the way the launcher does it:
    /// 7.63 for the diagnostics line on standard error (7.54's suppressed
    /// `CONNECT` headers are implied).
    #[must_use]
    pub fn supports_proxy(&self) -> bool {
        self.version >= (7, 63, 0)
    }

    /// Whether this curl evaluates CIDR ranges in a no-proxy list (7.86).
    #[must_use]
    pub fn supports_cidr_no_proxy(&self) -> bool {
        self.version >= (7, 86, 0)
    }

    /// Whether the diagnostics `write-out` line can be sent to standard
    /// error (7.63). Older curls run without it and failures are classified
    /// from the exit code alone.
    pub(crate) fn supports_stderr_write_out(&self) -> bool {
        self.version >= (7, 63, 0)
    }
}

fn parse_version(text: &str) -> Option<(u32, u32, u32)> {
    // `8.7.1`, and tolerantly `8.10.0-DEV`.
    let mut parts = text.split('.').map(|part| {
        let digits: String = part.chars().take_while(char::is_ascii_digit).collect();
        digits.parse::<u32>().ok()
    });
    let major = parts.next()??;
    let minor = parts.next()??;
    let patch = parts.next().flatten().unwrap_or(0);
    Some((major, minor, patch))
}

fn backend_named(word: &str) -> Option<TlsBackend> {
    let name = word.split('/').next().unwrap_or(word);
    match name.to_ascii_lowercase().as_str() {
        "libressl" => Some(TlsBackend::LibreSsl),
        "openssl" | "boringssl" | "awslc" | "quictls" => Some(TlsBackend::OpenSsl),
        "schannel" => Some(TlsBackend::Schannel),
        "securetransport" => Some(TlsBackend::SecureTransport),
        "gnutls" | "wolfssl" | "mbedtls" | "rustls-ffi" | "bearssl" => {
            Some(TlsBackend::Other(name.to_owned()))
        }
        _ => None,
    }
}

/// The verified operating-system curl.
///
/// There is exactly one executable a request may run, so there is nothing
/// for a caller to choose: [`TrustedCurl::resolve`] is the only constructor.
#[derive(Debug, Clone)]
pub struct TrustedCurl {
    path: PathBuf,
    info: &'static CurlInfo,
}

impl TrustedCurl {
    /// Locates and verifies the operating system's curl.
    ///
    /// The path check runs on every call (a few `stat`s). The version probe
    /// runs once per process, on the first success: the answer cannot change
    /// without the file changing, and a changed file fails the path check or
    /// is still the operating system's.
    pub fn resolve() -> Result<Self, NetFailure> {
        static INFO: OnceLock<CurlInfo> = OnceLock::new();
        let path = trusted_curl_path().ok_or(NetFailure::CurlUnavailable)?;
        if let Some(info) = INFO.get() {
            return Ok(Self { path, info });
        }
        let probed = probe(&path)?;
        Ok(Self {
            path,
            info: INFO.get_or_init(|| probed),
        })
    }

    /// The absolute, canonical path of the executable.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Version, TLS backend and capabilities.
    #[must_use]
    pub fn info(&self) -> &CurlInfo {
        self.info
    }

    /// The same executable with a different capability report, so a unit
    /// test can render a config as an old curl would be given it.
    #[cfg(test)]
    pub(crate) fn with_info(&self, info: &'static CurlInfo) -> Self {
        Self {
            path: self.path.clone(),
            info,
        }
    }
}

/// Runs `curl -q --version` under the launcher's environment policy.
fn probe(path: &Path) -> Result<CurlInfo, NetFailure> {
    let mut command = Command::new(path);
    command
        .arg("-q")
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    apply_environment(&mut command);
    let mut child = command
        .spawn()
        .map_err(|error| NetFailure::Spawn(error.to_string()))?;
    // The output is a few hundred bytes, far under a pipe buffer, so it is
    // safe to wait first and read after. A curl that never exits is killed.
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if started.elapsed() < PROBE_LIMIT => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(NetFailure::Spawn(
                    "curl --version did not finish".to_owned(),
                ));
            }
            Err(error) => return Err(NetFailure::Spawn(error.to_string())),
        }
    }
    let output = child
        .wait_with_output()
        .map_err(|error| NetFailure::Spawn(error.to_string()))?;
    CurlInfo::parse(&String::from_utf8_lossy(&output.stdout))
        .ok_or_else(|| NetFailure::Spawn("curl --version printed no version banner".to_owned()))
}

/// Empties a child's environment and fixes its working directory.
///
/// The daemon may have been started by whatever first called `pam`, an
/// agent included, so nothing it inherited is passed on: not a proxy
/// variable, not a CA variable, not `CURL_HOME`. The working directory is
/// the filesystem root, so no relative path in a config can mean a file in
/// a directory someone else chose.
pub(crate) fn apply_environment(command: &mut Command) {
    command.env_clear();
    #[cfg(target_os = "windows")]
    {
        // A Windows child cannot initialize WinSock or the crypto stack
        // without the system roots, and `/` is not a working directory
        // there: the drive root is the neutral equivalent.
        for key in WINDOWS_KEPT_ENV {
            if let Some(value) = std::env::var_os(key) {
                command.env(key, value);
            }
        }
        let drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_owned());
        command.current_dir(format!("{drive}\\"));
    }
    #[cfg(not(target_os = "windows"))]
    command.current_dir("/");
}

/// `/usr/bin/curl`, canonical, executable, with every ancestor owned by
/// root and not group- or world-writable: outside an ordinary same-user
/// process's write authority.
#[cfg(target_os = "macos")]
fn trusted_curl_path() -> Option<PathBuf> {
    use std::os::unix::fs::MetadataExt;
    let path = std::fs::canonicalize("/usr/bin/curl").ok()?;
    let binary = path.metadata().ok()?;
    if !binary.is_file() || binary.mode() & 0o111 == 0 {
        return None;
    }
    // A canonical path holds no symlinks; each component is checked itself.
    for ancestor in path.ancestors() {
        let metadata = ancestor.symlink_metadata().ok()?;
        if metadata.file_type().is_symlink() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0
        {
            return None;
        }
    }
    Some(path)
}

/// Windows has no root-owned file model readable without `unsafe` or a
/// platform crate, so trust comes from the one path the operating system
/// itself owns and services: `%SystemRoot%\System32\curl.exe`. The fixed
/// location is what rules out a planted lookalike — `PATH` is never
/// searched — and the canonical file must still be inside the canonical
/// `System32` directory.
#[cfg(target_os = "windows")]
fn trusted_curl_path() -> Option<PathBuf> {
    let system_root = std::env::var_os("SystemRoot")?;
    let system32 = std::fs::canonicalize(Path::new(&system_root).join("System32")).ok()?;
    let canonical = std::fs::canonicalize(system32.join("curl.exe")).ok()?;
    if !canonical.is_file() || !canonical.starts_with(&system32) {
        return None;
    }
    Some(canonical)
}

/// No other platform is supported; none has a curl pam trusts.
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn trusted_curl_path() -> Option<PathBuf> {
    None
}
