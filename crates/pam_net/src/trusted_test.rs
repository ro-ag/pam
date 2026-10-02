use crate::trusted::{CurlInfo, TlsBackend, TrustedCurl, WINDOWS_KEPT_ENV, apply_environment};

const MACOS_BANNER: &str = "curl 8.7.1 (x86_64-apple-darwin26.0) libcurl/8.7.1 (SecureTransport) LibreSSL/3.3.6 zlib/1.2.12 nghttp2/1.69.0\nRelease-Date: 2024-03-27\nProtocols: dict file ftp ftps gopher gophers http https imap imaps ipfs ipns ldap ldaps mqtt pop3 pop3s rtsp smb smbs smtp smtps telnet tftp\nFeatures: alt-svc AsynchDNS GSS-API HSTS HTTP2 HTTPS-proxy IPv6 Kerberos Largefile libz MultiSSL NTLM SPNEGO SSL threadsafe UnixSockets\n";

const WINDOWS_BANNER: &str = "curl 8.9.1 (Windows) libcurl/8.9.1 Schannel zlib/1.3 WinIDN\nRelease-Date: 2024-07-31\nProtocols: dict file ftp ftps http https imap imaps ipfs ipns ldap ldaps mqtt pop3 pop3s smb smbs smtp smtps telnet tftp\nFeatures: alt-svc AsynchDNS HSTS HTTPS-proxy IPv6 Kerberos Largefile libz NTLM SPNEGO SSL SSPI threadsafe Unicode UnixSockets\n";

#[test]
fn the_version_banner_is_read() {
    let macos = CurlInfo::parse(MACOS_BANNER).unwrap();
    assert_eq!(macos.version, (8, 7, 1));
    assert_eq!(macos.version_text(), "8.7.1");
    // The parenthesized backend is compiled in but not the one in use.
    assert_eq!(macos.backend, TlsBackend::LibreSsl);
    assert!(macos.https_proxy);
    assert!(macos.supports_proxy());
    assert!(macos.supports_cidr_no_proxy());
    assert!(macos.supports_stderr_write_out());
    assert!(macos.banner.starts_with("curl 8.7.1 "));

    let windows = CurlInfo::parse(WINDOWS_BANNER).unwrap();
    assert_eq!(windows.version, (8, 9, 1));
    assert_eq!(windows.backend, TlsBackend::Schannel);
    assert_eq!(windows.backend.to_string(), "Schannel");
    assert!(windows.https_proxy);

    let old = CurlInfo::parse("curl 7.55.1 (Windows) libcurl/7.55.1 WinSSL\nRelease-Date: 2017-11-14\nProtocols: http https\nFeatures: AsynchDNS IPv6 Largefile SSPI Kerberos SPNEGO NTLM SSL\n").unwrap();
    assert_eq!(old.version, (7, 55, 1));
    assert_eq!(old.backend, TlsBackend::Other("unknown".to_owned()));
    assert!(!old.https_proxy);
    assert!(!old.supports_proxy());
    assert!(!old.supports_cidr_no_proxy());
    assert!(!old.supports_stderr_write_out());

    let dev = CurlInfo::parse("curl 8.10.0-DEV (x) libcurl/8.10.0-DEV OpenSSL/3.3.1\n").unwrap();
    assert_eq!(dev.version, (8, 10, 0));
    assert_eq!(dev.backend, TlsBackend::OpenSsl);
    assert!(CurlInfo::parse("wget 1.21\n").is_none());
    assert!(CurlInfo::parse("").is_none());
    assert!(CurlInfo::parse("curl notaversion\n").is_none());
}

#[test]
fn the_child_environment_is_empty_except_for_the_windows_system_variables() {
    let mut command = std::process::Command::new("curl");
    command.env("HTTPS_PROXY", "http://evil.invalid:3128");
    apply_environment(&mut command);
    let explicit: Vec<(String, Option<String>)> = command
        .get_envs()
        .map(|(key, value)| {
            (
                key.to_string_lossy().into_owned(),
                value.map(|v| v.to_string_lossy().into_owned()),
            )
        })
        .collect();
    // Clearing drops the variable set before it; nothing is set after
    // except, on Windows, values copied from the allowlist.
    for (key, _) in &explicit {
        assert!(
            WINDOWS_KEPT_ENV.contains(&key.as_str()),
            "{key} is in the child environment"
        );
    }
    #[cfg(not(target_os = "windows"))]
    {
        assert!(explicit.is_empty(), "{explicit:?}");
        assert_eq!(
            command.get_current_dir().map(std::path::Path::to_path_buf),
            Some(std::path::PathBuf::from("/"))
        );
        // std renders a cleared environment as `env -i`: the one place the
        // clear itself can be observed.
        assert!(format!("{command:?}").contains("env -i"), "{command:?}");
    }
    #[cfg(target_os = "windows")]
    {
        let dir = command.get_current_dir().expect("a working directory");
        assert!(dir.to_string_lossy().ends_with(":\\"), "{}", dir.display());
    }
}

#[test]
fn the_trusted_curl_is_the_operating_systems_by_absolute_path() {
    let Ok(curl) = TrustedCurl::resolve() else {
        eprintln!("no trusted operating-system curl; skipping");
        return;
    };
    assert!(curl.path().is_absolute());
    #[cfg(target_os = "macos")]
    assert_eq!(curl.path(), std::path::Path::new("/usr/bin/curl"));
    #[cfg(target_os = "windows")]
    assert!(
        curl.path()
            .to_string_lossy()
            .to_ascii_lowercase()
            .ends_with("system32\\curl.exe"),
        "{}",
        curl.path().display()
    );
    assert!(curl.info().version >= (7, 55, 0));
    // Resolved again: the same answer, from the cached probe.
    let again = TrustedCurl::resolve().unwrap();
    assert_eq!(again.info(), curl.info());
    assert_eq!(again.path(), curl.path());
}
