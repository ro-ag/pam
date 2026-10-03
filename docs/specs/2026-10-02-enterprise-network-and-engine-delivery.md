# Enterprise network settings and engine delivery — design and implementation plan

Status: implemented, 2026-10-02, on `feat/enterprise-network` (tasks T1–T7
below); Windows evidence pending (T8). What was built where it differs from
the design is in [As built](#as-built). Implements the owner directive of
2026-10-02 ("do what is best for the product and make it easy for enterprise
environments") and closes the design review's deferred items "two curl
launchers with divergent policy" and "proxy and certificate settings need an
owner decision" ([review, model 9](../reviews/design-review-2026-10-02.md)).
Companion to [the llama.cpp engine spec](2026-09-13-llama-cpp-engine.md) and
[command containment](../command-containment.md).

## As built

The design above the fold is the contract; these are the places the
implementation settled differently, each recorded by the task that made the
call, and the items still open.

Contract differences:

- **The local engine archive is its own op.** `admin.models.engine.import
  { path, confirm }` (120 s bridge deadline), not `install { source: { kind:
  "local" } }`. `install { confirm }` keeps its shape and uses the configured
  mirror when one is set; both refuse any key they do not list.
- **Weights import** is `admin.models.import { path, confirm, vendor?,
  expected_sha256? }`. The catalog preset is chosen by the file's size (no
  `preset_id`); a size match holds the copy to that preset's SHA-256 and
  records it verified; otherwise the file lands under `vendor` (default
  `imported`) and is verified only when `expected_sha256` was given and
  matched. A cancelled import is deleted, not resumed. The job row is kind
  `import` (store schema 15; it was `download` until that migration).
- **Disclosure fields are flat** on the `admin.models.engine.status` body
  (`expected_asset`, `expected_size`, `expected_sha256`, `download_url`,
  `download_host`, `mirror_in_use`, `mirror_host`, `upstream_host`,
  `engine_dir`, `install_dir`, `source`, `loaded`, `removable`,
  `network_issue`) rather than a `plan` object, and catalog presets carry
  `fetch { url, host, source }`. Neither carries `route` or `proxy`: that
  would need a keychain-backed profile resolution on every status poll, and
  the route is what the Network tab's Test shows. The engine card and the
  download confirmation therefore have no "Route:" line.
- **Manifest source kinds** are `download | mirror | import` (not `upstream |
  mirror | local_archive`), with `host` for a download, `host` and `url` for a
  mirror, `path` and `imported_at_ms` for an import.
- **No engine cancel op.** Install and import stay synchronous under the
  bridge deadline, as decided; dropping the deadline cancels the transfer or
  the copy, and the card shows the two-minute resume note instead of a Cancel
  button.
- **`stage` gains `connect`.** A failed first connection on a direct or
  bypassed route (target DNS, connect, connect timeout) is reported at stage
  `connect`; `proxy` is only for proxy-side failures; a failure before any
  connection (no usable curl, unusable settings) reports the first stage the
  route has. The reply carries `route` as specified and no `proxy` field.
- **`EngineRelease` fields stay public.** What is gated is the entry point:
  `install(base, cancel, net, mirror)` and `import(base, path, cancel)` build
  `EngineRelease::pinned` themselves; `install_release` and `import_release`
  exist only under `cfg(any(test, feature = "testing"))`.
- **`engine_busy`.** Install, import and remove are refused while a model is
  loaded, under the operation lock, so a load cannot slip in.
- **The managed layer** ships as the `ManagedNetworkLayer` trait with a fixed
  stub (`FixedManagedNetwork`); `mirror_allowed_hosts` is policy-only and is
  enforced on the resolved value; the policy file is a later plan.
- **`ignored_env`** lists eleven names (the proxy variables in both cases,
  `CURL_CA_BUNDLE`, `SSL_CERT_FILE`, `SSL_CERT_DIR`); the page prints them.
- **`tools/check.sh`** does not yet export `PAM_REQUIRE_TLS_FIXTURE=1`; that
  one-line edit is T8's. T7 ran the gate with the variable in the environment.

Open:

- Windows evidence (T8, in the Parallels VM): `curl --version` and backend;
  whether `write-out` prints on a failed transfer; what `cacert` does on
  Schannel; the exact stderr for an untrusted issuer, a name mismatch, a
  proxy 407 and a refused proxy; the revocation failure text for a private
  CA; whether an issuer is printed; "Test network settings" against the
  fixtures. Also: the wording when an import source is held with exclusive
  sharing (reported as `engine_import_source_missing`), and a full volume off
  macOS, where `platform_free_bytes` is `None` and the engine copy reports
  `engine_io_failed` with the OS text rather than `engine_no_space`.
- macOS: the fixtures prove that a private issuer is untrusted until its root
  is imported and trusted afterwards; whether `cacert` replaces or extends
  the keychain's trust for the same request is not measured.
- The two owner questions below (Windows revocation, proxy single sign-on)
  are unchanged, and the landing git broker stays proxy-disabled as scoped.

Supported platforms for this work (owner scope change, 2026-10-02): macOS arm64
and Windows amd64/arm64. Linux and Intel macOS are not supported and nothing here
is designed, tested or documented for them. Their `ENGINE_ASSETS` rows are
removed by [the drop-Linux-and-Intel-Mac plan](../plans/2026-10-02-drop-linux-and-intel-mac.md),
so the table has exactly the three supported targets.

Line references are to the working tree on `feat/framed-public-transport`
(HEAD 7a6bf46 plus uncommitted plan 49 edits to `admin.rs`, `daemon.rs`,
`lib.rs`, `transport.rs` and others). Re-anchor before implementing; the files
this plan edits in `pam_daemon` overlap plan 49, so implementation starts after
that plan is squash-merged (see [Implementation plan](#implementation-plan)).

## Goal and non-goals

Goal: PAM works on a network where traffic leaves through an HTTPS proxy, where
TLS is inspected by a corporate certificate authority, and where GitHub and
Hugging Face are blocked at runtime or the machine has no route at all. Every
network fact is set by the human in the GUI, shown before it is used, audited
when it changes, and never inherited from an environment the daemon does not
control.

In scope:

1. GUI-set network settings: HTTPS proxy (with optional authentication), a
   no-proxy list, a CA bundle, for the HTTP connectors and for downloads.
2. One hardened curl launcher for both, replacing the two that exist.
3. Two more ways to supply the engine (an internal mirror URL; a pre-provisioned
   archive on disk) and two for model weights (mirror; import from a file), all
   under the same pinned digests.
4. Plain disclosure before the Install click and in the README.
5. A "Test network settings" action with legible causes.
6. A settings shape a later managed-policy layer can override and lock.

Not in scope: the policy file itself; SOCKS and PAC/WPAD; proxy single sign-on
(Kerberos/Negotiate, see [Open questions](#open-questions)); a proxy for the
landing git broker (it runs git with `http.proxy` forced empty,
`landing_git.rs:279`, and stays that way until a follow-up); proxies for the
vendor agent CLIs the curator runs; a CLI for any of this (administration stays
GUI-only, `docs/admin-boundary.md`); making engine install a progress job.

## Current state

### Two curl launchers

| | Connectors (`pam_connectors`) | Downloads (`pam_model`) |
| --- | --- | --- |
| Trusted binary | `curl.rs:32-74` (`/usr/bin/curl` with root-owned ancestors on macOS; `%SystemRoot%\System32\curl.exe` on Windows) | `download.rs:1126-1163`, a copy; its own comment says it is duplicated because "this crate does not depend on `pam_connectors`" (`download.rs:449-458`) |
| Environment | `env_clear()` (`curl.rs:154`); Windows adds `SystemRoot`, `SystemDrive`, `windir`, `COMSPEC`, `TEMP`, `TMP` (`curl.rs:163-179`). Nothing else, so a proxy or CA variable in the daemon's environment has no effect. | `env_clear().envs(curl_env(...))` (`download.rs:820`) where `curl_env` keeps `HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY`, `NO_PROXY` (both cases), `CURL_CA_BUNDLE`, `SSL_CERT_FILE`, `SSL_CERT_DIR` (`download.rs:1100-1118`). The comment calls it "an explicit, temporary allowlist". |
| Arguments | `-q`, `--config -`, `--silent`, `--show-error`, `--include`, `--max-time`, `--max-filesize`, `--proto =https` (`curl.rs:141-153`); URL, headers and body on stdin (`curl.rs:202-223`) | `-q`, `--fail`, `--location`, `--proto =https,http`, `--proto-redir =https,http`, timeouts, `--output <part>`, `--etag-save`, URL after `--` (`download.rs:821-850`); stdin is null (`download.rs:851`) |
| Scheme | https only; plain http behind a test-only method (`curl.rs:185-194`) | https and http both accepted in production (`check_url`, `download.rs:473-493`) |
| Failure mapping | exit 35/51/58/59/60 become `Certificate`, 28 `Timeout`, everything else `Network("curl exited N")` (`curl.rs:280-303`) | `failure_cause` maps 5/6 to `dns_failed`, 7 to `connect_failed`, 35/58/59/60/77/83/91 to `tls_error`, others (`download.rs:522-541`) |

The two behave differently on exactly the axis an enterprise cares about: a
download can be proxied by a daemon-environment variable, a connector call cannot
be proxied at all (`docs/command-containment.md:15` records this as "a recorded
owner decision"). A proxy variable in the environment of a lazily started daemon
is the thing decision 1 forbids trusting: the daemon is started by whatever
called `pam`, an agent included.

### Facts that shape the design

- Both launchers hand the URL over differently, but neither has a notion of a
  proxy, a CA file, or a route. `HttpRequest` has no network field
  (`transport.rs:65-80`); the connector crate sees only `&dyn HttpTransport`.
- `CurlTransport::trusted()` is built once at daemon start and held as
  `Arc<dyn HttpTransport>` (`daemon.rs:586`, `open_http_transport` at
  `daemon.rs:756`, field at `connector_service.rs:339`). A setting that can change
  at runtime therefore has to be read per spawn, not captured at construction.
- `--include` output is parsed by `parse_response` (`curl.rs:413-428`), which
  skips only 1xx blocks. Through a proxy, curl prints a `HTTP/1.1 200 Connection
  established` block for the CONNECT before the real response; today that would
  be parsed as the final answer with an empty body. The launcher must pass
  `suppress-connect-headers` (curl 7.54+).
- Scope is checked on the product URL before any process starts:
  `authorize_connector_at` compares the stored scope's normalized base URL to the
  configured one (`scope_policy.rs:243-247`), `scoped_row` runs it per physical
  request (`connector_service.rs:651-667`), and `ScopedTransport::send_once`
  repeats it per request including the one permitted redirect hop
  (`connector_service.rs:823-865`, `867-911`; hop target filter
  `redirect_target_refusal`, `connector_service.rs:922-947`). The proxy never
  appears in any of that and must not.
- Settings live in the store's `setting` table as JSON text
  (`store.rs:2174` read, `2240` write, `2207` compare-and-swap). The scope policy
  is the precedent for a versioned single-blob setting that fails closed when
  malformed (`scope_policy.rs:16`, `109-120`). Secrets live in the OS keychain
  through `SecretStore` under service `dev.pam.connector`, account
  `pam.connector.v1.<id>` (`secrets.rs:33`, `579`, `609`).
- Admin ops follow one shape: an `OP_*` constant, a `*_ADMIN_OPS` list the GUI
  bridge whitelists, a `dispatch_*` function called from `admin.rs:379-399`, one
  terminal audit row for the request, plus an extra action row for config
  changes (`admin_connectors.rs:61`, `148-156`). The bridge gives each op a
  deadline (`bridge.rs:64`, `169-175`) and demands a typed phrase for ops that
  widen what agents or the network may do (`bridge.rs:380-405`).
- The engine reaches its model server over a private Unix socket, or a loopback
  TCP port on Windows (`engine_server.rs:352-370`), through `engine_http`, a
  hand-written client with no curl, no TLS and no redirects
  (`engine_http.rs:1-8`). The child runs with `env_clear()`
  (`engine_server.rs:724`). The proxy therefore cannot touch the engine's
  traffic, and the launcher is not involved in it.
- Installing the engine is one synchronous admin op under a 120 s bridge deadline
  (`bridge.rs:64`, `171`). It builds `EngineRelease::pinned`, downloads with the
  model downloader, unpacks with the OS `tar`, and requires the server to report
  the pinned build (`engine.rs:388-449`, `603-712`). `install_release` and
  `EngineRelease` are public with every field public (`engine.rs:164-179`,
  `400`), so today nothing structural stops a caller from installing a release
  with a different digest; the daemon just does not.
- There is no way to remove the engine, in the GUI or the daemon.
- Test fixtures that exist: `crates/pam_connectors/tests/curl_origin.rs` (a plain
  HTTP/1.1 loopback origin driven by the real trusted curl; modes `Json`,
  `Oversized`, `Stall`; helper `curl_on_path` at `:224`) and
  `crates/pam_model/src/testing.rs` (a range-serving origin with ETag, `drop_after`
  and chunked faults). There is no proxy fixture and no TLS fixture anywhere in
  the workspace, and no TLS crate in `Cargo.lock`.

## Settings model

### Shape

One versioned JSON document in the `setting` table under the key `net.settings`,
read on every spawn, never cached (the same rule as the scope policy: a change
applies to the next request). `deny_unknown_fields`, at most 16 KiB. Missing key
is the default (direct connection, nothing else). A document that does not parse,
has an unknown version, or fails validation does not fall back to defaults: the
launcher refuses with `network_settings_invalid`. Falling back to "direct" on a
corrupt proxy setting would send traffic around a proxy the organisation
requires.

```json
{
  "version": 1,
  "proxy": { "url": "http://proxy.corp.example:3128", "auth": "basic", "username": "svc-pam" },
  "no_proxy": ["jenkins.corp.example", ".internal.example", "10.0.0.0/8"],
  "ca_bundle": { "sha256": "…64 hex…", "certificates": 3,
                 "source_path": "C:\\ProgramData\\corp\\ca.pem", "imported_ts": 1790000000 },
  "engine_mirror": "https://artifacts.corp.example/llama.cpp/b10938/",
  "models_mirror": "https://artifacts.corp.example/api/huggingfaceml/hf-remote/"
}
```

| Field | Type | Default | Validation (at save and again at every spawn) |
| --- | --- | --- | --- |
| `proxy.url` | string or null | null = direct | scheme `http` or `https`; host present; explicit port required (curl defaults a bare proxy to 1080, which surprises); no userinfo, query, fragment; path empty or `/`; at most 255 bytes; normalized to lowercase host, no trailing slash. `socks4`, `socks5`, `socks5h` and scheme-less values are refused with a sentence saying so (a scheme-less value gets "did you mean http://…"). |
| `proxy.auth` | `none`, `basic`, `anyauth` | `none` | `basic` and `anyauth` need a stored credential to be useful; saving them without one is allowed (the Test says "proxy authentication required") but the GUI marks it. `anyauth` lets curl pick among Basic, Digest and NTLM from the 407 challenge; NTLM needs `DOMAIN\user` in `username`. |
| `proxy.username` | string or null | null | at most 128 bytes, no `:`, no control characters. Not secret; stored in the document. |
| proxy password | keychain | none | written only through the admin op, stored via `SecretStore` as connector id `network.proxy` (account `pam.connector.v1.network.proxy`), never in the document, an audit row, a reply, a log line, argv or the environment. Trimmed; control characters refused (same rule as `credential_arg`, `admin_connectors.rs:291-337`). Replies say only `credential: { present: bool }`. |
| `no_proxy` | list of strings | empty | at most 64 entries, each at most 255 bytes, trimmed, lowercased, deduplicated. Grammar in [Proxy](#proxy). Empty entries, ports, URLs and `<local>` are refused. |
| `ca_bundle` | object or null | null | produced only by import from a path (see [CA bundle](#ca-bundle)); the stored fields describe the private copy PAM made. Not writable as a raw string. |
| `engine_mirror` | URL or null | null | [Mirror URL rules](#mirror-url-rules). |
| `models_mirror` | URL or null | null | same rules. |

Names are final: setting key `net.settings`; keychain id `network.proxy`; private
files under `<base>/net/`; admin ops `admin.network.get`, `.set`, `.test`;
audit action `network.configure`.

A seventh field exists in the types but not in the stored document:
`mirror_allowed_hosts`. It is part of the managed layer only (below), because a
list the same human can edit is not a control.

### Admin ops (all GUI-only through the private admin socket)

New module `crates/pam_daemon/src/admin_network.rs`, dispatched from
`AdminService::dispatch` next to `dispatch_connectors` (`admin.rs:379-399`), with
`NETWORK_ADMIN_OPS` appended to the bridge whitelist (`bridge.rs:76-133`) the same
way `CONNECTOR_ADMIN_OPS` is. Same security model as every admin op: tripwire,
request row, one terminal audit row, structural guard (no `classify` entry, never
grantable). No CLI subcommand.

`admin.network.get {}` answers:

```json
{
  "settings": { "proxy": {…}, "no_proxy": […], "ca_bundle": {…}, "engine_mirror": "…", "models_mirror": "…",
                "credential": { "present": true, "store_available": true } },
  "effective": { "proxy": { "source": "user", "locked": false }, … },
  "curl": { "version": "8.7.1", "backend": "SecureTransport", "supports_proxy": true, "supports_cidr_no_proxy": true },
  "ignored_env": ["HTTPS_PROXY"]
}
```

`effective` is per field: `source` is `default`, `user` or `policy`; `locked` is
true when policy owns it (see [Policy layer](#policy-layer)). `curl` comes from
a cached `curl --version` probe by the launcher. `ignored_env` lists the *names*
(never values) of proxy and CA variables present in the daemon's own environment,
so the screen can say they are ignored; there is deliberately no import button,
because that environment is the untrusted one.

`admin.network.set` takes a patch. Absent key keeps, `null` clears, a value sets
(the `ConfigurePatch` convention, `admin_connectors.rs:120-133`):

```json
{ "proxy": null | { "url": "…", "auth": "none|basic|anyauth", "username": null | "…" },
  "credential": { "set": "…" } | { "clear": true },
  "no_proxy": ["…"],
  "ca_bundle": null | { "path": "…" },
  "engine_mirror": null | "…", "models_mirror": null | "…" }
```

Unknown keys are refused with `invalid_admin_args` (so no field can ever smuggle
a digest, a tag or a raw CA string in). The patch is validated whole before any
effect and is atomic as a unit: if any field it touches is locked by policy the
whole patch is refused with `setting_locked`. Effects, in this order, so a
failure leaves the old configuration intact:

1. validate every field; for `ca_bundle`, read, validate and normalize the file
   and write the private copy `<base>/net/ca-<sha12>.pem` (content-addressed, so
   an old copy is never overwritten);
2. write or clear the keychain credential (`SecretStore`, connector id
   `network.proxy`);
3. write the document with `compare_exchange_setting` on the exact prior bytes
   (`store.rs:2207`), so two saves cannot lose each other's update; a lost race
   answers `network_settings_conflict` and the GUI reloads;
4. append the `network.configure` audit row on the request's envelope id
   (`append_audit(envelope_id, …, Decision::Allow, Actor::Human, Some(detail))`,
   the same call as `admin_connectors.rs:148-156`), then delete CA copies no
   longer referenced.

The audit row records what changed and nothing secret:

```json
{ "changed": ["proxy", "ca_bundle"],
  "proxy": { "host": "proxy.corp.example", "port": 3128, "scheme": "http", "auth": "basic", "username": "svc-pam" },
  "credential": "set",
  "no_proxy": ["jenkins.corp.example", ".internal.example"],
  "ca_bundle": { "sha256": "…", "certificates": 3, "source_path": "…" },
  "engine_mirror_host": "artifacts.corp.example", "models_mirror_host": null,
  "locked_by_policy": [] }
```

`credential` is `set`, `cleared` or `unchanged`, the vocabulary of
`CredentialAction::audit_word`. The terminal request row carries only
`{ "op", "changed" }`. Arguments are never in the request ledger (existing admin
rule).

Typed confirmation: the bridge's `required_confirmation` returns a new phrase
`network` (`CONFIRM_NETWORK`) for `admin.network.set` whenever the patch sets or
changes `proxy.url`, `credential.set` or `ca_bundle`, and not for clearing them,
editing `no_proxy`, or setting mirrors. Reason: a proxy plus a CA bundle is the
one configuration that lets a third party read the Authorization headers PAM sends
to connectors (a TLS-inspecting proxy terminates the session). That is an
exposure change on the order of adding a grant. A compromised webview can still
supply the phrase, as the review already records for grants; the phrase guards
against accident, not against that.

`admin.network.test` is specified in [Connection test](#connection-test).

### Where each consumer reads it

`pam_net::NetworkSource` (below) is implemented once in the daemon
(`network_service.rs`): it loads `net.settings`, applies the managed layer,
re-validates, reads the proxy password from `SecretStore` only when
`auth != none`, verifies the CA copy's digest, and returns an immutable
`Arc<NetworkProfile>`. Consumers hold an `Arc<dyn NetworkSource>` and ask per
spawn:

- connectors: `CurlTransport::trusted(source)` (replaces the argument-less
  constructor, `curl.rs:102`); the daemon builds it in `open_http_transport`;
- downloads: `ModelService` holds the source (set the way `set_engine_base` is,
  `model_service.rs:560`), resolves a profile in `start_download`
  (`model_service.rs:871`) and passes it to `pam_model::download::start`; the
  engine install takes the same profile;
- the Test action.

A keychain read per spawn is the existing pattern for connector secrets
(`connector_service.rs:705`); the review's "per-request credential cache" item
stays deferred and applies to this read as well.

## One hardened curl launcher

### Where it lives

A new small crate, `crates/pam_net`. The two existing crates cannot share it
without a layering inversion: `pam_model` must not depend on `pam_connectors`
(a model layer that pulls in the flow schema and the connector adapters to get a
curl launcher), and `pam_connectors` must not depend on `pam_model`. `pam_proto`
and `pam_flow` are not homes either: one is the wire schema, the other the flow
language, and `pam_model` depends on neither. The review deferred this item for
precisely that reason ("the two crates share no dependency"); a third leaf crate
is the smallest answer that fixes it. It adds no external dependency
(`url`, `thiserror`, `sha2`, `hex`, `tokio` with `process`, `io-util`, `time`,
`sync` are already in the workspace) and compiles no C. It is not published (the
release workflow builds binaries only, `.github/workflows/release.yml`).

Contents (each with a sibling `_test.rs`):

| Module | Owns |
| --- | --- |
| `trusted.rs` | The trusted-curl path check (moved from `curl.rs:32-74` and `download.rs:1126-1163`, which both go away), a cached `curl --version` probe giving version and TLS backend. |
| `profile.rs` | `NetworkProfile`, `Proxy`, `NoProxyRule`, validation for every field in the table above, the route preview (`route_for(&Url)`), mirror URL rules and the catalog rewrite. |
| `ca.rs` | CA bundle read, validate, normalize, private copy, digest check. |
| `launch.rs` | `CurlBuilder`: the one place that builds curl's argument vector, environment and stdin config; `escape`; capped reads; kill on drop. |
| `failure.rs` | `NetFailure` and the classification of exit code, `write-out` sentinel and stderr. |
| `testing.rs` (feature `testing`) | Fake HTTP proxy, TLS origin driver, static PEM fixtures. |

### API sketch

```rust
pub struct TrustedCurl { path: PathBuf, info: CurlInfo }      // resolved once
pub struct CurlInfo { pub version: (u32, u32, u32), pub backend: TlsBackend, pub banner: String }

pub struct NetworkProfile { /* proxy, no_proxy, ca_bundle (private copy path) */ }
impl NetworkProfile {
    pub fn direct() -> Self;
    pub fn route_for(&self, target: &Url) -> Route;           // Direct | Bypass | Proxy { host, port }
}
pub trait NetworkSource: Send + Sync {
    fn profile(&self) -> Pin<Box<dyn Future<Output = Result<Arc<NetworkProfile>, NetworkError>> + Send + '_>>;
}

impl TrustedCurl {
    pub fn resolve() -> Result<&'static Self, NetFailure>;     // OnceLock
    pub fn request(&self, net: &NetworkProfile) -> CurlBuilder;
}
// CurlBuilder: .url() .header() .method() .data_binary() .max_time() .connect_timeout()
//   .speed() .max_filesize() .output() .etag_save() .resume() .fail_on_http_error()
//   .follow_https_redirects() .include_headers() .diagnostic() .spawn() -> CurlChild
```

### What the launcher fixes

1. **Argument vector is constant**: `-q --config -` and nothing else. Every
   variable value (URL, headers, body, output and etag paths, timeouts, size
   limit, protocol restrictions, proxy, credentials, CA path) is a line of the
   stdin config document, escaped by one `escape` function (the one at
   `curl.rs:401`). Consequences: nothing secret or user-chosen is in argv, so
   `ps` shows nothing; a path with a space or a backslash on Windows cannot be
   mis-split by Windows command-line quoting; a pasted URL starting with `-`
   cannot be an option (it is a config value). The download's `--`-before-URL
   fence (`download.rs:849`) becomes unnecessary but `check_url` stays as the
   first fence. A test asserts the constructed argv equals the constant for
   every builder configuration.
2. **Environment policy is one rule**: `env_clear()` plus, on Windows only,
   `SystemRoot`, `SystemDrive`, `windir`, `COMSPEC`, `TEMP`, `TMP`
   (`curl.rs:163-179`); working directory `/` or the drive root. No proxy
   variable, no CA variable, no `SSLKEYLOGFILE`, `CURL_HOME`, `HOME`, `PATH`.
   `download::curl_env` and its `KEPT` list are deleted.
3. **Protocol**: `proto = "=https"` and `proto-redir = "=https"` in production for
   both launchers. Plain http (and `http://` pasted model URLs, which
   `check_url` accepts today) are refused. A `testing`-feature method allows http
   for fixtures, as `allow_http_for_tests` does now (`curl.rs:189`).
4. **Network lines** from the profile, in this form:
   - direct: `noproxy = "*"` (belt and braces: no current curl reads OS proxy
     settings, but "nothing is inherited" should not depend on that);
   - proxied: `proxy = "http://host:port"`, `proxytunnel`, `suppress-connect-headers`,
     `noproxy = "<list>"`, and with a credential `proxy-user = "<user>:<password>"`
     with `proxy-basic` or `proxy-anyauth`;
   - CA: `cacert = "<private copy>"`, and for an `https://` proxy also
     `proxy-cacert = "<private copy>"` (explicit, so the proxy's own certificate
     is checked against the same bundle rather than whatever the backend defaults
     to);
   - never any option that weakens verification: no `insecure`, `proxy-insecure`,
     `ssl-no-revoke`, `ssl-revoke-best-effort`, `capath` from outside. A test
     scans the `pam_net` source for those spellings and fails if any appears.
5. **Loopback never goes through a proxy.** If the initial target host is
   `localhost`, a loopback IP literal or `::1`, the builder omits `proxy` and
   writes `noproxy = "*"`. Reason: the proxy cannot reach the machine's own
   loopback and would learn an internal address. (The engine's socket is not curl
   at all; this rule covers a developer's local Jenkins and the test fixtures'
   escape hatch, see [Test strategy](#test-strategy).) The proxy's own address
   being loopback (a local forwarder such as Cntlm) is fine; the rule applies to
   targets only.
6. **Diagnostics line**: `write-out = "%{stderr}\npam-net http_connect=%{http_connect} http_code=%{http_code} ssl_verify=%{ssl_verify_result}\n"`
   on every run, so classification has the CONNECT status (407, 403, 502 from the
   proxy) as a number instead of parsing curl's prose. `%{stderr}` needs curl
   7.63. The probe requires 7.63 and `suppress-connect-headers` (7.54) before it
   will configure a proxy; older curls get `curl_too_old` naming the version.
   T1 confirms on macOS and the Windows 11 VM that `write-out` is emitted on a
   failed transfer; if either platform does not, classification falls back to the
   stderr text for that platform and the table in `failure.rs` records which.
7. **Capped, killed-on-drop children** as today (`curl.rs:76-84`, `255-279`,
   `download.rs:44`, `854`).

The connector crate keeps `CurlTransport`, request validation
(`validate_headers`, `validate_request_body`, `curl.rs:482-564`), response
parsing and its own redirect hop; they call the builder. `download.rs` keeps
sidecars, checkpoints, resume, ETag restart and digest verification; it calls the
builder with `output`, `etag_save`, `resume`, `fail_on_http_error`,
`follow_https_redirects`. Behavioural change to note in the changelog: model
downloads stop honouring `HTTPS_PROXY` and friends; the GUI is the only source.

### Failure classification

`NetFailure` is the shared vocabulary, replacing `failure_cause`
(`download.rs:522`), the `Certificate` arm (`curl.rs:289`) and the `Network("curl
exited N")` text:

| Cause | When | Sentence the human reads |
| --- | --- | --- |
| `proxy_dns_failed` | exit 5 | "The proxy name `proxy.corp.example` did not resolve." |
| `proxy_unreachable` | exit 7 or 28 before CONNECT while a proxy is in use (the only TCP connect is to the proxy) | "Nothing accepted the connection at proxy.corp.example:3128." |
| `proxy_auth_required` | `http_connect=407` and no credential sent | "The proxy wants authentication. It offers: Basic, NTLM." (schemes from `Proxy-Authenticate`, diagnostic mode only) |
| `proxy_auth_rejected` | 407 with a credential sent | "The proxy refused the stored user name and password." |
| `proxy_denied` | CONNECT answered 403, 502, 503 | "The proxy refused to connect to jenkins.corp.example:443 (HTTP 403)." |
| `dns_failed` | exit 6 (direct) | "jenkins.corp.example did not resolve." |
| `connect_failed` | exit 7 (direct) | "Nothing accepted the connection." |
| `tls_untrusted_issuer` | exit 60/35/51 with an unknown-issuer message | "The server's certificate was issued by `CN=Corp Inspection CA`, which is not trusted. If your organisation inspects TLS, import its root in Settings › Network." The issuer is named when the backend prints it (see [Connection test](#connection-test)). |
| `tls_hostname_mismatch` | exit 60 with a name-mismatch message | "The certificate is not valid for jenkins.corp.example." |
| `tls_expired` | expiry text | "The certificate has expired or is not yet valid; check the clock." |
| `tls_revocation_unavailable` | Windows Schannel revocation error | "Windows could not check whether the certificate is revoked (no reachable revocation list)." |
| `ca_bundle_unreadable` | exit 58/77 with a `cacert` set | "curl could not read PAM's copy of the CA bundle; re-import it." |
| `timeout` | exit 28 elsewhere | the existing timeout wording |
| `curl_unavailable`, `curl_too_old` | trusted path / version probe | the platform install line (`download.rs:497`) or the version |

`TransportError` gains `Net(NetFailure)`; `Certificate` stays for existing
callers and tests. `From<TransportError> for ConnectorError` maps `Net` to
`ConnectorError::Network(failure.sentence())`, so connector refusals and the Test
share wording. Downloads publish `DownloadState::Failed { cause: failure.cause(),
.. }` and `failure_recovery` is rewritten around the same causes (its current
"check the network or proxy" lines, `download.rs:555-569`, become specific).

## Proxy

Accepted: `http://host:port` and `https://host:port`. The usual enterprise proxy
is an `http://` listener that tunnels HTTPS with CONNECT; PAM only ever talks to
`https` targets, so every connector and download request is a CONNECT tunnel and
the proxy sees the target host and port but not the path, query or headers
(unless it inspects TLS, below). An `https://` proxy is accepted and its
certificate is verified against the CA bundle (or the platform trust when none is
set). Not accepted in this version: SOCKS (needs its own fixture, and enterprise
HTTPS egress is nearly always an HTTP proxy), scheme-less values, userinfo in the
URL (so a password can never be in the settings document or echoed back), PAC and
WPAD (curl does not evaluate them; the administrator enters the proxy host; the
Network page says so).

Authentication: `none`, `basic`, `anyauth`. The password is in the keychain; the
launcher writes `proxy-user = "user:password"` into curl's stdin config, so it is
absent from argv, the environment, the audit log and every log. With an `http://`
proxy and Basic, the password crosses the LAN to the proxy in clear text; the
screen says so beside the field. The proxy credential is sent only to the proxy:
each hop of a connector redirect is a separate curl process, and the `Authorization`
header is already dropped on the hop (`curl.rs:332-334`, `connector_service.rs:903-907`).
The `Proxy-Authorization` name is also in the daemon's sensitive-header strip list
there; the launcher never writes it as a header line.

No-proxy matching. curl evaluates the list it is given (`noproxy = "…"`), because
downloads follow redirects across hosts inside one curl process (Hugging Face to
its CDN) and only curl sees each hop. The accepted entry grammar is the portable
subset, validated in `pam_net` and mirrored by a Rust preview used only for
display and the Test:

- `*` (everything bypasses; equals "no proxy");
- a host name, matching that host and any subdomain, case-insensitive; a leading
  dot is allowed and means the same (`.corp.example` and `corp.example` both match
  `jenkins.corp.example` and `corp.example`);
- an IPv4 or IPv6 literal, exact;
- an IPv4 or IPv6 CIDR range (`10.0.0.0/8`) — accepted only when the probe says
  the trusted curl is 7.86 or newer; otherwise refused with the version.

A host name is never resolved to be compared with a CIDR; a CIDR matches only
when the target is that kind of literal. There are no ports, no wildcards inside
names, no `<local>`. Loopback targets bypass regardless of the list (launcher
rule 5). The preview `route_for(&Url)` answers `Direct` (no proxy configured),
`Bypass` (matched the list or loopback) or `Proxy`. To keep the preview from
drifting from curl, a test runs a corpus of target names through the real curl and
the fake proxy and requires the proxy's connection count to equal the preview
(a bypassed `.invalid` name fails DNS with exit 6 instead of reaching the proxy).

Interaction with scope and redirects:

- The scope check is on the product URL and runs before any process starts
  (`scope_policy.rs:229-267`, `connector_service.rs:651-667`). Adding a proxy
  changes neither the URL being authorized nor what is compared. A proxy is a
  path to a host, not a host an agent can name.
- Every physical request, including the one log-redirect hop, passes
  `send_once` (rechecks scope and the connection snapshot) and
  `redirect_target_refusal` (no IP literals, no local-looking names, port 443
  only) *before* the transport is called, so the hop target is judged by its URL,
  not by where the proxy would send it. Name resolution moves to the proxy, which
  is the reason the filter is name-based; it already is.
- Each hop re-reads the profile. A settings change between the two hops applies
  to the second; this is acceptable and not worth a snapshot.
- An agent cannot choose, bypass or observe the proxy: connector calls reach the
  transport only through `invoke_with_budget`, and the profile is not part of the
  request an agent builds.

The engine's loopback socket never goes through a proxy for two independent
reasons: `engine_http` is not curl and does not read any profile (`engine_http.rs:1-8`),
and the launcher's loopback rule would bypass it even if it did.

## CA bundle

### What the setting is

An import, not a raw path. The human types a path in the Network page; the daemon
reads it once, validates it, writes a normalized private copy, and records its
digest. From then on curl is given the private copy, never the original.

Validation of the source (at import, in a blocking job):

- absolute path; canonicalized; a regular file (a symlink is followed once, by
  `canonicalize`, and the resolved file is what is checked and read);
- readable; at most 4 MiB;
- macOS: owned by root or the daemon's user, not group- or world-writable, and
  its directory not group- or world-writable (so an agent-writable file is
  refused; this mirrors the trust rule the curl path uses, `curl.rs:42-48`);
- Windows: the same checks cannot be made without ACL APIs (the curl path check
  has the same limit, `curl.rs:57-62`); no mode check, UNC paths allowed (IT
  distributes bundles from shares), and the private copy below is what removes
  the exposure;
- content: UTF-8 text with at least one `-----BEGIN CERTIFICATE-----` block whose
  base64 decodes to DER starting with `0x30` (a small decoder in `ca.rs`); any
  `PRIVATE KEY`, `ENCRYPTED PRIVATE KEY` or `RSA PRIVATE KEY` block refuses the
  whole file ("this file holds a private key; PAM needs only certificates"). No
  X.509 parser is added; expiry and chain problems surface in the Test.

The private copy contains only the normalized certificate blocks (comments, keys
and stray text are dropped), is written `0600` in `<base>/net/` (`0700`) through
the existing atomic private-file helper (`pam_model::private`), and is named by
its content digest. The settings document stores the digest, certificate count,
source path (display only) and import time. At every spawn the source of truth is
the private copy; its SHA-256 is recomputed and compared with the recorded digest,
and a mismatch refuses the request with `network_ca_tampered`. When the original
changes later, the Network page compares its digest with the import and says "the
source file changed since import; re-import" without changing behaviour. Moving
to a private copy is what closes the time-of-check/time-of-use gap and the Windows
ACL gap in one step.

### What it does to curl

`cacert` (and `proxy-cacert` for an `https://` proxy) points at the private copy.
It **replaces** the backend's default trust for PAM's requests rather than adding
to it; the setting's help says so, and says the bundle must therefore contain
every root the targets need (the corporate root and, if public hosts are reached
without inspection, the public roots). Because the Test covers the upstream hosts
whenever no mirror is configured, a bundle that drops GitHub's or Hugging Face's
root shows up the moment it is saved.

### Per platform

| | macOS arm64 | Windows amd64/arm64 |
| --- | --- | --- |
| Trusted curl | `/usr/bin/curl`, Apple's build; on the development host `curl 8.7.1 … libcurl/8.7.1 (SecureTransport) LibreSSL/3.3.6` | `%SystemRoot%\System32\curl.exe`, Microsoft's build, Schannel; version depends on the Windows build and updates |
| Default trust (no bundle) | the macOS keychain through SecureTransport: system roots plus roots an administrator or MDM profile has marked trusted | the Windows certificate store (machine and user), which is where Group Policy and Intune deploy enterprise and TLS-inspection roots |
| Common enterprise case | the inspection root is already trusted by an MDM profile: **leave the bundle empty** | the root is already in the store by GPO: **leave the bundle empty** |
| With a bundle | `cacert` is honoured by the SecureTransport/LibreSSL build; it is expected to replace keychain trust for that request (T8 records what this host does) | curl documents Schannel support for `cacert` since 7.60; the chain is expected to be required to end in a certificate from the file, instead of the store (T8 records it on the Windows 11 VM). Revocation checking stays on and fails for private CAs with no reachable CRL or OCSP responder. |
| What PAM does if the backend does not honour the file | the Test fails with the real cause; the field help then tells the human to install the root in the keychain instead | same, naming the Windows certificate store (Trusted Root Certification Authorities); PAM never writes to the OS certificate store itself |

The setting is therefore present and functional on both platforms, led on each by
"if your organisation's root is already trusted by this computer, leave this
empty", and the Test is the arbiter of whether a given curl/backend/bundle
combination works. The page shows `curl.backend` from the probe next to the
field. On Windows, a failure of `tls_revocation_unavailable` is reported
verbatim; PAM does not offer to switch revocation off (see
[Open questions](#open-questions)).

TLS-inspecting proxies: the proxy terminates the tunnel and presents a leaf signed
by the organisation's CA. With the CA trusted (OS store or bundle) curl accepts it
and everything works; PAM cannot tell, and does not try to. The Network page
states plainly that such a proxy can read the credentials PAM sends to connectors,
and the typed `network` confirmation exists for that reason.

PAM offers no "do not verify" option anywhere: not as a setting, not as an
argument, not in the Test, not for a proxy, not by environment (the environment is
cleared). The source-scan test makes adding one a failing change.

## Mirrors and offline delivery

All of it sits under one invariant: **the pinned digest, size, tag and build are
compile-time constants of the PAM build and no setting, argument or file can
change them.** Today that is true only by convention (`EngineRelease` and
`install_release` are public, `engine.rs:164-179`, `400`). The plan makes it
structural:

- `install_release` and an `EngineRelease` constructor taking a digest become
  `#[cfg(any(test, feature = "testing"))]`. The production entry point is
  `engine::install(base, cancel, net, source)` with `source` one of
  `Upstream`, `Mirror(MirrorBase)`, `LocalArchive(PathBuf)`; it builds
  `EngineRelease::pinned(target)` itself and only `url_base` may differ, via
  `MirrorBase`, a validated type.
- `admin.models.engine.install` and the new import ops reject unknown arguments
  (`sha256`, `tag`, `build`, `url`, `bytes` all fail `invalid_admin_args`), and a
  test asserts it.
- The daemon's catalog and the engine constants are the only digest source; a
  digest typed by a human (for a non-catalog import) is compared, never trusted
  as an expectation of what is *qualified* (see weights below).

### Mirror URL rules

Applied at save and at every spawn:

- scheme `https` only; host present; no userinfo, query or fragment; at most 512
  bytes; no `.` or `..` segments; normalized with a trailing slash;
- the host may be a name or an IP literal (internal mirrors are often private),
  but loopback, link-local (including the 169.254.169.254 metadata address),
  unspecified and multicast addresses and the name `localhost` are refused;
- an explicit port is allowed;
- if the managed layer supplies `mirror_allowed_hosts` (non-empty), the host must
  match an entry (same grammar as no-proxy hosts); otherwise any host. The field
  is policy-only for the reason given in [Shape](#shape).

**Engine mirror.** `engine_mirror` is the directory URL; PAM appends the pinned
asset name unchanged. For build b10938 on macOS arm64, a mirror of
`https://artifacts.corp.example/llama.cpp/b10938/` is asked for
`https://artifacts.corp.example/llama.cpp/b10938/llama-b10938-bin-macos-arm64.tar.gz`,
which replaces `https://github.com/ggml-org/llama.cpp/releases/download/b10938/`
(`ENGINE_RELEASE_BASE`, `engine.rs:36`). The bytes are checked against the same
size and SHA-256 and the unpacked server against the same build number. A mirror
that serves anything else is refused as `engine_digest_mismatch`, exactly like a
corrupted GitHub download. A redirect from the mirror may only go to https
(`proto-redir`).

**Models mirror.** `models_mirror` replaces the scheme-and-host prefix
`https://huggingface.co/` of a catalog preset's URL; the rest is appended. The
preset `https://huggingface.co/ggml-org/gpt-oss-20b-GGUF/resolve/main/gpt-oss-20b-MXFP4.gguf`
with `https://artifacts.corp.example/api/huggingfaceml/hf-remote/` becomes
`https://artifacts.corp.example/api/huggingfaceml/hf-remote/ggml-org/gpt-oss-20b-GGUF/resolve/main/gpt-oss-20b-MXFP4.gguf`.
A preset whose URL does not start with that prefix is fetched directly and the
download confirmation says so. Pasted-URL downloads are never rewritten: the human
typed the exact address. Size and SHA-256 come from the catalog and are checked
after the transfer, as now (`download.rs:901-936`). The checkpoint's
`canonical_source` is the effective URL (`download.rs:227`), so switching between
upstream and mirror with a partial on disk reports the existing
`checkpoint_conflict` and the discard-and-restart recovery rather than gluing
bytes from two servers; accepted cost, no checkpoint format change.

SSRF through a mirror URL: only the GUI can set it (admin op, tripwire). The fetch
is a GET whose body is written to a private part file and deleted on any digest
mismatch; the response is never returned to the caller (the failure detail names
digests, not content). Loopback and metadata addresses are refused at save; a
mirror redirect cannot leave https. The residual is a blind HTTPS request to an
internal host chosen by the human, with no readable result.

### Pre-provisioned archive (engine)

IT distributes the **pinned release archive** (the same file GitHub serves) to a
path on the machine or a share. A bare unpacked directory is deliberately not
accepted: PAM pins a digest per archive, not per file, so an unpacked tree has
nothing to verify against and accepting one would be a downgrade path. A
"directory" path is accepted only as a directory that contains the pinned asset by
its exact name.

`admin.models.engine.install { confirm: true, source: { kind: "local", path } }`:

1. Canonicalize `path`. If it is a directory, the archive is
   `dir/<pinned asset name>` (exact name, no listing, no globbing); if missing,
   refuse naming the expected file name. If it is a file, any name is fine.
2. Open it once. The opened handle must be a regular file whose size equals the
   pinned size; otherwise refuse with both sizes.
3. Stream from that handle into `<base>/engine/<asset name>` (the private `0700`
   engine directory, file `0600`) while hashing the same bytes with SHA-256. One
   pass: the bytes hashed are exactly the bytes copied, so there is no window
   between verification and use. The source is never modified, moved or deleted
   (copy, not move: it belongs to IT, may be on a read-only share, and is
   redistributed to other machines).
4. If the digest differs from the pinned one, delete the private copy and refuse
   `engine_digest_mismatch`, showing both digests and that this PAM build pins
   llama.cpp b10938.
5. From here the flow is the existing one: unpack the private copy with the OS
   `tar` (`engine.rs:603-642`; `tar.exe` reads the Windows zip), require
   `--version` to report the pinned build (`engine.rs:667-712`), move the release
   directory into place, write the manifest, delete the private archive.
6. The manifest gains `source`: `upstream`, `mirror` (with host) or `local_archive`
   (with the original path). Absent in older manifests, which display as "source
   not recorded". The card shows it.

Symlinks: a symlinked source is followed once by `canonicalize`; the handle opened
on the result is what is read. A source inside `<base>/engine` is refused (it
would be deleted by step 5). No network is touched and curl is not spawned; a test
passes a profile source that fails the test if asked for a profile and asserts it
is never called.

Permissions of the result: `<base>/engine` `0700` (existing,
`engine.rs:558-569`), the archive `0600` for its short life, the unpacked release
as the archive records modes inside that private directory. Windows inherits the
parent directory's ACL, as it does for the rest of `<base>`.

### Weights

- **Mirror**: as above.
- **Import from a file**: `admin.models.import { path, preset_id }` for a catalog
  model, or `{ path, vendor, expected_sha256? }` for any `.gguf`. For a preset, the
  source file's size is compared to the preset first, then copied and hashed in one
  pass into the model's sidecar part file (`.<file>.pam-model.part`, same lock and
  naming as a download so an import and a download of the same model cannot
  collide, `download.rs:310-321`, `1014-1034`), compared with the preset's SHA-256,
  and installed with the same `hard_link`-without-overwrite step
  (`download.rs:947-977`). It reuses `DownloadHandle`/`DownloadState` and the
  `model_job` row (kind `import`), so progress, cancel and failure rendering are
  the GUI's existing ones. Copy, never move; mode `0600` on macOS; the destination
  must not exist.
- A matching catalog digest records the model as verified in the private trust
  store exactly as a finished download does (`registry.rs:448-470`).
- A non-catalog `.gguf` is imported as an unverified, test-only model (the class a
  pasted-URL download gets today) unless the human supplies `expected_sha256`; if
  supplied and equal to the computed digest it is recorded as verified the way
  `admin.models.verify` records one. Admission for *jobs* still requires a
  qualification record for that digest (`pam_model` module docs, `qualification.rs`),
  so an imported file cannot become a tier default by being imported.

### The air-gapped first run, end to end

1. On a connected machine, IT reads the pinned asset name, size and SHA-256 for
   each target from the README table (kept in sync with `ENGINE_ASSETS` by a
   test) or the engine card's "Install from a file" panel, downloads the archive
   (and the catalog `.gguf` files wanted), and checks the digests.
2. IT distributes them to a path the machine can read: a local folder, a
   `ProgramData` directory, a share.
3. On the target, Models › Inference engine › "Install from a file…": type the
   folder or file path; PAM copies, hashes, compares with the value built into
   this version, unpacks, runs `--version`, and shows "Installed from a local file".
4. Models › Downloads › "Import from a file…" for each model: type the path, pick
   the catalog model; PAM copies, hashes against the catalog and marks it verified.
5. Nothing in steps 3 and 4 used the network or started curl.

## Disclosure copy

Dynamic values come from the daemon, never composed in the frontend:
`admin.models.engine.status` gains `plan` (`url`, `host`, `source`
`upstream|mirror`, `asset`, `bytes`, `sha256`, `install_dir`, `route`
`direct|proxy|bypass`, `proxy` `host:port` or null) and `admin.models.catalog`
presets gain `fetch` (`url`, `host`, `source`, `route`, `proxy`). The host shown is
the host of the URL that would actually be fetched, computed by the same function
the downloader uses, so the copy cannot disagree with the request. Angle brackets
below are those fields.

### Engine card

Not installed:

> **Inference engine** · llama.cpp
>
> Not installed.
>
> PAM can run a small language model on this computer to summarize build logs.
> That needs the llama.cpp engine, which PAM does not ship inside the app. Nothing
> is downloaded until you press Install.
>
> What Install does
> - Downloads `<asset>` (`<size>`)
> - From `<host>`, `<url>`
> - Route: `<direct connection | through the proxy proxy.corp.example:3128 | direct, matched your no-proxy list>`
> - Checks that its SHA-256 is `<sha256 first 12…last 6>`, the value built into this version of PAM. A file that differs is deleted and nothing is installed.
> - Installs llama.cpp build `<tag>` in `<install_dir>`
>
> After that, the engine is an ordinary program that runs as your user, as a child
> of the PAM daemon, only while a model is loaded. PAM talks to it through a
> private socket (on Windows, a local port on 127.0.0.1 protected by a per-load
> key). PAM starts it with a model file path, no network options and an almost
> empty environment, and never gives it your connector credentials.
>
> To remove it, press Remove engine, or stop the daemon and delete `<engine
> folder>`. Downloaded models are stored elsewhere and are not touched.
>
> Cannot reach `<host>` from this network? Set a proxy or an internal mirror in
> Settings › Network, or install from a file you already have.
>
> [Install engine] [Install from a file…]

When a mirror is set the "From" line reads "From `<mirror host>`, your configured
mirror, `<url>` (upstream is github.com)".

"Install from a file…" expands to a path field and:

> Give the path of the llama.cpp release archive, or a folder that contains it.
> This computer needs `<asset>` (`<size>`, SHA-256 `<sha256>`). PAM copies the
> file, checks it against that SHA-256, and leaves the original untouched. An
> archive from any other build is refused.

Installing:

> Installing…
>
> Downloading `<asset>` (`<size>`) from `<host>`, `<route>`. Then PAM checks the
> SHA-256, unpacks it into `<install_dir>` with the operating system's tar, and
> runs it once with `--version` to confirm it reports build `<build>`.
>
> This request times out after two minutes. If it does, press Install again; the
> transfer resumes where it stopped.

For a local file the first sentence is "Copying `<file>` and checking its SHA-256."

Installed:

> Installed · llama.cpp `<tag>` · `<target>`
> - Archive: `<asset>`, SHA-256 `<sha256 first 12…last 6>` (matched the value built into PAM)
> - Source: `<github.com | your mirror artifacts.corp.example | a local file: /opt/pam/<asset> (copied; the original was not changed)>`
> - Server: `<version line>`
> - Location: `<install_dir>`
> - Runs: as a local process of your user, only while a model is loaded; reached through a private socket; has no access to connector credentials.
> - Remove: press Remove engine, or stop the daemon and delete `<engine folder>`.
>
> [Reinstall engine] [Remove engine]

### Model download confirmation

Pressing Download on a catalog model opens this in place of starting the transfer
(the existing `ConfirmButton` pattern, `Models.tsx`):

> Download `<label>`?
> - Size: `<size>`
> - From: `<host>`, `<url>` — `<your configured mirror; the catalog source is huggingface.co | the catalog source>`
> - Route: `<direct | through the proxy … | direct, matched your no-proxy list>`
> - Checks: size and SHA-256 (`<sha256 first 12…>`) must equal the values built into this version of PAM; a file that differs is deleted.
> - Saved to: `<path>`
> - Licence: `<license_id>`, `<license_url>`
>
> This is model data, not a program. It is read by the local engine and nothing
> else. If the transfer is interrupted, press Download again to resume.
>
> [Download] [Cancel]

A pasted URL, in the same place:

> Unverified download. PAM has no expected SHA-256 for this address; it saves
> whatever the server sends from `<host>`. The file is kept as a test-only model
> and is not used for jobs until it is verified. Only https addresses are accepted.
> Mirrors do not apply to pasted addresses.

Import from a file:

> Import `<label>` from a file? PAM copies `<path>`, checks its size and SHA-256
> against the catalog (`<sha256 first 12…>`), and saves it to `<path>`. The original
> is not changed. No network is used.

### README section

Added after "Desktop workspace" in `README.md`, with the asset table kept in sync
with `ENGINE_ASSETS` by a test (`include_str!("../../../README.md")` in
`pam_model`'s engine test file; the supported rows only):

> ## Local models and the inference engine
>
> PAM can summarize logs with a language model that runs on your own computer.
> This is optional and off until you turn it on in Models. It needs two things PAM
> does not ship in the app: the llama.cpp inference engine and the model weights.
> Neither is downloaded until you press a button.
>
> **What is fetched, and from where**
>
> | What | From | Checked against |
> | --- | --- | --- |
> | The llama.cpp engine, build b10938, one archive for your platform | `github.com/ggml-org/llama.cpp/releases/download/b10938/` | the SHA-256 and size below, built into PAM |
> | A model you choose in Models › Downloads | `huggingface.co` (the exact address is shown before you confirm) | the size and SHA-256 listed in PAM's catalog |
>
> | Platform | Archive | Size | SHA-256 |
> | --- | --- | --- | --- |
> | macOS arm64 | `llama-b10938-bin-macos-arm64.tar.gz` | 11.1 MB | `69f236c8aa148eb32bfd76774a0a449e2f9b754c595e8f6d90b12cf7fecb8399` |
> | Windows x64 | `llama-b10938-bin-win-cpu-x64.zip` | 18.4 MB | `ba39502946f4c0e966e5e93393618953dc4c005a252fbaf8c9786c33a9f8b60d` |
> | Windows arm64 | `llama-b10938-bin-win-cpu-arm64.zip` | 12.0 MB | `85bc7b14a62092e17beca76295a0e1cbe88510f02623c3b18707ca470c06faeb` |
>
> A file whose size or SHA-256 differs is deleted and not installed, wherever it
> came from. After unpacking, PAM runs the server once with `--version` and
> requires it to report build 10938.
>
> **What runs on your machine.** The engine is an ordinary program started by the
> PAM daemon under your user account, only while a model is loaded. It is installed
> under `~/.pam/engine` (`%USERPROFILE%\.pam\engine` on Windows). PAM talks to it
> over a private socket (a loopback port protected by a per-load key on Windows),
> starts it with a model path and an almost empty environment, and does not give
> it your connector credentials. Models are stored under the models directory you
> choose in Settings › Models.
>
> **Corporate networks.** In Settings › Network you can set an HTTPS proxy (with a
> user name and password kept in your OS keychain), a no-proxy list and a CA
> bundle, and internal mirror addresses for the engine and for models. These apply
> to connector requests and to downloads. PAM ignores `HTTPS_PROXY`, `NO_PROXY`,
> `SSL_CERT_FILE` and similar variables in its environment: only what you set in
> the GUI is used. If your organisation's TLS-inspection root is already trusted by
> your operating system, leave the CA bundle empty. A proxy that inspects TLS can
> read the credentials PAM sends to connectors. "Test network settings" shows,
> for each configured service and download host, whether it is reached and, if not,
> why.
>
> **No network at all.** Download the archive for your platform from the address
> above (and any model files) on another machine, check the SHA-256, copy them to
> this one, and use Models › Inference engine › Install from a file and Models ›
> Downloads › Import from a file. PAM copies the files, checks them against the
> same SHA-256 values, and never changes the originals.
>
> **Removing it.** Models › Inference engine › Remove engine, or stop the daemon
> and delete the `engine` folder named above. Delete a model from Models; model
> files are not in the engine folder.

The existing sentence in `docs/command-containment.md:15` ("Model downloads run
curl with a cleared environment that keeps only the proxy and certificate
variables … connector reads cannot be configured for an enterprise proxy") is
rewritten in the docs task: both launchers clear the environment; only GUI
settings apply.

### Network settings page copy

Header: "Network. How PAM reaches connector services and download hosts. Nothing is
read from environment variables." Proxy panel help: "Use an http:// or https://
proxy address with its port. SOCKS and automatic configuration (PAC) scripts are
not supported. A user name and password are stored in this computer's keychain.
With an http:// proxy and Basic sign-in the password is sent to the proxy without
encryption on your network." CA panel help: "If your organisation inspects TLS and
this computer's keychain or certificate store already trusts its root, leave this
empty. Otherwise import a PEM file of the certificates PAM should trust. It
replaces the system's trust for PAM's requests, so include every root those
services need. A proxy that inspects TLS can read the credentials PAM sends to
connectors."

## Connection test

`admin.network.test {}` (optionally `{ target: "<connector id>" | "engine" |
"models" }`) checks that proxy and CA settings work against the places PAM
actually goes. No free-form URL is accepted, so the action cannot be used to
probe arbitrary hosts: targets are derived from configured state only.

Targets: the base URL of every enabled HTTP connector
(`connectors.list()`); the engine host (the effective URL of the pinned asset
for this platform) when the engine is not installed or a mirror is set; the models
host (the effective prefix of the catalog) when a models mirror is set or any model
is not installed. At most 12 targets, probed four at a time.

Each probe uses the launcher with the current effective profile and sends **no
credentials and no custom headers**: `HEAD` of the URL (the connector root; the
engine asset URL; the models host root), `--max-time 8`, `--connect-timeout 5`, no
redirect follow. Any HTTP status, including 401, 403 and 404, means the network
path works (that is what is being tested, not authorization); a mirror asset
response is additionally compared with the pinned size when it carries
`Content-Length`. The connector's own credential test remains `admin.connectors.test`.

The probe runs in diagnostic mode: the launcher adds `verbose` and, for a TLS
failure, keeps **only** the lines of the form `* … issuer: …` and `* … subject: …`
(curl's OpenSSL/LibreSSL backends print them before the verification verdict) and
`Proxy-Authenticate` values from the CONNECT block; everything else in verbose
output, which includes the `Proxy-Authorization` header, is discarded unread and
never stored, logged or returned. Where the backend does not print an issuer
(expected on Schannel and possibly SecureTransport), the sentence says "the
issuer could not be read from this curl (`<backend>`); check this computer's
certificate trust." T1 records what each platform prints.

The reply, per target:

```json
{ "target": "jenkins", "host": "jenkins.corp.example", "route": "proxy",
  "stage": "tls", "ok": false, "http_status": null,
  "cause": "tls_untrusted_issuer",
  "detail": "The server's certificate was issued by CN=Corp Inspection CA, which is not trusted.",
  "recovery": "If your organisation inspects TLS, import its root CA in Settings › Network, or ask IT to deploy it to this computer's trust store." }
```

`stage` is the furthest point reached: `proxy` (connected to the proxy), `tunnel`
(CONNECT answered 200), `tls` (handshake verified), `http` (a status came back).
`route` is the preview (`direct`, `bypass`, `proxy`) so a bypassed host that fails
reads "direct, matched your no-proxy list". The causes are the table in
[Failure classification](#failure-classification); proxy-unreachable, proxy
auth required (with the offered schemes), TLS untrusted issuer (naming it where
readable) and DNS are the four the owner asked for explicitly.

Op properties: `Outcome::Verified` (no state changes); audit `{ "op", "targets",
"failed": ["jenkins:tls_untrusted_issuer"] }`; daemon deadline 20 s; the bridge
adds `NETWORK_TEST_DEADLINE_MS = 25_000` beside `CONNECTOR_TEST_DEADLINE_MS`
(`bridge.rs:69`, `169-175`). The Network page shows the results as a table and
offers the test after every save.

## Policy layer

A later plan adds a read-only managed policy file. The settings are shaped now so
that layer is a pure overlay and needs no migration:

- Resolution is a function over three values per field:
  `effective = managed.field.or(user.field).unwrap_or(default)`, producing
  `(value, source)` where `source` is `policy`, `user` or `default`.
  `managed` is an `Option<ManagedNetwork>` whose fields are `Option<_>`: *present
  means pinned and locked*, absent means the user's value applies. It also carries
  the policy-only `mirror_allowed_hosts` and may carry a pinned proxy credential
  reference (not designed here).
- `NetworkService` holds an `Arc<dyn ManagedNetworkLayer>` with one method
  returning the current `Option<ManagedNetwork>`; the default implementation
  returns `None`. The later plan provides a real one (and decides how the file is
  read, signed and watched). This plan ships the trait, the resolution function,
  and tests that exercise it with a stub.
- `admin.network.get.effective` already reports `source` and `locked` per field;
  the GUI renders locked fields disabled with "Set by your organisation".
- `admin.network.set` refuses any patch touching a locked field with
  `setting_locked` (recovery: "Managed by your organisation's policy; ask your
  administrator."), whole patch, nothing applied. The user's stored values are
  never overwritten by policy, so removing the policy restores them.
- The launcher and every consumer see only the resolved `NetworkProfile`, so
  policy enforcement cannot be bypassed by a consumer that reads the document
  directly: no consumer does. The mirror rules and the CA digest check run on the
  resolved value, so a pinned mirror outside `mirror_allowed_hosts` is refused the
  same way a user's would be.
- A managed CA bundle is a path to a file the policy controls; it goes through the
  same import (private copy, digest) at resolution time, so the same
  `network_ca_tampered` guarantees hold.

## Threats

| Threat | Analysis |
| --- | --- |
| A malicious proxy or mirror setting | Settings are written only by `admin.network.set`, an admin op: no CLI, no public-socket route, tripwire on non-GUI callers, no `classify` entry, never grantable. Setting a proxy or CA additionally needs the typed `network` phrase. A compromised webview can still supply the phrase (accepted, review item bridge 9). |
| What an agent can and cannot influence | Cannot read or write any network setting or the proxy credential (admin-only, keychain, not in any reply it can obtain). Cannot choose a connector's URL (scope policy compares the stored base URL, `scope_policy.rs:243`). Cannot direct a request around the proxy (the launcher decides the route) or onto it differently. Cannot trigger an engine or model download (GUI-only). Can cause connector calls to happen through a flow step it is granted, and those calls use whatever profile the human set; it can observe their results as it can today. Flow command steps and the landing git broker do not use the profile and remain network-denied or proxy-disabled. |
| Daemon environment poisoning | The daemon may be started lazily by an agent. No consumer reads proxy or CA environment variables; the launcher clears the environment; the engine is started with a cleared environment. `ignored_env` shows names only, with no import. This closes the one channel (`download::curl_env`) where an inherited variable could reroute traffic. |
| Credential exposure paths | Proxy password: keychain only; stdin config only; never argv, environment, logs, audit, replies, or the settings document. Verbose output in the Test is filtered to issuer, subject and `Proxy-Authenticate`, so `Proxy-Authorization` is never retained. Connector tokens: unchanged (stdin config), but now cross a proxy; a TLS-inspecting proxy can read them (stated in the UI and README). The CA private copy holds certificates only. The secret type is zeroed on drop as today. |
| Malicious or poisoned CA bundle | The bundle controls what PAM trusts, so importing a hostile one enables interception. Mitigations: GUI-only, typed confirmation, key material refused, normalized to certificates only, digest recorded and shown, private `0600` copy checked on every use, a changed source reported. The human decides what to trust; PAM does not widen it. |
| SSRF via a mirror URL | See [Mirror URL rules](#mirror-url-rules): https only, no loopback or link-local, body never returned and deleted on mismatch, redirects https only, set only by the GUI. The Test accepts no free-form URL. |
| Downgrade of the pinned digest | Impossible through any setting or argument: digest, size, tag and build are constants; `install_release` is test-only; the new ops reject unknown arguments; a mirror or local file must match the same SHA-256 and the unpacked server the same build. Tests: unknown-argument refusal; wrong-digest archive via mirror and via local path; correct digest with a wrong build number; a manifest planted beside an import is ignored. |
| TOCTOU on imported files | One handle: size checked on it, bytes hashed while copied, private copy used afterwards; the CA bundle likewise copied before use. |
| Proxy sees too much | The proxy learns target host and port of each CONNECT; with `no_proxy` the human can keep internal hosts off it; loopback is always off it. |
| Fail-open on bad settings | Corrupt or invalid `net.settings`, an unreadable credential when `auth != none`, or a tampered CA copy refuses the request with a named cause; it never falls back to a direct connection. |
| Plain-http downloads | Refused in production for pasted URLs too (a behaviour change from `download.rs:825-828`). |

## GUI changes

- Settings gets a **Network** tab (`id: "network"`, eyebrow "Daemon setting"),
  between Connectors and Daemon (`Settings.tsx:921-970`), with panels: Proxy (URL,
  authentication, user name, write-only password with "stored"/Clear, no-proxy list
  one per line), Certificate authority (path, Import, shows certificate count,
  digest, source and "source changed"), Mirrors (engine, models), Test network
  settings (button and result table), and an "ignored environment variables"
  notice. Locked fields show "Set by your organisation". Saving proxy or CA
  changes uses the existing `TypedConfirm` with the phrase `network`.
- The Models engine card gains the plan block, "Install from a file…" and "Remove
  engine"; the Downloads list gains the confirmation panel and "Import from a
  file…". Path fields are typed text, the existing pattern for the models
  directory (`SettingsModels.tsx` `StoragePanel`); the app has no file-dialog
  plugin and none is added.
- `frontend/src/lib/ipc.ts` gets `network*` calls and the `EngineStatus` additions.
  The strings in [Disclosure copy](#disclosure-copy) live in the card components;
  numbers and hosts come from the daemon.

## Test strategy

Fixtures (new, in `pam_net` behind the `testing` feature, consumed by the other
crates' tests):

- **Fake HTTP proxy** (tokio `TcpListener`): `CONNECT` to any requested name is
  tunnelled to a configured upstream loopback address regardless of the name (so
  tests can use `origin.pam-test.invalid` and prove the proxy, not DNS, was used);
  also absolute-form `GET` forwarding for the plain-http fixtures. Modes: `Allow`,
  `RequireAuth { user, password, schemes }` (407 with `Proxy-Authenticate`, then
  accepts the correct `Proxy-Authorization`), `Deny(403)`, `Bad(502)`, and
  `Connect200Banner` (replies `HTTP/1.1 200 Connection established` so the
  CONNECT-block bug is exercised). It records every request line and every
  `Proxy-Authorization` seen.
- **TLS origin with a private CA**: committed static PEM fixtures in
  `crates/pam_net/tests/fixtures/` (a test CA, a leaf for
  `origin.pam-test.invalid` signed by it, a second unrelated CA, a leaf with the
  wrong name), long-lived and clearly labelled test-only, generated once with
  `openssl` and checked in with a README giving the commands. The origin is
  `openssl s_server -www` started on a free loopback port, located through
  `PAM_TEST_OPENSSL` or `PATH` (macOS `/usr/bin/openssl`; on the Windows VM the
  OpenSSL that ships with Git for Windows). No TLS crate is added: none exists in
  the workspace and the available ones compile C, which the dependency rules
  forbid. TLS tests are skipped with a printed line when `openssl` is absent,
  unless `PAM_REQUIRE_TLS_FIXTURE=1`, in which case absence is a failure;
  `tools/check.sh` exports it and the Windows run script sets it, so the gate cannot
  silently skip them.
- **Plain-http origin** and **range-serving origin**: the existing
  `curl_origin.rs` and `pam_model::testing`, unchanged, driven through the proxy
  fixture with the `testing`-only http allowance.

What each layer proves:

| Layer | Tests |
| --- | --- |
| `pam_net` unit | Every validation rule in the settings table (accepted and refused forms, including SOCKS, scheme-less, userinfo, missing port); no-proxy grammar and the route preview; CA PEM rules (key refused, empty, oversize, non-certificate, normalization drops stray text, digest stable); mirror rules and the catalog rewrite example above; argv constant for every builder configuration; config document holds proxy credential and no argv/env does; environment map empty on macOS and the Windows allowlist only on Windows; source scan finds no `insecure`/`no-revoke` spelling; classification table over recorded curl stderr and `write-out` samples from macOS 8.7.1 and the Windows VM. |
| `pam_net` real curl | Through the fake proxy: a proxied request is seen as CONNECT; a bypassed or loopback target never reaches the proxy and a direct `.invalid` name fails DNS (the preview-parity corpus); 407 then success with credentials (proxy saw `Proxy-Authorization`, argv did not carry it); proxy unreachable (closed port); 403 and 502; the `Connect200Banner` mode does not become the response. With the TLS origin: success with the right bundle; `tls_untrusted_issuer` without it (and with the other CA); name mismatch; the issuer named where the backend prints it. A parent-process `HTTPS_PROXY` set in the test environment is not honoured. |
| `pam_connectors` | `curl_origin.rs` still green over the new launcher; a new `curl_proxy.rs`: a connector GET through the proxy returns the origin's body; scope and redirect behaviour unchanged (existing tests); `TransportError::Net` maps to `ConnectorError::Network` with the sentence. |
| `pam_model` | Download suite green over the launcher; resume and ETag restart through the proxy; `https`-only refusal of `http://` including a redirect to http; failure causes; engine install with a mirror base (the fake archive through `install_release`, test-only); local archive: wrong size, wrong digest, directory without the asset, symlinked source, source untouched, private copy deleted on mismatch, profile source never consulted; weights import: catalog digest verified and recorded, mismatch deletes the part, existing destination refused, concurrent download of the same model refused by the lock; README table equals `ENGINE_ASSETS`. |
| `pam_daemon` | `admin_network_test.rs`: get/set/clear round trips; patch atomicity; unknown keys refused; locked field refuses the whole patch (stub managed layer); CAS conflict; credential never in any reply, audit row, request row or log capture; audit rows contain the documented fields and nothing secret; CA import end to end; fail closed on a corrupt document; connector test and a flow connector step through the proxy; model download through the proxy; engine status `plan` host matches the URL requested; unknown install arguments refused; engine remove. |
| Bridge | `required_confirmation` returns `network` exactly for proxy/credential/CA sets, not for clears, no-proxy or mirrors; deadlines; whitelist contains the new ops. |
| Frontend | vitest for the Network tab (validation display, locked state, write-only password, typed confirmation, test results), the engine card in its three states with each route and source, the download confirmation (catalog, mirror, pasted URL) and the import and install-from-file panels; the design-contract and arbitrary-value lint rules apply as everywhere. |

Rust unit tests follow the project rule: no `#[cfg(test)] mod tests` blocks in
source files; each module has a sibling `module_test.rs` declared from its parent
with `#[cfg(test)] mod module_test;`. Integration tests live under each crate's
`tests/`. Before launching the full gate, each touched crate runs
`cargo clippy -p <crate> --all-targets -- -D warnings` (memento
`clippy-before-full-gate`); each worktree sets its own `CARGO_TARGET_DIR`.

## Implementation plan

Branch `feat/enterprise-network` from `main` after plan 49
(`feat/framed-public-transport`) is squash-merged, because Phase C edits
`admin.rs`, `daemon.rs` and `lib.rs`, which plan 49 is changing now. One PR,
squash-merged with a `feat:` title, PR checks green first, commits referencing
their ptrack task as `#<id>`; no release is cut from this work. No workflow files
are added or changed. Tasks within a phase own disjoint files; a file not listed
for a task is not touched by it.

### Phase A (one agent)

**T1. `pam_net` crate.**
- New: `crates/pam_net/Cargo.toml`, `src/lib.rs`, `trusted.rs`, `profile.rs`,
  `ca.rs`, `launch.rs`, `failure.rs`, `testing.rs`, sibling `*_test.rs` for each,
  `tests/proxy_curl.rs`, `tests/tls_origin.rs`, `tests/fixtures/**`.
- Edited: root `Cargo.toml` (workspace member and `pam_net` workspace dependency).
- Work: everything in [One hardened curl launcher](#one-hardened-curl-launcher),
  the validation and route preview, CA import, mirror rules, `NetFailure`, the
  fixtures. Also records, in `failure.rs` comments and the test fixtures, what
  macOS curl 8.7.1 prints for each failure (to be repeated on Windows in T8).
- Acceptance: all `pam_net` tests pass on macOS; real-curl proxy and TLS tests run
  (not skipped) with `PAM_REQUIRE_TLS_FIXTURE=1`; `cargo clippy -p pam_net
  --all-targets -- -D warnings`; `cargo doc -p pam_net --no-deps` with `-D warnings`.

### Phase B (two agents in parallel)

**T2. Adopt the launcher in connectors and downloads.**
- Files: `crates/pam_connectors/src/curl.rs`, `curl_test.rs`, `transport.rs`,
  `transport_test.rs`, `lib.rs`, `Cargo.toml`, `tests/curl_origin.rs`, new
  `tests/curl_proxy.rs`; `crates/pam_model/src/download.rs`, `download_test.rs`,
  `lib.rs`, `testing.rs`, `Cargo.toml`.
- Work: `CurlTransport::trusted(source)`; remove the duplicated trusted-path code
  and `download::curl_env`; builder-based spawns; https-only; `TransportError::Net`;
  `NetFailure` into `DownloadState::Failed` and `failure_recovery`;
  `download::start(request, net)`; constant argv.
- Acceptance: the existing connector and download suites pass unchanged except
  where the https-only rule or constructor signature forces an edit (listed in the
  commit); the new proxy tests pass; clippy on both crates. Daemon does not
  compile until T3 (it is not built in this phase; the task is verified with
  `-p pam_connectors -p pam_model`).

**T5. Frontend: Network tab.**
- Files: `frontend/src/screens/SettingsNetwork.tsx`, `SettingsNetwork.test.tsx`,
  `Settings.tsx` (tab entry and pane only), `Settings.test.tsx` (tab list),
  `frontend/src/lib/ipc.ts` and `ipc.test.ts` (network ops and types only).
- Work: the panels, copy and behaviour in [GUI changes](#gui-changes) and
  [Network settings page copy](#network-settings-page-copy), written against the
  op contracts in this document with a mocked bridge; tokens from the Tailwind
  `@theme`, no arbitrary values.
- Acceptance: `npm --prefix frontend run lint`, `build`, `test` green.

### Phase C (two agents in parallel)

**T3. Daemon settings, ops and wiring.**
- New: `crates/pam_daemon/src/network_service.rs` (+ `_test.rs`: the
  `NetworkSource` implementation, resolution with the managed-layer trait and a
  stub), `admin_network.rs` (+ `_test.rs`).
- Edited: `admin.rs` (one field, one dispatch line, module doc line),
  `lib.rs` (modules), `daemon.rs` (`open_http_transport` takes the source; build
  the service), `connector_service.rs` (nothing but the constructor wiring if
  needed), `model_service.rs` (hold the source, resolve and pass the profile in
  `start_download`; no other change), `crates/pam_gui/src/bridge.rs`
  (`NETWORK_ADMIN_OPS`, `CONFIRM_NETWORK`, `required_confirmation`, test deadline)
  and its tests, `crates/pam_testkit/src/lib.rs` only if its daemon helper needs the
  new config field.
- Acceptance: the daemon rows of the test table; the whole workspace compiles;
  `cargo clippy` on `pam_daemon` and `pam_gui`; `cargo test -p pam_daemon -p pam_gui`.

**T6. Frontend: engine card, download confirmation, imports.**
- Files: `frontend/src/screens/EngineCard.tsx`, `EngineCard.test.tsx`, `Models.tsx`,
  `Models.test.tsx`, `frontend/src/lib/ipc.ts` and `ipc.test.ts` (engine, import and
  catalog `fetch` types and calls only; rebased on T5's edits to the same file).
- Work: the three engine states and the confirmations in
  [Disclosure copy](#disclosure-copy), "Install from a file…", "Remove engine",
  "Import from a file…", against the contract in Phase D with a mocked bridge.
- Acceptance: frontend lint, build, test green.

### Phase D (one agent)

**T4. Engine and weights delivery backend.**
- Files: `crates/pam_model/src/engine.rs`, `engine_test.rs`, `download.rs` and
  `download_test.rs` (`start_import` only), `lib.rs`, `registry.rs` (only if
  `record_download` needs a variant for imports); `crates/pam_daemon/src/admin_engine.rs`,
  `admin_engine_test.rs`, `admin_models.rs`, `admin_models_test.rs`,
  `model_service.rs` (import job wiring and `plan` helpers), `crates/pam_gui/src/bridge.rs`
  (whitelist entries for the new ops only).
- Work: `engine::install(base, cancel, net, source)` with `Upstream`, `Mirror`,
  `LocalArchive`; `install_release` and digest-taking constructor made test-only;
  manifest `source`; `admin.models.engine.install { source }`,
  `admin.models.engine.remove { confirm }`, `admin.models.import`; `plan` on engine
  status and `fetch` on catalog presets; strict argument checking on all of them;
  the README-table test.
- Acceptance: the `pam_model` and `pam_daemon` rows of the test table;
  `cargo clippy` on both crates; the fake-engine daemon tests still install through
  the test-only path.

### Phase E

**T7. Documentation (one agent).** `README.md` (the section above),
`docs/command-containment.md` (HTTP transport paragraph and the curator paragraph
rewritten: one launcher, no inherited proxy or CA variables, https-only),
`docs/enterprise-connector-contracts.md` (one sentence: connector HTTP honours the
GUI network settings), `docs/specs/2026-09-13-llama-cpp-engine.md` (acquisition
section: mirror, local archive, remove), `docs/reviews/design-review-2026-10-02.md`
(mark model 9 fixed, with a pointer here), `CHANGELOG.md` (Added: network settings,
mirrors, offline import, remove engine; Changed: downloads no longer read proxy or
CA environment variables and refuse plain http). No code.
Acceptance: the README table test from T4 passes; links resolve.

**T8. Verification (one agent, no new code).**
1. `bash tools/check.sh` on macOS, with `PAM_REQUIRE_TLS_FIXTURE=1` exported by the
   script (a one-line edit to `tools/check.sh`, the only change this task makes).
2. Windows run in the Parallels Windows 11 VM, following the recorded procedure
   (bundle over `\\Macrano-ci\pam-xfer`, `prlctl exec` as SYSTEM, no `set &&` target
   override; memory `windows-work-via-parallels`): `cargo test -p pam_net
   -p pam_connectors -p pam_model -p pam_daemon` with `PAM_REQUIRE_TLS_FIXTURE=1`
   and `PAM_TEST_OPENSSL` pointing at Git for Windows' `openssl.exe`.
3. Record in an "Evidence" section appended to this spec, for each of macOS and
   Windows: `curl --version` banner and TLS backend; whether `write-out` printed on
   failure; what `cacert` does (replaces the platform trust or not); the exact
   stderr for untrusted issuer, name mismatch, proxy 407, proxy refused and, on
   Windows, a private-CA revocation failure; whether an issuer is printed; the
   result of `Test network settings` against the fixtures. If a recorded fact
   contradicts a statement in this document, the document is corrected before
   merge (notably the Windows `cacert` row).
4. Manual real-environment pass, owner's call: an actual corporate proxy if one is
   available; otherwise the fixtures stand.

## Decisions

Decided here, not open:

- Single document `net.settings`, read per spawn, fail closed.
- Proxy credential in the keychain under connector id `network.proxy`; username in
  the document; no userinfo in URLs.
- New leaf crate `pam_net`; both launchers drop their own trusted-curl code.
- argv is the constant `-q --config -`; everything else on stdin.
- https-only for production downloads and mirrors, plain http test-only.
- No SOCKS, no PAC, no `--insecure` of any kind, no inherited environment, no
  import of environment values.
- curl evaluates `noproxy`; the Rust preview is display-only and parity-tested.
  Loopback targets always bypass the proxy.
- CA bundle is an import with a private, digest-checked copy; it replaces system
  trust; key material is refused.
- Typed confirmation `network` for proxy, credential and CA changes.
- Local engine archive must be the pinned archive (file, or a folder containing it
  by exact name); an unpacked tree is refused. Copy, never move.
- Weights import copies and hashes in one pass through the download job
  machinery.
- Engine install stays one synchronous op with resume; not turned into a job here.
- Mirror allowlist is policy-only.
- Engine remove op added, so "how to remove it" has a button as well as a folder.
- Plain-http pasted model URLs are no longer accepted.
- Linux and Intel macOS are not supported and are not documented.

## Open questions

Only two need the owner.

1. **Windows certificate revocation.** On Windows, Schannel checks revocation and
   fails for private CAs and TLS-inspection leaves whose CRL or OCSP responder is
   unreachable (`CRYPT_E_NO_REVOCATION_CHECK`, curl's `--ssl-no-revoke` exists for
   exactly this). That is a common enterprise failure. This design offers no
   switch, per "never offer disable verification", and reports
   `tls_revocation_unavailable` with a recovery line pointing at the CRL
   distribution point. Recommendation: keep it that way for v1 and revisit only if
   T8 shows the inspection-proxy case is unusable on the Windows VM; then the
   narrower `ssl-revoke-best-effort` (tolerate an unreachable responder, still
   reject a revoked certificate) is the option to consider, behind the typed
   confirmation. Needs a decision only if T8 hits it.
2. **Proxy single sign-on.** Many Windows enterprises authenticate the proxy with
   Kerberos or NTLM as the signed-in user, with no stored password (curl
   `proxy-negotiate` with an empty user). v1 supports Basic and `anyauth` with an
   explicit stored credential (NTLM works with `DOMAIN\user`), which covers proxies
   that accept a service account but not ones that insist on the logged-in user's
   ticket. Adding a `negotiate` mode is small in the launcher but cannot be
   fixture-tested here (it needs a domain), so it would ship unproven. Recommendation:
   defer, and ask the first enterprise pilot which proxy it uses before building
   it.
