# Flows Engine + Connector Host Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an agent run `pam flow run <id>` against a global YAML flow library (seven embedded starters, human-edited in the GUI) whose steps are allowlisted local commands and read-only connector calls (GitHub Actions, Jenkins, SonarQube, Jira DC, Confluence Cloud, SharePoint, AWS CLI), gated per step by the existing policy matrix and approvals, with every output compressed into evidence and a compact verdict back.

**Architecture:** Two pure crates (`pam_flow`: schema/validation/normalized YAML/digest/builtins/library; `pam_connectors`: seven connectors over an `HttpTransport` trait with a system-`curl` implementation) plus daemon services (`secrets` over the keyring stack, `ConnectorService`, `FlowService`) wired into the existing pipeline as capabilities `flow.run|list|show` and GUI-only `admin.flows.*` / `admin.connectors.*`. Store migration 5 adds the `connector` table. CLI gains `pam flow`; the GUI gains the Flows screen and two Settings panels. Spec: `docs/specs/2026-09-02-flows-connectors-design.md` — every requirement traces to it.

**Tech Stack:** Rust 1.97 (edition 2024), tokio, turso store, `serde_yaml_ng`, `url`, `keyring-core` 1.0 + per-OS stores, system `curl`, Tauri 2, React 19 + TanStack Query/Router, Tailwind v4 tokens, vitest.

## Global Constraints

- **C-free dependency tree**: after every dependency change run `cargo tree -e normal,build | grep -E '^(cc|cmake|onig_sys|esaxx-rs|ring|aws-lc-sys|openssl-sys|dbus|libdbus-sys) '` — must print nothing. No `reqwest`, no `rustls`, no `ring`. HTTPS is system `curl` only.
- **Sibling tests**: unit tests in `module_test.rs`, declared `#[cfg(test)] mod module_test;` from the parent. Never `#[cfg(test)] mod tests` inline. Integration tests in `crates/<crate>/tests/*.rs`.
- **turso concurrency rule**: every `Store` method takes `conn_lock` first; a transaction holds it across `BEGIN..COMMIT`.
- **Test harness rule**: daemon tests seed the relaxed profile (`pam_testkit::seed_relaxed`) explicitly; never assert unix-only lock/signal details; kill children in a platform-neutral way.
- **Refusal legibility**: every failure = `{ cause, detail, recovery }`; recovery names the GUI screen ("open Pam → Settings → Connectors → …") or the concrete fix. Never a security command an agent could run.
- **Secrets**: never in SQLite, logs, audit detail, argv, or evidence. curl gets headers through `--config -` on stdin. Env passed to commands is scrubbed of names matching `(?i)token|secret|password|passwd|credential|api_key|apikey|private_key`.
- **Frontend**: Tailwind v4 semantic tokens only (ESLint bans arbitrary values), CVA variants, existing `Panel`/`Badge`/`Button`/`ConfirmButton`/`FailureNote`/`Section` furniture; `font-voice` serif for Pam sentences, `font-data` mono for ids/paths/YAML, `font-display` for big numbers.
- **Gates**: `tools/check.sh` (fmt, clippy `-D warnings` pedantic, tests, eslint, tsc+vite build, vitest) green on the settled tree before every PR. Foreground gates only; never background a check. No `#[allow]` sprinkles — fix the code.
- **Commits**: conventional prefix, `#<task-id>` in the subject, **no AI attribution trailers of any kind**. Branch per task, PR to `main`, squash merge, branch deleted. PR title carries `#<task-id>`.
- **Bounds copied from the spec**: flow id/step id `[a-z0-9-]{1,64}`; ≤ 64 steps, ≤ 16 inputs, file ≤ 256 KiB, `name` ≤ 120 bytes, `description` ≤ 2 KiB; args ≤ 64, each ≤ 4 KiB, total ≤ 32 KiB; step timeout default 300 s, max 3600 s; retry attempts 1..5, backoff ≤ 60 s doubling, cap 60 s; library ≤ 256 entries; command output cap `pam_compact::MAX_SOURCE_BYTES` (64 MiB); JSON responses ≤ 1 MiB; logs ≤ 64 MiB; AWS stdout ≤ 256 KiB, stderr ≤ 4 KiB, 30 s; `pam flow run` default deadline 1 800 000 ms; connector test deadline 10 s (bridge 15 s); shells refused: `sh bash zsh fish dash pwsh powershell cmd cmd.exe env xargs sudo doas`; default allowlist `git cargo rustup npm npx pnpm yarn node make go python3 pytest uv mvn gradle dotnet gh`; default extra PATH macOS `~/.cargo/bin /opt/homebrew/bin /usr/local/bin`, Linux `~/.cargo/bin ~/.local/bin /usr/local/bin`, Windows `%USERPROFILE%\.cargo\bin`; step gate capability name `flow.step:<flow>/<step>`; evidence kinds `connector.result`, `flow.result` (plus the log kinds `LogService` writes).

---

## Wave map (parallelism)

| Wave | Tasks | Disjoint file sets |
| --- | --- | --- |
| 0 | prep (coordinator): plan doc, crate skeletons, workspace deps | root `Cargo.toml`, `crates/pam_flow/{Cargo.toml,src/lib.rs}`, `crates/pam_connectors/{Cargo.toml,src/lib.rs}` |
| 1 | #45 `pam_flow` · #46 `pam_connectors` · #47 store · #48 secrets | `crates/pam_flow/**` · `crates/pam_connectors/**` · `crates/pam_store/**` · `crates/pam_daemon/Cargo.toml`, `crates/pam_daemon/src/secrets*.rs`, `crates/pam_daemon/src/lib.rs` (one `pub mod secrets;` + test mod line) |
| 2 | #49 `ConnectorService` + `admin.connectors.*` | `crates/pam_daemon/**` (connector_service*, admin_connectors*, daemon.rs, admin.rs, lib.rs), `crates/pam_testkit/**` |
| 3 | #50 `FlowService` + capabilities + `admin.flows.*` | `crates/pam_daemon/**` (flow_service*, flow_exec*, admin_flows*, executor.rs, policy.rs, daemon.rs, admin.rs, lib.rs), `crates/pam_testkit/**` |
| 4 | #51 CLI · #52 GUI | `crates/pam/**` · `crates/pam_gui/**`, `frontend/**` |
| 5 | #18 starter flows on the bench + integrate and verify (checkpoint) | — |

Wave 0 exists so the two new crates and their workspace lines land once, before four agents fork the tree; without it T1 and T2 both edit the root manifest.

---

### Task 0 (coordinator, no ptrack task): skeletons and workspace lines

**Files:** `Cargo.toml` (members += `crates/pam_flow`, `crates/pam_connectors`; `[workspace.dependencies]` += `pam_flow`, `pam_connectors` path deps, `serde_yaml_ng = "0.10"`, `url = "2"`), `crates/pam_flow/Cargo.toml` (deps: serde, serde_yaml_ng, serde_json, sha2, hex, thiserror), `crates/pam_flow/src/lib.rs` (`#![forbid(unsafe_code)]` + crate doc), `crates/pam_connectors/Cargo.toml` (deps: serde, serde_json, thiserror, url, tokio `process,io-util,time,rt`), `crates/pam_connectors/src/lib.rs`.

- [ ] Add the lines, `cargo check --workspace`, run the C-free grep, commit `chore(workspace): pam_flow and pam_connectors skeletons`, push with the plan doc, PR, squash.

---

### Task 1 (ptrack #45): schema, validation, normalized YAML, digest, builtins, library, vars

**Files:**
- Create: `crates/pam_flow/src/schema.rs` (+ `schema_test.rs`), `validate.rs` (+ test), `normalize.rs` (+ test), `library.rs` (+ test), `vars.rs` (+ test), `builtin.rs` (+ test), `duration.rs` (+ test), `crates/pam_flow/flows/{after-merge-checks,pr-readiness,release-readiness,summarize-build-log,dependency-audit,ci-failure-triage,sonar-gate-check}.yaml`
- Modify: `crates/pam_flow/src/lib.rs` (mods + re-exports)

**Interfaces (Produces):**

```rust
// lib.rs re-exports
pub use schema::{Action, Approval, ArgValue, ConnectorId, Effect, Flow, Input, OutputPolicy, Retry, Role, Step, When};
pub use validate::{FlowError, parse};                  // parse(yaml) -> Result<Flow, FlowError>
pub use normalize::{digest, to_normalized_yaml};
pub use library::{Entry, Library, Source};
pub use vars::{Vars, substitute, references};
pub use builtin::{BuiltinFlow, builtin};
pub use duration::{parse_duration, format_duration};   // "60s" | "500ms" | "2m" | "1h"; formats the shortest exact unit

// schema.rs — serde types; the raw YAML shape has its own private `RawFlow`/`RawStep`
// (deny_unknown_fields, `run` xor `connector`), converted in validate.rs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)] #[serde(rename_all = "snake_case")]
pub enum ConnectorId { Github, Jenkins, Sonarqube, Jira, Confluence, Sharepoint, Aws }
impl ConnectorId { pub const ALL: [Self; 7]; pub fn as_str(self) -> &'static str; pub fn parse(s: &str) -> Option<Self>; }
pub enum ArgValue { Text(String), Int(i64) }          // untagged serde
pub struct Flow { pub id: String, pub name: String, pub description: String, pub inputs: BTreeMap<String, Input>, pub steps: Vec<Step> }
pub struct Input { pub description: String, pub default: Option<String> }
pub struct Step { pub id: String, pub action: Action, pub timeout: Duration, pub effect: Effect, pub role: Role,
                  pub output: OutputPolicy, pub needs: Vec<String>, pub when: When, pub retry: Retry, pub approval: Approval,
                  pub env: BTreeMap<String, String> }
pub enum Action { Command { argv: Vec<String> }, Connector { connector: ConnectorId, call: String, with: BTreeMap<String, ArgValue> } }
pub enum Effect { ReadOnly, Stateful }   pub enum Role { Observe, Verify, Change }
pub enum OutputPolicy { Compact, Summarize, Discard }
pub enum When { NeedsSucceeded, Always, Succeeded(String), Failed(String) }
pub struct Retry { pub attempts: u8, pub backoff: Duration }   pub enum Approval { None, Required }
impl Step { pub fn kind(&self) -> &'static str /* "command" | "connector" */; pub fn gated(&self) -> bool /* stateful || approval required || connector */ }

// validate.rs
#[derive(Debug, Error)] pub enum FlowError {
    #[error("{path}: {message}")] Invalid { path: String, message: String },
    #[error("flow file is {actual} bytes; the limit is {maximum}")] TooLarge { actual: usize, maximum: usize },
    #[error("{0}")] Io(String),
}
pub const SHELLS: &[&str]; pub const MAX_STEPS: usize = 64; /* every bound from Global Constraints as a const */
pub fn parse(yaml: &str) -> Result<Flow, FlowError>;
pub fn is_shell(program: &str) -> bool;                      // exact match, case-insensitive, `.exe` stripped
pub fn looks_secret_like(value: &str) -> bool;               // ghp_/github_pat_/AKIA/ASIA/eyJ...eyJ/Bearer /url userinfo
pub fn is_sensitive_arg(arg: &str) -> bool;                  // --token --password --secret --api-key (=value or bare)
pub struct CallSpec { pub name: &'static str, pub args: &'static [(&'static str, bool /*required*/)], pub yields_log: bool }
pub fn connector_calls(id: ConnectorId) -> &'static [CallSpec]; // the spec's call table; pam_connectors mirrors it (T2 asserts equality)

// normalize.rs
pub fn to_normalized_yaml(flow: &Flow) -> String;   // canonical key order: schema,id,name,description,inputs,steps; per step id, run|connector/call/with, then only non-default fields in the order timeout,effect,role,output,needs,when,retry,approval,env
pub fn digest(flow: &Flow) -> String;               // hex(sha256("pam-flow-v1\0" ++ normalized))

// library.rs
pub enum Source { Builtin, Library }
pub struct Entry { pub id: String, pub source: Source, pub path: Option<PathBuf>, pub yaml: String, pub parsed: Result<Flow, FlowError> }
pub struct Library { dir: PathBuf }
impl Library { pub fn new(dir: PathBuf) -> Self; pub fn dir(&self) -> &Path;
    pub fn list(&self) -> Result<Vec<Entry>, FlowError>;              // sorted by id; library shadows builtin
    pub fn get(&self, id: &str) -> Result<Option<Entry>, FlowError>;
    pub fn save(&self, id: &str, yaml: &str) -> Result<Entry, FlowError>;   // parse → id must equal → create dir → write `<id>.yaml.tmp-<pid>` → rename
    pub fn delete(&self, id: &str) -> Result<bool /*revealed builtin*/, FlowError>; }

// vars.rs
pub struct Vars { map: BTreeMap<String, String> /* "inputs.repo", "repo.path", … */, steps: BTreeMap<String, serde_json::Value> /* step id → { result, exit_status } */ }
impl Vars { pub fn new() -> Self; pub fn set(&mut self, key: &str, value: impl Into<String>); pub fn set_step(&mut self, id: &str, value: serde_json::Value); }
pub fn references(text: &str) -> Vec<String>;                        // every `${…}` key, in order
pub fn substitute(text: &str, vars: &Vars) -> Result<String, VarError>; // VarError::Unresolved { key }
// `${steps.<id>.result.<pointer>}` resolves `pointer` with `[n]` and `.field` segments against the step JSON; scalars stringify, arrays/objects → Unresolved
```

**Steps**

- [ ] `duration.rs` + test: `parse_duration("60s"|"500ms"|"2m"|"1h")`, rejects `"60"`, `"1.5s"`, negative; `format_duration` round-trips.
- [ ] `schema.rs`: raw serde types with `deny_unknown_fields`; `timeout`, `retry.backoff` as strings converted in validate. Test: a full-featured YAML deserializes; unknown key errors name the key.
- [ ] `validate.rs` + test — one test per rule, each asserting the `path` in the error: `schema` must be 1; id regex; duplicate step id; `run` xor `connector`; program regex + shells (`sh`, `CMD.EXE`); args bounds; connector unknown / call unknown / `with` key unknown / missing required arg; `needs` later or unknown step; `when` refs; `stateful` forces approval and `role: verify` on stateful rejected; role defaults; timeout bounds; retry bounds; env name regex; secret-like strings in args/env/defaults (`ghp_…`, `AKIA…`, `eyJ…`, `https://u:p@h`); sensitive arg names; file size; step/inputs counts; unknown `${var}` names (`references` against inputs + `repo.*` + `steps.<earlier>.*`).
- [ ] `normalize.rs` + test: normalized output is byte-stable across two parses, omits defaults, keeps step order; `digest` differs only on content; a builtin's normalized form re-parses to an equal `Flow`.
- [ ] `vars.rs` + test: `references`, `substitute` with `inputs.*`, `repo.*`, `steps.x.result.jobs[0].id`, `steps.x.exit_status`, unresolved error names the key, no re-parse (a substituted value containing `${…}` stays literal).
- [ ] Seven starter YAMLs in `crates/pam_flow/flows/` exactly per the spec table (descriptions in plain English, `dependency-audit` says it needs `cargo-audit`); `builtin.rs` with `include_str!` + test that every builtin parses and `id` equals the file stem.
- [ ] `library.rs` + test (tempdir): empty dir lists the 7 builtins; a saved file shadows a builtin (`source: Library`, `path: Some`); `save` rejects id mismatch, invalid YAML (nothing written, no tmp left), ignores `.yml`/`.txt`/directories, caps at 256 entries; `delete` returns `true` when a builtin is revealed, `Ok(false)`… no: `delete` of a plain library id returns `false`, of a shadow returns `true`, of a missing id is `FlowError::Invalid { path: "id", message: "no library flow named …" }`; `get` of an invalid library file returns `Entry { parsed: Err(..) }` (the GUI shows why).
- [ ] Gate: `cargo test -p pam_flow`, `cargo clippy -p pam_flow --all-targets -- -D warnings`, `cargo fmt`. Commit `feat(flow): pam_flow crate (#<task>)`, PR.

---

### Task 2 (ptrack #46): seven connectors over `HttpTransport`, `CurlTransport`, AWS CLI

**Files:**
- Create: `crates/pam_connectors/src/{transport.rs,curl.rs,error.rs,descriptor.rs,github.rs,jenkins.rs,sonarqube.rs,jira.rs,confluence.rs,sharepoint.rs,aws.rs}` + a `_test.rs` sibling each; `crates/pam_connectors/tests/curl_origin.rs`
- Modify: `crates/pam_connectors/src/lib.rs`; `crates/pam_connectors/Cargo.toml` (dev-dep `pam_flow` for the call-table equality test; `tokio` with `net` for the test origin under `[dev-dependencies]`)

**Interfaces (Produces):**

```rust
pub use pam_flow::ConnectorId;   // re-export; pam_connectors depends on pam_flow for the id and CallSpec (normal dep, not dev)

pub struct HttpRequest { pub method: Method /* Get */, pub url: Url, pub headers: Vec<(String, String)> /* includes Authorization */, pub max_bytes: u64, pub follow_one_https_redirect_without_auth: bool }
pub struct HttpResponse { pub status: u16, pub headers: Vec<(String, String)>, pub body: Vec<u8> }
pub enum TransportError { Timeout, Certificate, Network(String), TooLarge { maximum: u64 }, Spawn(String) }
pub trait HttpTransport: Send + Sync {
    fn send<'a>(&'a self, request: HttpRequest, deadline: Instant) -> Pin<Box<dyn Future<Output = Result<HttpResponse, TransportError>> + Send + 'a>>;
}
pub struct CurlTransport { curl: PathBuf }
impl CurlTransport { pub fn new(curl: PathBuf) -> Self; pub fn config_for(request: &HttpRequest, deadline_secs: u64) -> String /* pub for the test */; }
// curl argv: [--config, -, --silent, --show-error, --include, --proto, =https,http (http only for the test origin: gated by `allow_http` set only in tests via `CurlTransport::allow_http_for_tests`), --max-time N, --max-filesize B, --location-trusted never]; config on stdin: `url = "…"` then one `header = "Name: value"` per header; response parsed from `--include` output (last status line + headers + body); redirect: when `follow_one_https_redirect_without_auth` and status 301/302/307 with an https Location, send once more without the Authorization header
// exit 28 → Timeout, 35/51/58/59/60 → Certificate, 63 → TooLarge, other non-zero → Network(stderr excerpt ≤ 512 bytes, control chars scrubbed)

pub struct Connection { pub base_url: Url, pub username: Option<String>, pub secret: Option<Secret> }
pub struct Secret(String); impl Secret { pub fn new(s: String) -> Self; pub fn expose(&self) -> &str; } impl Drop for Secret { /* zeroize bytes */ } impl Debug for Secret { /* "[REDACTED]" */ }
pub fn validate_base_url(id: ConnectorId, raw: &str) -> Result<Url, ConnectorError>;   // https only, no userinfo/query/fragment, trailing slash normalized; aws accepts None

#[derive(Debug, Error)] pub enum ConnectorError { Auth, Forbidden, NotFound, RateLimited { retry_after: Option<Duration> }, Timeout, Certificate, Network(String), Remote { status: u16 }, TooLarge { bytes: u64, maximum: u64 }, BadArgs(String), BadResponse(String), Cli(String), CliMissing }
impl ConnectorError { pub fn cause(&self) -> &'static str; pub fn detail(&self) -> String; pub fn recovery(&self, id: ConnectorId) -> String; pub fn retryable(&self) -> bool; }
// causes: connector_auth, connector_forbidden, connector_not_found, connector_rate_limited, connector_timeout, connector_certificate, connector_network, connector_remote, connector_response_too_large, connector_bad_args, connector_bad_response, connector_cli, connector_cli_missing
// recovery lines: auth → "open Pam → Settings → Connectors → <Name> → replace the credential and Test"; network/cert → "check the base URL in Pam → Settings → Connectors → <Name>"; rate limit → "wait <n>s and re-run"; cli missing → "install the aws CLI and make sure it is on the daemon's PATH"

pub enum CallResult { Json(serde_json::Value), Log { name: String, bytes: Vec<u8>, exit_status: Option<i32> } }
pub struct VerifyReport { pub detail: String }   // "authenticated as octocat", "site id …", "account 123456789012 arn …"
pub struct Descriptor { pub id: ConnectorId, pub name: &'static str, pub auth: AuthKind, pub needs_base_url: bool, pub username_label: Option<&'static str> /* "user", "email", "profile" */, pub calls: &'static [pam_flow::CallSpec] }
pub enum AuthKind { Bearer, BasicUserSecret, TokenAsUser, AwsProfile }
pub fn descriptor(id: ConnectorId) -> &'static Descriptor;
pub async fn call(id: ConnectorId, conn: &Connection, call: &str, args: &BTreeMap<String, ArgValue>, transport: &dyn HttpTransport, deadline: Instant) -> Result<CallResult, ConnectorError>;
pub async fn verify(id: ConnectorId, conn: &Connection, transport: &dyn HttpTransport, deadline: Instant) -> Result<VerifyReport, ConnectorError>;
pub mod aws { pub const ALLOWED: &[(&str, &str)]; pub const FORBIDDEN_FLAGS: &[&str]; pub fn argv(service, command, args: &[String], profile: Option<&str>) -> Result<Vec<String>, ConnectorError>; pub fn aws_binary() -> Option<PathBuf>; }
```

Per-connector module shape: `pub(crate) async fn call(conn, call, args, transport, deadline)` and `verify(...)`, building `HttpRequest`s and parsing JSON with `serde_json::Value` into the spec's result objects (`{ runs: [...] }`, `{ jobs: [...] }`, `{ partial: bool, ... }`). Auth header per `AuthKind`: Bearer → `Authorization: Bearer <secret>`; BasicUserSecret → `Authorization: Basic base64(user:secret)`; TokenAsUser → `Basic base64(secret:)`. Add `Accept: application/json` and `User-Agent: pam/<version>`; GitHub adds `X-GitHub-Api-Version: 2022-11-28`. A tiny private base64 encoder lives in `transport.rs` (no new dep).

**Steps**

- [ ] `error.rs` + test: cause/recovery table; `retryable` only for `RateLimited`, `Timeout`, `Remote{5xx}`, `Network`.
- [ ] `transport.rs`: types, `FakeTransport` under `#[cfg(test)]` in a shared `testing.rs` (records requests, answers a queue of responses). `validate_base_url` + test (https only, userinfo/query/fragment refused, `/` appended, aws exempt).
- [ ] `curl.rs` + test: `config_for` writes `url`, one `header` line per header with quotes escaped, never argv-visible; exit-code mapping; response parse handles `HTTP/1.1 100 Continue` prelude and `HTTP/2 200` lines. `tests/curl_origin.rs`: a `tokio::net::TcpListener` mini-origin answering a fixed HTTP/1.1 response (JSON, then an oversized body, then a 30 s stall) proves real curl: headers arrive on the wire, `--max-filesize` → `TooLarge`, `--max-time` → `Timeout`; the whole file is skipped with `eprintln!("curl not on PATH; skipping")` when `which curl` fails.
- [ ] `descriptor.rs` + test: the seven descriptors; test asserts `descriptor(id).calls` is pointer-equal to `pam_flow::connector_calls(id)`.
- [ ] `github.rs` + test (fake transport): `runs` builds `/repos/{repo}/actions/runs?status=failure&per_page=N` with Bearer + api-version headers and returns `{ runs: [{id, name, status, conclusion, html_url, head_sha, created_at}] }`; `run` → run + jobs (`{ run: {...}, jobs: [{id, name, conclusion, status}] }`); `job_log` → `Log` with the redirect flag set, `exit_status` from the job's conclusion (fetched first); 401→Auth, 403+`x-ratelimit-remaining: 0`→RateLimited(retry_after from `x-ratelimit-reset`), 404, 429, 500; body > 1 MiB → TooLarge; `verify` → `/user` login.
- [ ] `jenkins.rs` + test: `jobs`, `builds`, `console` (Log; `exit_status` 0 for SUCCESS, 1 for FAILURE/ABORTED/UNSTABLE, None when building); Basic `user:token`; nested job paths (`folder/job`) map to `/job/folder/job/job`; `verify` → `/me/api/json` id.
- [ ] `sonarqube.rs` + test: `quality_gate` → `{ status, conditions: [{metric, status, actual, threshold}] }`; `issues` → `{ partial, total, issues: [{key, rule, severity, component, line, message}] }`; token as Basic user; `verify` requires `valid: true` even on 200.
- [ ] `jira.rs` + test: `search` (jql, maxResults, fields), `issue` (description cut at 16 KiB, `partial`), Bearer PAT; `verify` requires `name` or `key`.
- [ ] `confluence.rs` + test: `search` (cql), `page` (body.storage cut at 64 KiB, `partial`), Basic `email:token` from `username` + secret; `verify` requires `accountId` or `displayName`.
- [ ] `sharepoint.rs` + test: `documents` (`search(q='…')`, `'` refused as BadArgs), `lists`, `$top`; `partial` from `@odata.nextLink` or full page; Bearer; `verify` → `/sites/root` id.
- [ ] `aws.rs` + test: allowlist (the 25 pairs), `FORBIDDEN_FLAGS`, `file://` refusal, `argv` order (`service command args… [--profile P] --output json --no-cli-pager`), `profile` regex; `call` spawns `aws` (tokio process, no shell, stdin null, stdout ≤ 256 KiB → `partial`, stderr ≤ 4 KiB, 30 s cap min deadline, kill on timeout), `NotFound` spawn → `CliMissing`; `verify` = `sts get-caller-identity` requiring `Account` and `Arn`, non-zero exit → `Auth`. Tests use a fake `aws` script placed first on a temporary `PATH` via `aws_binary_override` (`#[cfg(test)]` thread-local) — on Windows the fake is a `.cmd`; keep the test platform-neutral by asserting through the override hook, not by executing when `cfg!(windows)`.
- [ ] Gate: `cargo test -p pam_connectors`, clippy, fmt, C-free grep. Commit `feat(connectors): pam_connectors crate (#<task>)`, PR.

---

### Task 3 (ptrack #47): migration 5, connector rows, capability filter

**Files:**
- Modify: `crates/pam_store/src/migrations.rs` (+ `migrations_test.rs`), `crates/pam_store/src/store.rs` (+ `store_test.rs`), `crates/pam_store/src/lib.rs` (re-exports)

**Interfaces (Produces):**

```rust
pub struct ConnectorRow { pub id: String, pub enabled: bool, pub base_url: Option<String>, pub username: Option<String>,
                          pub last_test_status: Option<String> /* "passed" | "failed" */, pub last_test_detail: Option<String>, pub last_test_ts: Option<i64>, pub updated_ts: i64 }
pub struct ConnectorPatch<'a> { pub enabled: Option<bool>, pub base_url: Option<Option<&'a str>> /* Some(None) clears */, pub username: Option<Option<&'a str>> }
impl Store {
    pub async fn list_connectors(&self) -> Result<Vec<ConnectorRow>, StoreError>;                       // ordered by id
    pub async fn get_connector(&self, id: &str) -> Result<Option<ConnectorRow>, StoreError>;
    pub async fn upsert_connector(&self, id: &str, patch: ConnectorPatch<'_>) -> Result<ConnectorRow, StoreError>;  // INSERT … ON CONFLICT DO UPDATE only the given fields; updated_ts = now
    pub async fn record_connector_test(&self, id: &str, passed: bool, detail: &str) -> Result<(), StoreError>;   // creates the row when absent
    pub async fn list_requests_filtered(&self, limit: Option<u64>, repo: Option<&str>, agent: Option<&str>, state: Option<RequestState>, capability: Option<&str>) -> Result<Vec<RequestRow>, StoreError>;  // new last parameter; every existing caller passes None
}
```

**Steps**

- [ ] Migration 5 SQL exactly as in the spec (`connector` table); `migrations_test`: a v4 database migrates to 5 and the table exists with the CHECKs.
- [ ] Store methods + tests: upsert creates then patches only given fields (`Some(None)` clears base_url), list ordered, `record_connector_test` on an absent id creates the row, `list_requests_filtered(.., Some("flow.run"))` returns only those rows. Update the existing callers of `list_requests_filtered` (admin activity list) to pass `None`.
- [ ] Gate: `cargo test -p pam_store`, `cargo clippy --workspace --all-targets -- -D warnings` (the daemon caller compiles). Commit `feat(store): connector rows and capability filter (#<task>)`, PR.

---

### Task 4 (ptrack #48): keyring-backed `SecretStore` with a fake for tests

**Files:**
- Create: `crates/pam_daemon/src/secrets.rs`, `secrets_test.rs`
- Modify: `crates/pam_daemon/Cargo.toml` (deps: `keyring-core = "=1.0.0"`; `[target.'cfg(target_os = "macos")'.dependencies] apple-native-keyring-store = { version = "=1.0.2", features = ["keychain"] }`; windows `windows-native-keyring-store = { version = "=1.1.0", default-features = false }`; linux `zbus-secret-service-keyring-store = { version = "=1.0.1", features = ["rt-tokio-crypto-rust"] }`), `crates/pam_daemon/src/lib.rs` (`pub mod secrets;` + `#[cfg(test)] mod secrets_test;`)

**Interfaces (Produces):**

```rust
pub const SECRET_SERVICE: &str = "dev.pam.connector";
pub fn account_for(connector_id: &str) -> String;   // "pam.connector.v1.<id>"
#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum SecretError { Unavailable, Denied }
impl SecretError { pub fn cause(&self) -> &'static str /* store_unavailable | store_denied */; pub fn recovery(&self) -> &'static str; }
pub trait SecretBackend: Send + Sync {
    fn get(&self, account: &str) -> Result<Option<String>, SecretError>;
    fn set(&self, account: &str, secret: &str) -> Result<(), SecretError>;
    fn delete(&self, account: &str) -> Result<bool, SecretError>;
}
pub struct NativeSecretBackend { /* Arc<CredentialStore>, explicit_target: bool (windows) */ }
impl NativeSecretBackend { pub fn open() -> Result<Self, SecretError>; }
pub struct FakeSecretBackend { entries: Mutex<BTreeMap<String, String>>, pub fail_with: Mutex<Option<SecretError>> }   // pub, used by daemon tests through DaemonConfig
pub struct SecretStore { backend: Arc<dyn SecretBackend> }
impl SecretStore {
    pub fn new(backend: Arc<dyn SecretBackend>) -> Self;
    pub fn native() -> Result<Self, SecretError>;
    pub async fn get(&self, connector_id: &str) -> Result<Option<pam_connectors::Secret>, SecretError>;   // spawn_blocking
    pub async fn set(&self, connector_id: &str, secret: &str) -> Result<(), SecretError>;
    pub async fn clear(&self, connector_id: &str) -> Result<bool, SecretError>;
    pub async fn present(&self, connector_id: &str) -> Result<bool, SecretError>;
    pub fn warm(self: &Arc<Self>);    // macOS only: spawns one `present("github")` on a blocking task, logs elapsed ms; no-op elsewhere
}
```

**Steps**

- [ ] Write `secrets_test.rs` first against `FakeSecretBackend`: set/get/present/clear round-trip; `Debug` of a `Secret` prints `[REDACTED]`; `fail_with` surfaces `Denied`/`Unavailable`; `account_for` shape; `warm` on non-macOS returns immediately.
- [ ] Implement per pam-old's `pam_platform::secrets` (`Store::new()` per OS, `build(service, account, modifiers)`, `get_password`/`set_password`/`delete_credential`, `NoEntry` → `None`/`false`, `NoStorageAccess` → `Denied`, everything else → `Unavailable`; platform error text goes to `tracing::warn!` only).
- [ ] Gate: `cargo test -p pam_daemon secrets`, clippy, fmt, C-free grep (the keyring stores must not pull `dbus`/`cc`). Commit `feat(daemon): keyring-backed secret store (#<task>)`, PR.

---

### Task 5 (ptrack #49): `ConnectorService`, `admin.connectors.*`, daemon wiring, testkit hooks

**Files:**
- Create: `crates/pam_daemon/src/connector_service.rs` (+ test), `crates/pam_daemon/src/admin_connectors.rs` (+ test)
- Modify: `crates/pam_daemon/src/daemon.rs` (`DaemonConfig { secret_backend: Option<Arc<dyn SecretBackend>>, http_transport: Option<Arc<dyn HttpTransport>> }`, construction + `warm`), `admin.rs` (`AdminService { connectors: Arc<ConnectorService> }`, `dispatch_connectors` first-refusal like `dispatch_logs`), `lib.rs`, `crates/pam_daemon/Cargo.toml` (`pam_connectors`, `pam_model` already), `crates/pam_testkit/src/lib.rs` (`FakeHttp` re-export helper: `TestDaemon::spawn_with_connectors(fake_backend, fake_transport)`), `crates/pam_daemon/tests/daemon.rs` (admin op tests)

**Interfaces (Produces):**

```rust
pub struct ConnectorService { store: Arc<Store>, secrets: Arc<SecretStore>, transport: Arc<dyn HttpTransport>, store_available: bool }
pub struct ConnectorSummary { pub id: String, pub name: &'static str, pub auth: &'static str, pub username_label: Option<&'static str>, pub needs_base_url: bool,
                              pub enabled: bool, pub base_url: Option<String>, pub username: Option<String>, pub credential_present: bool, pub store_available: bool,
                              pub last_test: Option<LastTest { status: String, detail: String, ts: i64 }> }
pub enum CredentialAction { Set(String), Clear }
pub struct ConfigurePatch { pub enabled: Option<bool>, pub base_url: Option<Option<String>>, pub username: Option<Option<String>>, pub credential: Option<CredentialAction> }
#[derive(Debug, Error)] pub enum InvokeError { Disabled, CredentialMissing, BaseUrlMissing, Secret(SecretError), Connector(ConnectorError), NotConfigured }
impl InvokeError { pub fn cause(&self) -> &'static str; pub fn detail(&self) -> String; pub fn recovery(&self, id: ConnectorId) -> String; }
// causes: connector_disabled ("open Pam → Settings → Connectors → <Name> → enable"), credential_missing (… → set the credential), base_url_missing, store_unavailable, store_denied, plus ConnectorError causes
impl ConnectorService {
    pub fn new(store, secrets, transport) -> Self;
    pub async fn list(&self) -> Result<Vec<ConnectorSummary>, StoreError>;                 // all seven, rows merged; credential_present false when the store is unavailable
    pub async fn configure(&self, id: ConnectorId, patch: ConfigurePatch) -> Result<ConnectorSummary, InvokeError>;   // validates base_url via pam_connectors::validate_base_url; secret first, row second
    pub async fn test(&self, id: ConnectorId) -> Result<(bool, String), InvokeError>;       // verify under 10 s; records the result either way
    pub async fn invoke(&self, id: ConnectorId, call: &str, args: &BTreeMap<String, ArgValue>, deadline: Instant) -> Result<CallResult, InvokeError>;
}
pub const CONNECTOR_ADMIN_OPS: &[&str] = &[OP_CONNECTORS_LIST, OP_CONNECTORS_CONFIGURE, OP_CONNECTORS_TEST];
```

**Steps**

- [ ] `connector_service_test.rs` (in-memory store, `FakeSecretBackend`, `FakeTransport`): `list` shows seven with `credential_present`; `configure` set-secret + enable + base URL, bad URL refused before any write, clear removes the secret, unavailable store → `store_unavailable` and list still answers; `test` records passed/failed with detail; `invoke` on disabled/missing credential/missing base URL refuses before the transport sees anything (`FakeTransport` request log empty); `invoke` happy path returns the `Json`.
- [ ] Implement the service; audit row for configure: `action = "connector.configure"`, `detail = { id, enabled, base_url, username, credential: "set"|"cleared"|"unchanged" }` — never the secret (test greps the audit row for the secret string).
- [ ] `admin_connectors.rs`: ops `admin.connectors.list|configure|test` with `bad_args` refusals (`unknown connector`, `credential` shape); `dispatch_connectors` hooked into `AdminService::dispatch`; bridge deadline note in the module doc (15 s for test).
- [ ] Daemon wiring: `DaemonConfig` gains the two injection points (defaults `None` → native backend if it opens, else the service runs with `store_available = false`; `CurlTransport::new(pam_model::download::curl_path()?)`, a missing curl makes `invoke` refuse `connector_cli_missing` with `curl_recovery_line()` — the daemon still boots); `secrets.warm()` on macOS at boot.
- [ ] Testkit: `TestDaemon::spawn_with_connectors(backend: Arc<FakeSecretBackend>, transport: Arc<FakeTransport>)` (move `FakeTransport` to `pam_connectors::testing` behind a `testing` feature the testkit enables, same pattern as `pam_model::testing`).
- [ ] Integration tests (`tests/daemon.rs`): each admin op through the socket (request row `done`, single terminal audit row, tripwire refusal for `claude`), configure + test + list agree.
- [ ] Gate: full `tools/check.sh`. Commit `feat(daemon): ConnectorService + admin.connectors.* (#<task>)`, PR.

---

### Task 6 (ptrack #50): `FlowService`, step executor, capabilities, `admin.flows.*`, policy and executor wiring

**Files:**
- Create: `crates/pam_daemon/src/flow_service.rs` (+ test) — library, list/show, settings, verdict; `crates/pam_daemon/src/flow_exec.rs` (+ test) — one run: gate, command, connector, output, retry; `crates/pam_daemon/src/admin_flows.rs` (+ test)
- Modify: `policy.rs` (`classify`: `flow.run` → NonDestructive, `flow.list`|`flow.show` → ReadOnly; `pub fn evaluate_classified` made `pub`), `executor.rs` (`BuiltinCapability::{FlowRun, FlowList, FlowShow}`, `ExecContext { flows: Arc<FlowService>, approvals: Arc<ApprovalService>, caller: Caller, capability: String }`), `daemon.rs` (construct `FlowService`, pass `incoming_tx.clone()` to `AdminService` for `admin.flows.run`), `admin.rs` (`flows`, `submit`), `lib.rs`, `crates/pam_testkit/src/lib.rs` (`seed_allowed_programs(tmp, &[..])`, `seed_extra_path`), `crates/pam_daemon/tests/flows.rs` (new integration file)

**Interfaces (Produces):**

```rust
pub const SETTING_ALLOWED_PROGRAMS: &str = "flows.allowed_programs";
pub const SETTING_EXTRA_PATH: &str = "flows.extra_path";
pub const CAP_FLOW_RUN: &str = "flow.run"; pub const CAP_FLOW_LIST: &str = "flow.list"; pub const CAP_FLOW_SHOW: &str = "flow.show";
pub fn step_capability(flow: &str, step: &str) -> String;   // "flow.step:<flow>/<step>"
pub struct FlowSettings { pub allowed_programs: Vec<String>, pub extra_path: Vec<String> }
impl FlowSettings { pub fn platform_default() -> Self; pub fn secret_env_pattern() -> &'static str; }
pub struct FlowService { library: Library, store, approvals, connectors, logs, gate: Arc<PolicyGate> }
impl FlowService {
    pub fn new(base_dir: &Path /* library = base/flows */, store, approvals, connectors, logs, gate) -> Self;
    pub async fn settings(&self) -> Result<FlowSettings, StoreError>;            // persisted or platform default (persisted on first read)
    pub async fn set_settings(&self, patch: { allowed_programs: Option<Vec<String>>, extra_path: Option<Vec<String>> }) -> Result<FlowSettings, FlowRefusal>;  // shells refused
    pub fn library(&self) -> &Library;
    pub async fn list(&self) -> CapabilityOutput;                                  // verified; body { flows: [ListEntry] }
    pub async fn show(&self, id: &str) -> Result<CapabilityOutput, FlowRefusal>;  // verified; body { id, source, yaml, normalized_yaml, digest, valid, error? }
    pub async fn run(&self, ctx: &ExecContext, args: RunArgs { id, inputs: BTreeMap<String, String> }) -> Result<CapabilityOutput, CapabilityFailure>;
}
pub struct FlowRefusal { pub cause: &'static str, pub detail: String, pub recovery: String }   // flow_not_found, flow_invalid, input_missing, repo_missing, program_not_allowed
// CapabilityFailure gains `Refused { cause, detail, recovery }` so the pipeline can answer a refusal from an executor (today only Cancelled | Failed exist); the pipeline maps it to Response::Refusal with its own terminal audit row (action "execution_refused").

// flow_exec.rs
pub struct StepReport { pub id: String, pub kind: &'static str, pub status: StepStatus, pub attempts: u8, pub duration_ms: u64, pub exit_status: Option<i32>,
                        pub evidence: Vec<String>, pub summary: Option<String>, pub error: Option<StepError { cause: String, detail: String, recovery: String }> }
pub enum StepStatus { Succeeded, Failed, Skipped, Blocked, Cancelled }
pub struct RunReport { pub outcome: Outcome, pub summary: String, pub steps: Vec<StepReport> }
pub fn outcome_for(steps: &[StepReport], flow: &Flow) -> Outcome;     // blocked > unresolved > changed > verified > solved, skipped steps ignored
pub fn summary_for(steps: &[StepReport]) -> String;                   // "7 steps: 6 succeeded, 1 failed (clippy, exit 101)"
pub async fn run_command(spec: CommandSpec { program: PathBuf, argv: Vec<String>, cwd: PathBuf, env: Vec<(String, String)>, timeout: Duration }, cancel: &mut watch::Receiver<bool>) -> CommandOutcome { Exited { status: i32, output: Vec<u8> } | TimedOut { output } | OutputLimit { output } | Cancelled | SpawnFailed(String) }
pub fn scrub_env(vars: impl Iterator<Item = (OsString, OsString)>) -> Vec<(String, String)>;   // drops secret-named vars and PATH (PATH is rebuilt)
pub fn resolve_program(program: &str, extra_path: &[PathBuf], path: &OsStr) -> Option<PathBuf>;
```

Run algorithm — implement exactly the spec's §"`flow_service.rs` — the engine" list 1–8. Key code for the step gate:

```rust
let name = step_capability(&flow.id, &step.id);
let class = if matches!(step.action, Action::Connector { .. }) { CapabilityClass::External } else { CapabilityClass::Destructive };
match gate.evaluate_classified(&ctx.request_id, &name, class).await? {
    GateDecision::Allow { .. } => {}
    GateDecision::RequireApproval { .. } => match approvals.request_approval(&ctx.request_id, &name, &mut ctx.cancel).await? {
        ApprovalOutcome::Approved { .. } => store.update_request_state(&ctx.request_id, RequestState::Running, None).await?,
        ApprovalOutcome::Denied | ApprovalOutcome::TimedOut => { report.blocked(step, "approval_denied" | "approval_timeout", "…", "open Pam → Approvals"); break; }
        ApprovalOutcome::Cancelled => return Err(CapabilityFailure::Cancelled),
    },
    GateDecision::Refuse { cause, detail, recovery } => { report.blocked(step, cause, detail, recovery); break; }
}
```

Progress: `ctx.events.publish(id, Event::Progress { pct: Some(done * 100 / total), note: format!("{step}: running ({n}/{total})") })` before each step. Evidence: `flow.result` written last with `insert_evidence(id, request_id, "flow.result", body_json, meta { flow, outcome, steps, failed })`; `CapabilityOutput.evidence` = every id in order.

**Steps**

- [ ] `flow_exec_test.rs` (pure, no daemon): `outcome_for` matrix (blocked, unresolved, changed, verified, solved, skipped ignored); `summary_for`; `scrub_env` drops `GITHUB_TOKEN`, `AWS_SECRET_ACCESS_KEY`, keeps `HOME`; `resolve_program` prefers extra_path; `run_command` with the test's own helper: use `std::env::current_exe()`-independent programs available everywhere — `git --version` (exit 0), `git nonsense` (exit 1); timeout kills `git` stuck on… no: for timeout/cap use a tiny helper binary `crates/pam_daemon/src/bin/pam-flow-helper.rs` (`sleep <ms>` and `spew <bytes>`; `#[cfg(test)]`-only is impossible for a bin, so mark it `required-features = ["testing"]` in Cargo and enable `testing` for tests) — timeout → `TimedOut` with the child gone (poll `try_wait`), 64 MiB + 1 → `OutputLimit`, cancel flip → `Cancelled`.
- [ ] `flow_service_test.rs`: settings default + persist, shells refused, `list` body shape, `show` body shape for a builtin and an invalid library file.
- [ ] Implement `flow_exec.rs`, `flow_service.rs`; wire `policy.rs`, `executor.rs` (`FlowRun` → `ctx.flows.run(&ctx, args)`), `daemon.rs`, `admin_flows.rs` (`admin.flows.list|get|save|delete|run|settings.get|settings.set`; `run` builds `Envelope { id: new req id, capability: "flow.run", caller: { agent: "pam-gui", repo, pid: std::process::id() }, args: { id, inputs }, deadline_ms: 1_800_000, wait: false, client_version: DAEMON_VERSION }` and sends `IncomingRequest { identity: vec![], envelope, reply }` through `submit`, answering the `Ticket` — a `Result`/`Refusal` reply (gate refusal) is forwarded as that refusal).
- [ ] `tests/flows.rs` (testkit, `seed_relaxed` + `seed_allowed_programs(&["git", "pam-flow-helper"])` + extra_path containing the helper's dir): every scenario listed in the spec's Testing § for `pam_daemon` — builtins list/show; shadowing; two-step verified run with `flow.result` body equal to the response body and `log.compact` rows per step; failing step → `unresolved`, exit status + attempts; `when` skip; timeout; output cap; cancel via `pam cancel` mid-step; program not allowed → `blocked`; stateful step pauses (`waiting_approval` row, `ApprovalPending` event), approve with remember → `done`, second run has no pause; deny → `blocked` + one approval audit + one terminal audit; connector step with `FakeTransport` → `connector.result` evidence and `${steps.a.result.x}` substituted in step b's argv; disabled connector → `blocked` with the Settings recovery line; `admin.flows.run` → ticket, row `caller_agent = "pam-gui"` + chosen repo; `admin.flows.save/get/delete`; opt-in `PAM_BENCH_MODEL` summarize test.
- [ ] Gate: `tools/check.sh`. Commit `feat(daemon): FlowService, flow.* capabilities, admin.flows.* (#<task>)`, PR.

---

### Task 7 (ptrack #51): `pam flow list|show|run`

**Files:**
- Modify: `crates/pam/src/main.rs` (`Cmd::Flow { #[command(subcommand)] action: FlowCmd }`; `FlowCmd::{List { json }, Show { id }, Run { id, inputs: Vec<String> /* k=v */, no_wait, deadline_ms = 1_800_000, json }}`), `crates/pam/src/render.rs` (+ `render_test.rs`: `render_flow_list(body)`, `render_flow_show(body)` (prints `normalized_yaml`), `render_flow_result(body, evidence)`, `render_flow_progress(event)`), `crates/pam/src/lib.rs` (module docs list the new subcommand), `crates/pam/tests/cli.rs`

**Interfaces (Consumes):** `flow.list` body `{ flows: [{ id, name, description, source, valid, error?, steps, inputs: [{ name, description, default? }] }] }`; `flow.show` body; `flow.run` body per the spec's verdict JSON.

**Steps**

- [ ] `render_test.rs` first: list table (`id  source  steps  name`, invalid rows show `invalid: <message>`), result rendering (`✓ clippy  verified  4.2s`, `✗ test  failed  exit 101  ev_…`, `· docs  skipped`, `⊘ deploy  blocked  approval_denied`, then the summary sentence and each step's summary text indented), progress line `→ clippy (5/7)`.
- [ ] Implement the subcommand: `run` parses `k=v` inputs (`pam flow run: input "x" must be key=value` → `EXIT_USAGE`), sends `flow.run` with `wait: !no_wait`; when waiting it also follows progress: send with `wait: false`, then `client::follow_ticket` printing progress lines (quiet under `--json`), then `query` for the terminal body? — no: the terminal event carries no body, so keep it simple: `wait: true` in one request and no live progress (progress printing is `pam subscribe <ticket>`'s job; document that in `--help`). `--no-wait` prints the ticket line as `echo` does.
- [ ] `tests/cli.rs`: against a testkit daemon with `git` allowed: `flow list` shows seven builtins and exit 0; `flow show after-merge-checks` prints YAML starting with `schema: 1`; `flow run after-merge-checks` in a temp git repo (init + one commit) exits 0 and `--json` body has `outcome: "verified"`; unknown id exits 3 with the refusal on stderr.
- [ ] Gate: `tools/check.sh`. Commit `feat(cli): pam flow list/show/run (#<task>)`, PR.

---

### Task 8 (ptrack #52): bridge, Flows screen, Settings › Flows, Settings › Connectors, approvals copy

**Files:**
- Modify: `crates/pam_gui/src/bridge.rs` (+ `bridge_test.rs`: splice `FLOW_ADMIN_OPS`, `CONNECTOR_ADMIN_OPS`; `deadline_for(OP_CONNECTORS_TEST) = 15_000`), `frontend/src/lib/ipc.ts` (+ `ipc.test.ts`), `frontend/src/router.tsx`, `frontend/src/components/shell/Sidebar.tsx`, `frontend/src/App.test.tsx` (Flows is a link now), `frontend/src/screens/Settings.tsx` (+ test: two new sections `flows`, `connectors` between `models` and `daemon`), `frontend/src/screens/Approvals.tsx` (+ test: `flow` family copy)
- Create: `frontend/src/screens/Flows.tsx` (+ `Flows.test.tsx`), `frontend/src/screens/FlowEditor.tsx`, `frontend/src/screens/FlowRuns.tsx`, `frontend/src/screens/FlowRunCard.tsx`, `frontend/src/screens/SettingsFlows.tsx` (+ test), `frontend/src/screens/SettingsConnectors.tsx` (+ test)

**Interfaces (Consumes → ipc.ts):**

```ts
export type AdminOp = … | "admin.flows.list" | "admin.flows.get" | "admin.flows.save" | "admin.flows.delete" | "admin.flows.run" | "admin.flows.settings.get" | "admin.flows.settings.set" | "admin.connectors.list" | "admin.connectors.configure" | "admin.connectors.test";
export interface FlowListEntry { id: string; name: string; description: string; source: "builtin" | "library"; path?: string; valid: boolean; error?: string; digest: string; steps: number; inputs: { name: string; description: string; default?: string }[] }
export interface FlowDetail extends FlowListEntry { yaml: string; normalized_yaml: string; flow?: unknown }
export interface FlowSettings { allowed_programs: string[]; extra_path: string[] }
export interface FlowStepReport { id: string; kind: "command" | "connector"; status: "succeeded" | "failed" | "skipped" | "blocked" | "cancelled"; attempts: number; duration_ms: number; exit_status?: number; evidence: string[]; summary?: string; error?: { cause: string; detail: string; recovery: string } }
export interface FlowResult { flow: { id: string; name: string; source: string; digest: string }; repo: string; inputs: Record<string, string>; outcome: Outcome; summary: string; steps: FlowStepReport[] }
export interface ConnectorSummary { id: string; name: string; auth: "bearer" | "basic_user_secret" | "token_as_user" | "aws_profile"; username_label?: string; needs_base_url: boolean; enabled: boolean; base_url?: string; username?: string; credential_present: boolean; store_available: boolean; last_test?: { status: "passed" | "failed"; detail: string; ts: number } }
export function flowsList(): Promise<{ flows: FlowListEntry[] }>;  flowsGet(id); flowsSave(id, yaml); flowsDelete(id); flowsRun(id, repo, inputs): Promise<{ ticket: string; position: number }>; flowsSettingsGet(); flowsSettingsSet(patch);
export function connectorsList(); connectorsConfigure(id, patch: { enabled?, base_url?, username?, credential?: { set: string } | { clear: true } }); connectorsTest(id): Promise<{ status: "passed" | "failed"; detail: string; ts: number }>;
```

Runs history reads `activityList({ capability: "flow.run", repo? })` (extend the wrapper's args with `capability`, forwarded by `admin.activity.list` — T6 adds the arg) and `evidenceList(request_id)` → the `flow.result` row via `evidenceGet` (JSON parse of `text`).

**Steps**

- [ ] `bridge_test.rs`: every flow/connector op forwarded, unknown refused, `deadline_for("admin.connectors.test") === 15_000`. Implement the splice (fourth and fifth lists in `compose_admin_ops`).
- [ ] `ipc.test.ts` + wrappers.
- [ ] `Flows.test.tsx` first (mocked `ipc`): library column renders seven builtins with `builtin` badges and an invalid library entry with its message; selecting shows the YAML tab with the text; Save on a builtin is labelled Clone and asks for a new id; Save with a validation refusal renders a `FailureNote` with the path; Delete uses `ConfirmButton`; the Run card lists callers' repos and one field per input with its default; Run calls `flowsRun` and shows the progress line from a fed `pam://event` progress payload, then the verdict card after a `done` event (verdict loaded through `evidenceList`/`evidenceGet`); the Runs tab lists rows and expands into the step table with outcome chips (`solved|changed|verified` accent, `unresolved` warn, `blocked` danger).
- [ ] Implement `Flows.tsx` (two columns inside the raised panel; the list in `font-data`; the detail tabs as CVA-variant buttons), `FlowEditor.tsx` (a `<textarea>` in `font-data`, Validate = `flowsSave` dry-run? — no dry-run op exists: Validate parses client-side only for YAML syntax via the daemon: **use `flowsSave` for Save and show the daemon's error; drop a separate Validate button**), `FlowRuns.tsx`, `FlowRunCard.tsx`. Router: `flowsRoute` at `/flows`; Sidebar: `NavLink to="/flows"` replaces `NavSoon`; `App.test.tsx` updated (five links, no "soon").
- [ ] `SettingsFlows.test.tsx` + panel: chips for allowed programs (remove ×, add field; a shell answer renders the daemon's refusal), extra PATH rows (add/remove), both saving through `flowsSettingsSet`.
- [ ] `SettingsConnectors.test.tsx` + panel: seven rows; enable toggle; base URL input hidden for aws; username input with the label from `username_label`; credential: password input + Set / Clear (Clear uses `ConfirmButton`), hidden for aws; Test button → result badge with relative time; badges `credential set`, `store unavailable` (from `store_available: false`, with the copy "the OS credential store is unavailable; see the daemon log"), `access denied` on a `store_denied` refusal; a failed configure shows the `FailureNote`.
- [ ] `Approvals.tsx`: `approvalMeaning` case `"flow"` → `{ before: "The flow asks to run a gated step, ", after: ". Approving runs that step this once; remember keeps it for this flow." }` (the capability string is `flow.step:<flow>/<step>`; render `<flow> / <step>` from it in the data voice). Test.
- [ ] Settings copy: `RetentionPanel` untouched; `Section` order `Appearance, Security, Models, Flows, Connectors, Daemon, Retention, Logs` (update the two tests asserting the heading list).
- [ ] Eyeball in the fixture browser (memory `gui-fixture-drive-tauri-shim`): Flows list, editor with an error, run card, verdict, runs history, both settings panels, all four theme × mode combos; production proof `npm run build && rg 'admin.flows.run' frontend/dist/assets/*.js`.
- [ ] Gate: `tools/check.sh`. Commit `feat(gui): Flows screen, Settings flows/connectors, bridge ops (#<task>)`, PR.

---

### Task 9 (ptrack #18, coordinator): starter flows on the bench, integrate and verify

- [ ] Build the production binary (`npm --prefix frontend run build && cargo build --release -p pam --features gui-embed`), `strings target/release/pam | grep -c 'admin.flows.run'` > 0.
- [ ] With `PAM_BASE_DIR=/tmp/pamf`: `pam flow list`; `pam flow run after-merge-checks` and `pr-readiness` in this repo → verdicts with evidence; `pam flow run ci-failure-triage` against a real GitHub repo with a PAT set through the GUI (owner supplies; skip with a note if none) — otherwise prove the connector path with the fake transport test only and say so.
- [ ] `tools/check.sh` green on settled `main`; main CI run for the last merge green by id (`gh run watch <id> --exit-status`).
- [ ] ptrack: `task done 18 --summary` naming what calls what (agents through `pam flow run`, humans through the Flows screen, `LogService::compress` from every step), `plan done 5`, act on the checkpoint block, `summary set`.

---

## Self-review notes (coordinator)

- Spec coverage: schema/validation/normalize/digest/builtins/library/vars → T1; connectors + curl + AWS → T2; migration 5 + capability filter → T3; keyring → T4; connector service + admin ops + warm → T5; engine, step gate, command/connector execution, output policy, verdict, capabilities, `admin.flows.*` (incl. `run` through the pipeline ingress and settings) → T6; CLI → T7; GUI (Flows, Settings × 2, approvals copy, bridge) → T8; bench + checkpoint → T9.
- Known deviation from the spec, decided while planning: the Flows editor has no separate Validate button (no dry-run op); Save reports the daemon's validation error. `pam flow run` does not stream progress lines itself; `pam subscribe <ticket>` does. Both recorded in the spec's GUI/CLI sections at merge time.
- Type consistency: `ConnectorId` and `CallSpec` are owned by `pam_flow` and re-exported by `pam_connectors`; `Secret` is owned by `pam_connectors` and used by `pam_daemon::secrets`; `FakeTransport` lives in `pam_connectors::testing` (feature `testing`); `CapabilityFailure::Refused` is new in T6 and only T6's pipeline change consumes it.
