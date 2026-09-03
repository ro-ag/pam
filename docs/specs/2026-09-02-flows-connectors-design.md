# Flows engine + connector host — design

Status: approved by owner (brainstorming session, 2026-09-02)
Umbrella vision: `docs/vision.md` §3 "Local workflows kill boilerplate",
Scoping model ("Flows" and "Connectors" are global), Credentials.
Depends on: spine spec (policy gate, approvals, lanes, evidence), model
layer spec (`ModelService`), log compression spec (`LogService::compress`).

## Scope and owner decisions (2026-09-02)

- **Plan #5 absorbs plan #8.** Flows need connector steps and the
  starter flows the vision names are mostly connector-driven, so the
  connector host ships here. Plan #8 closes as merged; nothing is
  stubbed.
- **All seven connectors**: GitHub Actions, Jenkins, SonarQube, Jira
  Data Center, Confluence Cloud, SharePoint, allowlisted read-only AWS
  CLI passthrough. **Read-only calls only** in this plan; the one
  stateful step type is a command. (pam-old's `runs.rerun` stays out —
  it is the only stateful connector call and no starter flow needs it.)
- **HTTPS through system `curl`** as a child process, the same rule the
  model layer already follows: every pure-Rust TLS stack compiles C
  (`ring`, `aws-lc`) or is alpha. Secrets go to curl through a config
  file on stdin (`--config -`), never argv.
- **Credentials in the OS-native store** via pam-old's stack:
  `keyring-core` 1.0 with `apple-native-keyring-store` (macOS),
  `windows-native-keyring-store`, `zbus-secret-service-keyring-store`
  (Linux, pure-Rust D-Bus). SQLite keeps enabled flag, base URL,
  username, and test results — never a secret.
- **Command allowlist lives in Settings** (`flows.allowed_programs`),
  seeded with a toolchain list, GUI-editable; shells are refused
  unconditionally. pam-old's git-only allowlist is not carried: it made
  every build/test flow impossible.
- **Flows are YAML** (vision decision), one file per flow in the global
  library `<base>/flows/<id>.yaml`; the seven starter flows are embedded
  in the binary and overridable by a same-id library file.
- **GUI in this plan**: Flows screen (library, YAML editor, run with a
  repo picker, run history with per-step results and evidence),
  Settings › Flows (allowlist, extra PATH), Settings › Connectors
  (enable, base URL, username, credential set/clear, test). The xyflow
  designer canvas stays plan #6 and mounts beside the same YAML tab.

Out of scope: stateful connector calls, per-project flows (never — the
memento rule), flow scheduling/triggers, secrets in flows (validation
rejects secret-like strings), the designer canvas (#6), Ask Pam deep
links into flows (#7), evidence retention (#10).

## Crate: `pam_flow`

Pure library (`serde`, `serde_yaml_ng`, `serde_json`, `sha2`, `hex`,
`thiserror`): schema, validation, normalized rendering, digest, the
embedded starter flows, and the library directory reader. No daemon
knowledge.

### YAML schema (v1)

```yaml
schema: 1
id: ci-failure-triage            # must equal the file stem; [a-z0-9-]{1,64}
name: CI failure triage
description: Fetch the latest failed GitHub Actions run for this repo and summarize its failing job log.
inputs:                           # optional, ordered map
  repo:
    description: owner/name on GitHub
    default: ${repo.origin}       # defaults may use built-in variables
steps:
  - id: latest-failed             # [a-z0-9-]{1,64}, unique
    connector: github             # connector step: connector + call + with
    call: runs
    with: { repo: ${inputs.repo}, status: failure, limit: 1 }
  - id: job-log
    connector: github
    call: job_log
    with: { repo: ${inputs.repo}, job_id: ${steps.latest-failed.result.jobs[0].id} }
    output: summarize             # compact (default) | summarize | discard
  - id: worktree
    run: [git, status, --short]   # command step: argv array, never a shell string
    timeout: 60s                  # default 300s, max 3600s
    effect: read_only             # read_only (default) | stateful
    role: observe                 # observe | verify | change (default by effect)
    needs: [job-log]              # earlier steps only
    when: needs_succeeded         # needs_succeeded (default) | always | { succeeded: <step> } | { failed: <step> }
    retry: { attempts: 2, backoff: 500ms }   # attempts 1..5, backoff ≤ 60s, doubling, cap 60s
    approval: none                # none (default) | required; stateful ⇒ required is forced
    env: { CARGO_TERM_COLOR: never }         # additions only; names [A-Z_][A-Z0-9_]*, secret-like values refused
```

Rules (every violation is a `FlowError::Invalid { path, message }`
naming the YAML path):

- Unknown fields rejected (`deny_unknown_fields`). `schema` must be 1.
- Exactly one of `run` / `connector` per step. `run[0]` is a bare
  program name (`[A-Za-z0-9][A-Za-z0-9._+-]*`, no path separators);
  `sh`, `bash`, `zsh`, `fish`, `dash`, `pwsh`, `powershell`, `cmd`,
  `cmd.exe`, `env`, `xargs`, `sudo`, `doas` are refused at validation
  as well as at run time. Args ≤ 64, each ≤ 4 KiB, total ≤ 32 KiB.
- `connector` ∈ the static set; `call` ∈ that connector's read-only
  calls (see the connector table); `with` keys must be the call's
  declared arguments, all values strings or integers.
- `needs` and every `when` reference name an **earlier** step (steps
  execute in file order; the graph is the designer's, the order is the
  engine's). Duplicate ids rejected.
- `effect: stateful` forces `approval: required`; `role` defaults to
  `observe` for read-only and `change` for stateful; `role: verify` is
  read-only only.
- Bounds: ≤ 64 steps, ≤ 16 inputs, file ≤ 256 KiB, `name` ≤ 120 bytes,
  `description` ≤ 2 KiB.
- Secret hygiene (ported from pam-old): any string that looks like a
  bearer/PAT/AWS key/JWT or a URL with userinfo is rejected; argument
  names `--token=`, `--password`, `--secret`, `--api-key` (with or
  without `=`) are rejected.
- Variables: `${inputs.<k>}`, `${repo.path}`, `${repo.name}` (basename),
  `${repo.origin}` (`owner/name` parsed from `git remote get-url origin`
  when it is a GitHub URL, else empty and the step that uses it fails
  with `variable_unavailable`), `${steps.<id>.result.<json pointer>}`
  (connector JSON result field; `.exit_status` for commands). Unknown
  variables are validation errors; unresolvable ones at run time fail
  the step. Substitution happens per argument string, never re-parsed.

```rust
pub struct Flow { pub schema: u16, pub id: String, pub name: String, pub description: String,
                  pub inputs: IndexMap<String, Input>, pub steps: Vec<Step> }
pub struct Input { pub description: String, pub default: Option<String> }
pub struct Step { pub id, pub action: Action, pub timeout: Duration, pub effect: Effect, pub role: Role,
                  pub output: OutputPolicy, pub needs: Vec<String>, pub when: When, pub retry: Retry,
                  pub approval: Approval, pub env: BTreeMap<String, String> }
pub enum Action { Command { argv: Vec<String> }, Connector { connector: ConnectorId, call: String, with: BTreeMap<String, ArgValue> } }
pub enum Effect { ReadOnly, Stateful }        pub enum Role { Observe, Verify, Change }
pub enum OutputPolicy { Compact, Summarize, Discard }
pub enum When { NeedsSucceeded, Always, Succeeded(String), Failed(String) }
pub struct Retry { pub attempts: u8, pub backoff: Duration }   pub enum Approval { None, Required }

pub fn parse(yaml: &str) -> Result<Flow, FlowError>;           // parse + validate
pub fn to_normalized_yaml(flow: &Flow) -> String;             // canonical key order, defaults omitted; designer round-trip target
pub fn digest(flow: &Flow) -> String;                          // sha256 hex over "pam-flow-v1\0" + normalized yaml
pub fn builtin() -> &'static [BuiltinFlow];                    // { id, yaml: &'static str }, include_str! from crates/pam_flow/flows/*.yaml
pub struct Library { pub dir: PathBuf }
pub struct Entry { pub id, pub source: Source /* Builtin | Library */, pub path: Option<PathBuf>, pub yaml: String, pub parsed: Result<Flow, FlowError> }
impl Library {
    pub fn list(&self) -> Result<Vec<Entry>, FlowError>;       // library files (stem == id, `.yaml` only, ≤ 256 entries) merged over builtins; a library id shadows the builtin
    pub fn get(&self, id: &str) -> Result<Option<Entry>, FlowError>;
    pub fn save(&self, id: &str, yaml: &str) -> Result<Entry, FlowError>;   // validate first; atomic write (tmp + rename)
    pub fn delete(&self, id: &str) -> Result<(), FlowError>;   // library only; deleting a shadow reveals the builtin
}
```

Variable substitution and `steps.*` references are a separate pure
module (`pam_flow::vars`) the daemon feeds with a `Vars` map, so it is
unit-tested without a daemon.

### Starter flows (embedded, `crates/pam_flow/flows/`)

| id | steps |
| --- | --- |
| `after-merge-checks` | `git fetch --prune` · `git status --short` (verify) · `git log --oneline -20` (summarize) |
| `pr-readiness` | `git status --short` (verify clean) · `git fetch --prune` · `git log --oneline origin/main..HEAD` · `cargo fmt --all --check` (verify) · `cargo clippy --workspace --all-targets -- -D warnings` (verify, summarize) · `cargo test --workspace` (verify, summarize) |
| `release-readiness` | `git status --short` (verify) · `git describe --tags --abbrev=0` · `cargo test --workspace` (verify, summarize) · `cargo package --list --allow-dirty` (verify) |
| `summarize-build-log` | `cargo build --all-targets` (summarize) |
| `dependency-audit` | `cargo audit` (verify, summarize; description says it needs cargo-audit) · `cargo tree --duplicates` |
| `ci-failure-triage` | github `runs` (latest failed for `${inputs.repo}`) · github `run` (jobs) · github `job_log` (summarize) |
| `sonar-gate-check` | sonarqube `quality_gate` (`${inputs.project}`) (verify) · sonarqube `issues` (limit 50) |

Each is a normal YAML file a human clones and edits from the GUI; the
Rust-flavoured ones are the owner's bench and read as templates.

## Crate: `pam_connectors`

Pure library over an injected transport (`serde`, `serde_json`,
`thiserror`, `tokio` process/io for the curl transport, `url`). One
module per connector, one `_test.rs` sibling each with a fake transport.

```rust
pub enum ConnectorId { Github, Jenkins, Sonarqube, Jira, Confluence, Sharepoint, Aws }
pub struct Descriptor { pub id, pub name: &'static str, pub auth: AuthKind, pub base_url: BaseUrlRule, pub calls: &'static [CallSpec] }
pub enum AuthKind { Bearer /* github, jira, sharepoint: one secret */, BasicUserSecret /* jenkins (user), confluence (email): row username + secret */, TokenAsUser /* sonarqube: secret as Basic user, empty password */, AwsProfile /* no secret; row username = profile */ }
pub struct CallSpec { pub name: &'static str, pub args: &'static [ArgSpec], pub yields: Yields /* Json | Log */ }
pub struct Connection { pub base_url: Url, pub username: Option<String> /* the row's username: Jenkins user, Confluence email, AWS profile */, pub secret: Option<Secret> /* zeroized on drop; None for aws */ }
pub trait HttpTransport: Send + Sync { async fn send(&self, req: HttpRequest, deadline: Instant) -> Result<HttpResponse, TransportError>; }
pub struct CurlTransport;   // finds curl like pam_model::download::curl_path; writes `--config -` on stdin: url, headers (auth), -sS, --fail-with-body off, --max-time, --max-filesize, --proto =https, -L off; reads status + headers + body; body ≤ MAX_RESPONSE_BYTES (8 MiB JSON / 64 MiB logs)
pub async fn call(id: ConnectorId, conn: &Connection, call: &str, args: &BTreeMap<String, ArgValue>, transport: &dyn HttpTransport, deadline: Instant) -> Result<CallResult, ConnectorError>;
pub enum CallResult { Json(serde_json::Value), Log { name: String, bytes: Vec<u8>, exit_status: Option<i32> } }
pub async fn verify(id, conn, transport, deadline) -> Result<VerifyReport { detail: String }, ConnectorError>;
pub enum ConnectorError { Auth, Forbidden, NotFound, RateLimited { retry_after: Option<Duration> }, Timeout, Certificate, Network(String), Remote { status: u16 }, TooLarge { bytes, maximum }, BadArgs(String), Cli(String) }
impl ConnectorError { pub fn cause(&self) -> &'static str; pub fn recovery(&self, id) -> String }  // "open Pam → Settings → Connectors → GitHub → Test" style lines
```

HTTP mapping (all connectors): 401 → `Auth`, 403 with rate-limit
headers or 429 → `RateLimited`, 403 → `Forbidden`, 404 → `NotFound`,
5xx → `Remote`, curl exit 28 → `Timeout`, curl exit 60/35 →
`Certificate`, other curl failures → `Network`. Redirects are not
followed except GitHub job logs (one hop to an `https://` host, auth
header dropped). Base URLs must be `https://` without userinfo, query
or fragment; private/loopback hosts are allowed (self-hosted Jenkins
and SonarQube live there) — the human types the URL in the GUI.

Read-only calls (arguments in parentheses, `*` required):

| connector | auth | calls |
| --- | --- | --- |
| github | Bearer PAT; `GET /user` verifies | `runs(repo*, status=failure, limit=5)` → `GET /repos/{repo}/actions/runs`; `run(repo*, run_id*)` → run + `/attempts/{n}/jobs`; `job_log(repo*, job_id*)` → `/actions/jobs/{id}/logs` (Log; `exit_status` 1 when the job concluded `failure`, 0 on `success`, unknown otherwise) |
| jenkins | Basic `user:token`; `GET /me/api/json` verifies | `jobs(limit=50)` → `/api/json?tree=jobs[...]`; `builds(job*, limit=20)` → `/{job}/api/json?tree=builds[...]`; `console(job*, build*)` → `/{job}/{build}/consoleText` (Log; `exit_status` from the build `result`) |
| sonarqube | token as Basic user; `GET /api/authentication/validate` must answer `valid: true` | `quality_gate(project*)` → `/api/qualitygates/project_status`; `issues(project*, limit=50)` → `/api/issues/search?resolved=false` (result carries `partial: true` when more remain) |
| jira (Data Center) | Bearer personal access token; `GET /rest/api/2/myself` must carry `name` or `key` | `search(jql*, limit=20)` → `/rest/api/2/search?jql&maxResults&fields=summary,status,issuetype,priority,assignee,updated` (`partial` when `total` exceeds the page); `issue(key*)` → `/rest/api/2/issue/{key}?fields=…` (description cut at 16 KiB, marked partial) |
| confluence (Cloud) | Basic `email:api-token` (split at the first `:`); `GET /rest/api/user/current` must carry `accountId` or `displayName` | `search(cql*, limit=20)` → `/rest/api/content/search?cql&limit&expand=space,version` (`partial` from `totalSize` or `_links.next`); `page(id*)` → `/rest/api/content/{id}?expand=body.storage,space,version` (body cut at 64 KiB, partial) |
| sharepoint (Microsoft Graph) | Bearer Graph token; base URL is the Graph root (sovereign clouds are just another base); `GET /sites/root` must carry `id` | `documents(site*, query*, limit=20)` → `/sites/{site}/drive/root/search(q='{query}')?$top` (query refuses `'`); `lists(site*, limit=20)` → `/sites/{site}/lists?$top` (`partial` from `@odata.nextLink` or a full page) |
| aws | nothing stored; the local `aws` CLI resolves `~/.aws`; optional `profile` (`[A-Za-z0-9_.-]{1,64}`, no leading `-`) stored in the row's `username`; `sts get-caller-identity` must carry `Account` and `Arn` (non-zero exit = `Auth`) | `commands()` → the allowlist itself, no child; `cli(service*, command*, args=[])` → `aws <service> <command> <args…> [--profile P] --output json --no-cli-pager`, stdout ≤ 256 KiB (`partial` when cut), stderr ≤ 4 KiB, 30 s cap, missing binary → `NotFound` with the install line |

JSON responses are capped at 1 MiB (`TooLarge` beyond); every
`partial` flag rides into the step's `connector.result` so a verdict
never claims completeness it does not have.

AWS allowlist, exact `(service, command)` pairs (pam-old's 25):
`sts get-caller-identity` · `ec2 describe-instances`,
`describe-security-groups`, `describe-vpcs`, `describe-subnets` ·
`s3api list-buckets`, `list-objects-v2`, `get-bucket-location` ·
`iam list-users`, `list-roles`, `get-user`, `list-attached-role-policies` ·
`cloudformation list-stacks`, `describe-stacks`, `describe-stack-events` ·
`lambda list-functions`, `get-function-configuration` ·
`logs describe-log-groups`, `describe-log-streams`, `filter-log-events` ·
`ecs list-clusters`, `list-services`, `describe-services` ·
`rds describe-db-instances` · `cloudwatch describe-alarms`,
`get-metric-data`. Prefix heuristics are refused on purpose
(`ecr get-login-password`, `s3 presign` would slip through). Extra args:
≤ 32, ≤ 512 bytes each, no `file://`/`fileb://`, and none of the
daemon-owned flags (`--profile`, `--output`, `--no-cli-pager`,
`--cli-input-json`, `--cli-input-yaml`, `--endpoint-url`, `--debug`).

## Store (`pam_store`)

Migration 5:

```sql
CREATE TABLE connector (
  id TEXT PRIMARY KEY,                       -- github | jenkins | ...
  enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
  base_url TEXT,
  username TEXT,
  last_test_status TEXT CHECK (last_test_status IN ('passed', 'failed')),
  last_test_detail TEXT,
  last_test_ts INTEGER,
  updated_ts INTEGER NOT NULL
);
```

`Store` gains `list_connectors`, `upsert_connector(id, enabled?, base_url?, username?)`,
`record_connector_test(id, status, detail)`; `list_requests_filtered`
gains a `capability: Option<&str>` filter (the Flows run history). No
flow tables: a run is a `request` row (`flow.run`), its verdict an
evidence row.

Settings keys (JSON in `setting`): `flows.allowed_programs` (array,
default `git cargo rustup npm npx pnpm yarn node make go python3 pytest
uv mvn gradle dotnet gh`), `flows.extra_path` (array of directories
prepended to PATH; default macOS `~/.cargo/bin /opt/homebrew/bin
/usr/local/bin`, Linux `~/.cargo/bin ~/.local/bin /usr/local/bin`,
Windows `%USERPROFILE%\.cargo\bin`). A launchd/systemd daemon inherits
a minimal PATH, so without this cargo never resolves.

## Daemon (`pam_daemon`)

### `secrets.rs` — credential store

`SecretStore` over `keyring-core` with the per-OS store selected at
compile time (pam-old's `pam_platform::secrets`, trimmed): service
`dev.pam.connector`, account `pam.connector.v1.<connector id>`;
`get/set/delete` run under `spawn_blocking`; errors sanitized to
`Unavailable | Denied | Missing` (platform text goes to the daemon log
only). A `FakeSecretStore` (in-memory) is injected by tests through
`DaemonConfig::secret_store: Option<Arc<dyn SecretBackend>>`. macOS
warm-up at daemon start (one `get` on a background task, logged with
elapsed ms); no probe on Linux (session-bus hang, memento).

### `connector_service.rs`

Holds the store, the secret store, the transport (`CurlTransport`, or a
fake from `DaemonConfig::http_transport` in tests). `configure(id,
patch)` writes the row and the secret (secret first, row second, one
audit row `connector.configure` with no secret in `detail`);
`test(id)` runs `verify` under a 10 s deadline and records the result;
`invoke(id, call, args, deadline)` refuses `connector_disabled`
("open Pam → Settings → Connectors → enable …"),
`credential_missing`, `store_unavailable` before any network, then
calls `pam_connectors::call`. Secrets live only inside the call.

### `flow_service.rs` — the engine

`FlowService { library: Library, store, approvals, connectors, logs, gate: PolicyGate }`.

`run(ctx: &ExecContext, args) -> Result<CapabilityOutput, CapabilityFailure>`:

1. Args `{ id*, inputs: {k: v} }`; unknown flow → `flow_not_found`
   (recovery: `pam flow list`); invalid file → `flow_invalid` with the
   validation message; inputs without value or default →
   `input_missing`; `caller.repo` must be an existing directory →
   `repo_missing`.
2. Resolve `Vars`: `repo.*`, `inputs.*` (defaults substituted after
   `repo.*`). `repo.origin` runs `git remote get-url origin` only when
   referenced.
3. For each step in order: evaluate `when` (unmet → `skipped`, next);
   substitute variables (unresolvable → step `failed`, cause
   `variable_unavailable`); publish `progress { pct: done/total, note:
   "<id>: running (n/total)" }`.
4. **Step gate.** Stateful command, `approval: required`, or any
   connector step evaluates `PolicyGate::evaluate(profile,
   store.active_grant(name), class)` with `name = "flow.step:<flow>/<step>"`
   and class `Destructive` (stateful/required) or `External`
   (connector). `Allow` → run (auto-grants are audited as today);
   `RequireApproval` → `approvals.request_approval(request_id, name,
   cancel)`; on `Approved` the request row goes back to `running` and
   the step runs; on `Denied`/`TimedOut` the step is `blocked` and the
   flow stops with outcome `blocked`; `Cancelled` → `CapabilityFailure::Cancelled`.
   `Refuse` (strict profile without a grant) → step `blocked` with the
   gate's cause/recovery. The remember checkbox therefore means "this
   step in this flow", which is what a human wants to remember.
5. **Command step.** Program must be in `flows.allowed_programs`
   (else `blocked`, cause `program_not_allowed`, recovery "open Pam →
   Settings → Flows → allowed programs"), resolved on
   `extra_path ++ PATH` (missing → `failed`, `program_missing`).
   `tokio::process::Command`: cwd = `caller.repo`, stdin null,
   stdout+stderr piped and interleaved into one buffer in arrival
   order, env = daemon env minus names matching
   `(?i)token|secret|password|passwd|credential|api_key|apikey|private_key`
   plus `PATH`, the step `env`, `GIT_TERMINAL_PROMPT=0`,
   `GIT_ASKPASS`/`SSH_ASKPASS` = false, `PAM_FLOW=<id>`, `PAM_STEP=<id>`,
   own process group on unix (`process_group(0)`), `kill_on_drop`.
   Timeout → kill the group, step `failed` (`timeout`); output over
   `MAX_SOURCE_BYTES` (64 MiB) → kill, `failed` (`output_limit`); cancel
   signal → kill, `CapabilityFailure::Cancelled`. Exit 0 = succeeded,
   else failed (`exit_status`). Retry: on `failed` with attempts left,
   sleep backoff × 2^(n−1) (cap 60 s, cancel-aware), re-run; attempts
   are counted in the verdict.
6. **Connector step.** `connectors.invoke(...)` under the step timeout;
   `Json` → evidence `connector.result` (JSON, meta `{connector, call,
   args}`), and the value is exposed to later steps as
   `steps.<id>.result`; `Log` → treated like command output.
   `ConnectorError` → step `failed` with the error's cause/recovery;
   `RateLimited` retries honour `retry_after` when it fits the step
   timeout.
7. **Output.** `compact`/`summarize` → `LogService::compress(request_id,
   { name: "<flow>/<step>", bytes, exit_status, use_model: summarize })`;
   the step records the evidence ids and, for `summarize`, the summary
   text (or `model_skipped`). `discard` keeps nothing. Empty output is
   not compressed.
8. **Verdict.** Outcome: any step `blocked` → `blocked`; any `failed`
   (after retries) → `unresolved`; else `changed` when a stateful step
   ran, else `verified` when a `verify` step ran, else `solved`. Summary
   sentence (deterministic): "7 steps: 6 succeeded, 1 failed (clippy,
   exit 101)" plus the failing step's summary text when it has one.
   Body:

```json
{ "flow": { "id", "name", "source": "builtin|library", "digest" }, "repo", "inputs": {},
  "outcome", "summary",
  "steps": [ { "id", "kind": "command|connector", "status": "succeeded|failed|skipped|blocked|cancelled",
               "attempts", "duration_ms", "exit_status", "evidence": ["ev_…"], "summary", "error": { "cause", "detail", "recovery" } } ] }
```

   The body is also written as evidence `flow.result` (meta `{ flow,
   outcome, steps, failed }`), so the GUI's run history reads it
   without re-running anything; `CapabilityOutput.evidence` lists every
   id the run produced. The pipeline writes the terminal audit row as
   for any capability, with `detail = { flow, outcome, steps_failed }`.

`list(ctx)` → `{ flows: [ { id, name, description, source, valid, error?, steps, inputs: [...] } ] }`
(outcome `verified`); `show(ctx, { id })` → `{ id, source, yaml,
normalized_yaml, digest, valid, error? }`.

Capabilities: `flow.run` classifies `NonDestructive` (a flow is a
recipe; its steps carry their own class), `flow.list` and `flow.show`
`ReadOnly`. `BuiltinCapability` gains `FlowRun`, `FlowList`,
`FlowShow`; `ExecContext` gains `flows: Arc<FlowService>` and
`caller: Caller`.

### Admin ops (GUI-only, same intercept)

| op | args | answer |
| --- | --- | --- |
| `admin.flows.list` | — | `{ flows: [ { id, name, description, source, path?, valid, error?, digest, steps, inputs } ] }` |
| `admin.flows.get` | `{ id }` | `{ id, source, path?, yaml, normalized_yaml, digest, valid, error?, flow: <Flow as JSON> }` |
| `admin.flows.save` | `{ id, yaml }` | the list entry; refusals `flow_invalid` (message + path), `id_mismatch`, `library_unwritable` |
| `admin.flows.delete` | `{ id }` | `{ id, revealed_builtin: bool }`; `not_found` for a builtin without a shadow |
| `admin.flows.run` | `{ id, repo, inputs }` | `{ ticket, position }` — builds a `flow.run` envelope with caller `{ agent: "pam-gui", repo }`, `wait: false`, and submits it through the pipeline ingress (gate, lanes, audit all apply); the GUI follows the ticket's events |
| `admin.flows.settings.get` / `.set` | — / `{ allowed_programs?, extra_path? }` | `{ allowed_programs, extra_path }`; shells refused with `program_not_allowed` |
| `admin.connectors.list` | — | `{ connectors: [ { id, name, auth, enabled, base_url, username, credential_present, store_available, last_test } ] }` |
| `admin.connectors.configure` | `{ id, enabled?, base_url?, username?, credential?: { set: string } \| { clear: true } }` | the list entry; `bad_url`, `store_unavailable`, `store_denied` |
| `admin.connectors.test` | `{ id }` | `{ status: passed\|failed, detail, ts }` |

Bridge deadlines: `admin.connectors.test` 15 s, the rest 30 s.

## CLI (`pam`)

`pam flow` is the one dynamic surface the spine spec allows.

```
pam flow list [--json]                       flow.list   → table: id · source · steps · name (invalid ones say why)
pam flow show <id>                           flow.show   → the normalized YAML
pam flow run <id> [k=v]... [--no-wait] [--deadline-ms N] [--json]   flow.run
```

`run` defaults `deadline_ms` to 1 800 000 (30 min) — a flow that runs
`cargo test` is not a 60 s request. Human rendering: one line per step
(`✓ clippy  verified  4.2s`, `✗ test  failed  exit 101  ev_…`,
`· docs  skipped`), then the summary sentence and the summary text for
`summarize` steps; refusals render as today. Exit codes reuse
`render::exit_code` (0 / unresolved 4 / blocked 5 / refused 3).
Progress events print as they arrive when waiting (`→ clippy (5/7)`),
quiet under `--json`.

## GUI (`pam_gui` + frontend)

- Bridge: `ADMIN_OPS` splices `FLOW_ADMIN_OPS` and `CONNECTOR_ADMIN_OPS`
  (daemon-owned lists); `ipc.ts` grows the `AdminOp` union and typed
  wrappers.
- **Flows screen** (`/flows`, sidebar entry replaces the "soon"
  placeholder): a library column (id, name, `builtin`/`library`
  badges, an invalid badge with the message) and a detail pane with
  tabs **YAML** (textarea in the data voice; Validate, Save, Clone —
  a builtin's Save becomes Clone with a new id —, Delete with the
  confirm button; errors render as a `FailureNote` naming the path)
  and **Runs** (the flow's `flow.run` requests newest-first with
  outcome badge, repo tail, age; a row expands into the step table
  from the `flow.result` evidence and the existing `EvidenceStrip`).
  A **Run** button opens an inline card: repo picker (known callers'
  repos, free text allowed), one field per declared input with its
  default, Run → the ticket's events drive a step progress line, the
  finished verdict card lands in place with the outcome chip. Plan #6
  adds the canvas tab next to YAML.
- **Settings › Flows**: allowed programs as removable chips plus an
  add field (shells refused with the daemon's message), extra PATH
  rows.
- **Settings › Connectors**: one row per connector: enabled toggle,
  base URL, username where the auth kind has one, credential field
  (password input; Set / Clear), Test, badges `credential set`,
  `store unavailable`, last test result with relative time. Copy
  distinguishes "no credential stored", "store unavailable", "access
  denied" (pam-old lesson). AWS shows the profile hint instead of a
  secret.
- **Approvals**: `approvalMeaning` gains the `flow` family: "The flow
  <flow> asks to run step <step> …" with the step kind.
- Frontend tests (vitest) mock `ipc` for the library list, the editor
  save/clone/delete paths, the run card and verdict, the runs history
  expansion, both settings panels, the approvals copy; the bridge test
  asserts every new op forwarded and unknown ops refused.

## Testing

- `pam_flow`: parse/validate every rule above (each rejection names
  its path), normalized YAML is stable and round-trips, digest changes
  with content only, builtins all parse, library list/get/save/delete
  with shadowing, atomic save leaves no temp file, variable
  substitution and `steps.*` pointers.
- `pam_connectors`: per connector a fake transport proving each call's
  request (method, path, query, headers with the right auth shape),
  response parsing, bounds, and the error mapping table; `CurlTransport`
  against a local plain-HTTP origin in a test (the curl config is
  exercised for real: headers, max-time, max-filesize; the `--proto`
  rule is asserted from the generated config) — skipped with a clear
  message when `curl` is absent; AWS allowlist and argv building with a
  fake `aws` script on PATH.
- `pam_store`: migration 5 on a v4 database, connector upsert/list/test
  round-trip, capability filter.
- `pam_daemon` (testkit, allowlist seeded with `git` and a test helper
  program): `flow.list`/`show` for builtins; a library flow shadows a
  builtin; a two-step command flow → `verified` with evidence rows and
  a `flow.result` body that matches; failing step → `unresolved` with
  exit status and retries counted; `when` skipping; step timeout kills
  the child (a sleeping helper) and the run ends `unresolved`; output
  over the cap; cancellation mid-step kills the child; program not
  allowed → `blocked`; stateful step under relaxed pauses, resolves via
  `handle.approvals()` with remember → second run does not pause; deny
  → `blocked` with one approval audit row and one terminal row; a
  connector step with the fake transport → `connector.result` evidence
  and `steps.*` substitution in the next step; disabled connector →
  `blocked` with the Settings recovery line; secrets: fake store
  set/clear through `admin.connectors.configure`, audit detail carries
  no secret, `admin.connectors.test` records the result; tripwire on
  every admin op; `admin.flows.run` submits through the gate (the
  request row has `caller_agent = pam-gui`, the chosen repo, one audit
  row). Opt-in `PAM_BENCH_MODEL` test: `output: summarize` yields a
  `log.summary` row.
- CLI (`crates/pam/tests/cli.rs`): `flow list`, `flow show`, `flow run`
  exit codes and the `--json` bodies against a testkit daemon.
- Gate: `tools/check.sh` green on the settled tree before every PR; CI
  green on all five targets after every merge; the C-free check
  (`cargo tree -e normal,build | grep -E '^(cc|cmake|onig_sys|esaxx-rs|ring|aws-lc-sys|openssl-sys|dbus)'`)
  prints nothing after the keyring and yaml crates land.

## Waves

| Wave | Tasks | Disjoint file sets |
| --- | --- | --- |
| 1 | `pam_flow` crate · `pam_connectors` crate · store migration 5 + connector rows + capability filter · `secrets.rs` + keyring deps | `crates/pam_flow/**` · `crates/pam_connectors/**` · `crates/pam_store/**` · `crates/pam_daemon/src/secrets*.rs` (+ root `Cargo.toml` members, coordinated) |
| 2 | `ConnectorService` + `admin.connectors.*` | `crates/pam_daemon/**` (connector files, admin_connectors, daemon wiring) |
| 3 | `FlowService` + capabilities + `admin.flows.*` + policy/executor wiring | `crates/pam_daemon/**` (flow files, executor, policy, daemon) |
| 4 | CLI `pam flow` · GUI (Flows screen, Settings panels, approvals copy, bridge) | `crates/pam/**` · `crates/pam_gui/**`, `frontend/**` |
| 5 | Starter flows end to end on the owner's bench (GitHub + Sonar real, the rest fake-transport) · integrate and verify | — |
