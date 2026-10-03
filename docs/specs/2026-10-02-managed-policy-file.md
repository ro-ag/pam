# Managed read-only policy file — design and implementation plan

Status: implemented; the Windows VM verification (T13 step 2) is done and recorded in
[Evidence to record](#evidence-to-record); the owner's macOS pass on the real
install path is done and recorded there (item 7, 2026-10-03).
Built on `feat/managed-policy` (T1–T12), 2026-10-02/03. What was built, and
where it departs from the design below, is in [As built](#as-built-2026-10-03);
where the two disagree, As built is the behavior. The administrator's guide is
[docs/policy/README.md](../policy/README.md).

Designed 2026-10-02 (ptrack plan 54). Implements the owner
directive of 2026-10-02 ("do what is best for the product and make it easy for
enterprise environments") for the one item the network spec deferred: a policy
an organisation delivers with its MDM, which the human at the keyboard and the
agent in the sandbox can read but not change. Companion to
[the enterprise network spec](2026-10-02-enterprise-network-and-engine-delivery.md)
(its "Policy layer" section built the overlay hook this plan fills in),
[the administration boundary](../admin-boundary.md) and
[scoped admission](../scoped-admission-and-budgets.md).

Supported platforms: macOS arm64 and Windows amd64/arm64 (owner scope change,
2026-10-02). Nothing here is designed or tested for Linux or Intel macOS.

Line references are to the working tree on `feat/enterprise-network` (HEAD
2708857). The network files this plan edits (`network_service.rs`,
`admin_network.rs`) belong to plan 52; implementation starts after that branch is
squash-merged, on a new branch (`feat/managed-policy`; never a `codex/` prefix).
Re-anchor line numbers before editing.

## Goal and non-goals

Goal: an administrator can push one small file to every endpoint, check it before
the push, see which machines accepted it, and know that (a) a human or an agent
cannot change what it governs, (b) a damaged or half-delivered file can neither
silently lift a restriction nor take the fleet's tooling down, and (c) every
person sees in the GUI which settings are managed, by whom, and why.

In scope:

1. One read-only policy file per platform at a root/Administrators-owned location,
   verified before it is trusted, strict schema, versioned.
2. A `PolicyHandle` every settings consumer reads through: the effective value is
   `policy over user over default`, computed at read time; the user's stored values
   are never rewritten.
3. Managed semantics (`locked`, `default`, `floor`/`min`/`max`, `allow`, and
   policy-only constraints) for every settings document in the store.
4. The `source`/`locked` shape on every admin `get`, a `policy` block in `status`,
   a Settings page, and audit rows carrying the policy digest.
5. A two-tier rule for a damaged file, with a last-known-good copy.
6. `pam policy check`, an offline read-only linter and compliance probe.

Not in scope (see [Decisions](#decisions) and [Open questions](#open-questions)):
per-user or per-group policy (the MDM scopes the file to devices); a signed
policy or a remote fetch (the file is root-owned; the OS is the signature); a
macOS configuration-profile (`/Library/Managed Preferences`) or Windows registry
(`HKLM\SOFTWARE\Policies`) reader, which are later transports for the same
document; ADMX/ADML templates; secrets in the policy (the file is world-readable
by design); stopping a determined local administrator who can run a different
binary (that is application allow-listing, the MDM's job).

## Current state

Every setting is a row in the `setting` table (`pam_store/src/migrations.rs:335`,
`key TEXT PRIMARY KEY, value TEXT`), read and written by the service that owns it.
There is no shared policy layer; the network document alone has a hook.

| Setting key | Owner | Read at | Written by (admin op) |
| --- | --- | --- | --- |
| `policy.profile` | `PolicyGate` | read once at `PolicyGate::new` (`policy.rs:250`), live copy in the gate; `profile()` serves the gate, `admin.profile.get` (`admin.rs:473`), flow gating (`flow_service.rs:749`, `:909`), watch stamps (`flow_watch_runtime.rs:98`), `status` (`daemon.rs:2550`) | `admin.profile.set` -> `set_profile` (`admin.rs:483`, `policy.rs:287`) |
| grants (`grant` table) | store + gate | `evaluate_classified` (`policy.rs:328`) | `admin.grants.add/revoke` (`admin.rs:535`, `:561`); `admin.approvals.resolve { remember }` (`admin.rs:799`; the grant row is inserted by the approval service, `approval.rs:454`) |
| `flows.scope_policy` | `ScopePolicy` | **nine direct `ScopePolicy::load(store)` callers**: `flow_recovery.rs:88`, `:498`, `flow_service.rs:570`, `connector_landing_git.rs:194`, `flow_landing_runtime.rs:301`, `evidence_service.rs:179`, `:223`, `flow_result_service.rs:184`, `:238`, `connector_service.rs:647` | `admin.flows.settings.set` (`admin_flows.rs:594`) -> `set_scope_policy` (`flow_service.rs:589`) |
| `flows.allowed_programs`, `flows.extra_path`, `flows.artifacts_root`, `flows.read_cache_roots` | `FlowService` | `settings()` (`flow_service.rs:533`), one reader | `admin.flows.settings.set` -> `set_settings` (`flow_service.rs:621`) |
| `flows.landing_policy` | `landing_policy.rs` | `load` (`landing_policy.rs:268`) | `admin.flows.landing.set` |
| `retention.evidence_days`, `retention.audit_days` | `RetentionService` | `settings()` (`retention.rs:373`), one reader; scheduler + `run_pass` (`:446`) | `admin.retention.set` -> `set_settings` (`retention.rs:416`) |
| `model.models_dir`, `model.idle_unload_min`, `model.default.*`, `curator.agent` | `ModelService`, `admin_models.rs` | `models_dir()` (`model_service.rs:1052`), `idle_unload_min()` (`:1641`), `selected_agent` (`admin_models.rs:1066`) | `admin.models.settings.set` (`admin_models.rs:830`), `admin.curator.set` (`:965`) |
| `net.settings` (+ keychain `network.proxy`) | `NetworkService` | `load()` (`network_service.rs:641`) through `resolve()` (`:424`); **the only layer with a policy hook**: `ManagedNetwork` (`:265`), `ManagedNetworkLayer` (`:285`), `Source` (`:323`), `with_managed` (`:575`) | `admin.network.set` (`admin_network.rs`), refusing `setting_locked` (`admin_network.rs:239-257`) |
| connector rows (enabled, base URL, user name) | `ConnectorService` | `connector_service.rs` | `admin.connectors.configure` (`admin_connectors.rs:32`) |
| login unit | `pam_client::service` | `service::status` | `pam service install` / GUI bridge; user-scope only (`service.rs:3`, LaunchAgent label `com.github.ro-ag.pam.daemon` `:24`, scheduled task `pam\daemon` `:34`) |

Facts the design rests on:

- **The store belongs to the user.** `~/.pam` is validated as owned by the
  daemon's uid (`admin_transport_unix.rs:91-143`) and the admin plane is proved by
  uid/possession (`admin-boundary.md`, "The private endpoint"). Anything the
  overlay rewrote would be rewritten in a file its victim owns. So policy is an
  overlay computed on read and is never persisted into the user's rows; removing
  the policy restores what the user had (as the network spec already states,
  "Policy layer", fourth bullet).
- **No new authority surface.** All writes go through admin ops that are
  GUI-only, tripwired, audited (`admin.rs:379-399`, `:1080-1106`). A refusal
  already writes an `admin`/`refuse` audit row with the cause and detail
  (`finish_refused`, `admin.rs:1080`).
- **Audit rows need a request row.** `audit.request_id REFERENCES request(id)`,
  `actor IN ('policy','human','system')`, `decision IN ('allow','refuse',...)`
  (`migrations.rs:286-296`). A boot-time policy event has no request, so it
  creates one (below). The store has two ingress values only (`public`, `admin`;
  `migrations.rs:153`); adding a third would rebuild the `request` table for a
  label, so daemon-originated rows use `ingress = admin`, `caller_agent =
  pam-daemon`, `capability = policy.load` (the tripwire's expected agent is
  `pam-gui`, so these can never be mistaken for a GUI act).
- **Windows has no ownership read without `unsafe`.** The workspace sets
  `unsafe_code = "deny"` (`Cargo.toml:93`). The trusted-curl code says so
  directly and falls back to a fixed path (`pam_net/src/trusted.rs:302-310`);
  the CA import's ownership rule is `#[cfg(unix)]` only
  (`network_service.rs:1006-1008`, `:1036`).
- **The daemon's environment is not trusted.** A lazily started daemon gets an
  allowlisted copy of the caller's environment that includes `ProgramData`
  (`pam_client/src/client.rs:580-604`) and an explicit `PAM_BASE_DIR`. An agent
  chooses both. The policy location therefore never comes from the environment,
  a flag or `<base>`.

## Design

### Principles

1. **Fixed location, no override.** The path is a constant per platform. No
   environment variable, flag, `<base>` file or admin op can move it. Tests
   inject a `PolicySource` through `DaemonConfig` (like `secret_backend`,
   `DaemonConfig`, `daemon.rs:528-552`), which no production code path sets.
2. **Verify, then read, on one handle.** Trust is judged on the opened file
   handle, not on a path that can change between the check and the read.
3. **Overlay at read.** `effective = policy.locked ?? clamp(user, policy) ??
   policy.default ?? builtin default`, computed by the one `PolicyHandle` every
   consumer reads, never by a consumer reading its own document and applying
   policy afterwards. The compiler enforces it: the raw loaders become
   `pub(crate)` for the admin edit path only (see T6).
4. **Enforce on read and refuse on write.** A tightened policy applies to the
   next read with no migration; a refused write tells the human why instead of
   silently not sticking.
5. **A bad file never loosens anything.** Section [A damaged file](#a-damaged-file-the-two-tier-rule).
6. **Policy-only keys are plain values; keys the human also has are mode objects.**
   Section [File format](#file-format).

### Where the file lives

| Platform | Path | Written by | Why this place |
| --- | --- | --- | --- |
| macOS | `/Library/Application Support/PAM/policy.json` | MDM package or root script, `root:wheel`, `0644`, directory `0755` | The conventional place for files an MDM (Jamf, Kandji, Intune, Mosyle) drops system-wide. Checked on this machine: `/Library` is `root:wheel 0755` and `/Library/Application Support` is `root:admin 0755` (group has no write). |
| Windows | `%ProgramData%\PAM\policy.json` | Intune platform script / Win32 app / GPO startup script as SYSTEM | `%ProgramData%` is the machine-wide, per-machine data root. Its default ACL lets `Users` create files in new subfolders, so the folder must have inheritance cut and a locked ACL (delivery script below); that is exactly why PAM verifies the ACL instead of trusting the location. |

On Windows the daemon may have a caller-influenced `ProgramData` (see above):
the value is used only when it matches `^[A-Za-z]:\\ProgramData$`
(case-insensitive); otherwise `C:\ProgramData`. The trust check below applies to
whatever path results, so a drive an agent controls is simply untrusted.

Files a policy refers to (a CA bundle) are any absolute path and pass the same
trust check, individually and with the same rules. By convention they sit beside
the policy (`.../PAM/ca/corp-root.pem`).

**Alternatives evaluated.**

| Delivery | For | Against | Verdict |
| --- | --- | --- | --- |
| File under `/Library/Application Support/PAM` (macOS) | Every MDM can push a file (pkg or script); trust model is POSIX ownership we can read with std; one grammar | Not a native "profile" an MDM console displays as a setting | **Recommended** |
| `/Library/Managed Preferences/com.github.ro-ag.pam.plist` (Configuration Profile, Custom Settings payload, domain = the bundle id `crates/pam/tauri.conf.json:5`) | The most MDM-native macOS channel; the OS writes it root-owned | Needs a plist reader (`plist` crate, a new dependency); plist types differ from JSON; per-user variants (`/Library/Managed Preferences/<user>/`) invite scope creep | Later transport (decision D8); same document, new `PolicySource` |
| File under `%ProgramData%\PAM` + ACL verification (Windows) | No dependency, no `unsafe`; same grammar and test matrix as macOS; Intune scripts run as SYSTEM | The ACL verification is an effective-access probe, not an owner read (below) | **Recommended** |
| `HKLM\SOFTWARE\Policies\PAM` registry values (GPO ADMX, Intune Settings Catalog / ADMX ingestion) | The native Windows channel; the key is admin-write-only by default so trust is intrinsic; no file ACL to get wrong | Needs `winreg` or `windows-sys` (new dependency; `unsafe` lives in the crate, not ours); one registry value per leaf duplicates the schema in ADMX; 32/64-bit views | Later transport carrying the identical JSON in one `REG_SZ` (`PolicyJson`), so one grammar and one test matrix (D8) |

### The trust check

`managed_policy_trust.rs` exposes one function,
`verify_and_read(path, &TrustRules) -> Result<TrustedBytes, Untrusted>`, used for
the policy file and for any file it names. `TrustRules::production()` is the only
constructor non-test code calls; tests build `TrustRules::owned_by(uid)` (macOS)
or an expected-ACL rule (Windows). No `unsafe`; no new dependency.

**macOS (and any unix) rules**, all by `std::fs` and
`std::os::unix::fs::MetadataExt`:

1. `symlink_metadata(path)`: not a symlink, a regular file.
2. Open it read-only; compare the handle's `(dev, ino)` with step 1's. A swap
   between the stat and the open is refused. (This replaces `O_NOFOLLOW`, which
   would need a libc constant.)
3. On the handle: `uid == 0`; `mode & 0o022 == 0` (no group or world write);
   `mode & 0o7000 == 0`.
4. Every ancestor of the canonical path, to `/`: `symlink_metadata`, a directory,
   not a symlink, `uid == 0`, `mode & 0o022 == 0`. This is the rule
   `pam_net/src/trusted.rs:285-300` already applies to `/usr/bin/curl`, without
   the sticky exemption `validate_ancestors` allows for temp directories
   (`admin_transport_unix.rs:110-123`), which a policy has no business in.
5. A belt-and-braces effective-access probe: try to open the file for write
   (`OpenOptions::write(true)`, never `create`, `truncate` or `append`, closed at
   once). If it succeeds, an ACL or a privilege the mode bits did not show lets the
   daemon's user modify the file: untrusted. It modifies nothing (an open without
   truncation changes neither content nor mtime). If the daemon runs as root the
   probe succeeds and the policy is untrusted by design: PAM does not run
   privileged.
6. Size: read at most 64 KiB + 1 bytes from the handle; one more byte is
   `policy_too_large`.

Known residual, stated: an extended ACL on a *parent directory* that grants the
daemon user write is not visible to `std` (no `acl_get_file` without FFI). The
parent probe is the Windows one below; on macOS the delivery guidance does not
use ACLs and `pam policy check --installed` plus the doctor check report mode
bits only. The probe in step 5 catches the file-level case.

**Windows rules.** Windows exposes no owner or DACL to safe `std`, so PAM asks the
operating system the question that matters instead: *can this process's own token
modify the file?* `std::os::windows::fs::OpenOptionsExt::{access_mode,
share_mode, custom_flags}` are safe and stable. An open with `access_mode(X)` and
`OPEN_EXISTING` succeeds only if the token holds right `X`, and an open with no
write disposition changes nothing.

1. `symlink_metadata` of the file and of the policy directory:
   `file_type().is_symlink()` is false for both (it is true for a symlink and for
   a junction, which is how `std` reports any reparse point of those tags), and
   the file is a regular file. The canonical path equals the expected path (so a
   directory junction is also caught).
2. For the **file**, each open must FAIL with access denied:
   `FILE_WRITE_DATA (0x2)`, `FILE_APPEND_DATA (0x4)`, `DELETE (0x10000)`,
   `WRITE_DAC (0x40000)`, `WRITE_OWNER (0x80000)`. (`WRITE_DAC` and `WRITE_OWNER`
   cover the owner's implicit right: a token that could rewrite the ACL or take
   ownership has them.)
3. For the **policy directory**, opened with `custom_flags(0x0200_0000)`
   (`FILE_FLAG_BACKUP_SEMANTICS`, required to open a directory), each of
   `FILE_ADD_FILE (0x2)`, `FILE_ADD_SUBDIRECTORY (0x4)`, `FILE_DELETE_CHILD
   (0x40)`, `DELETE`, `WRITE_DAC`, `WRITE_OWNER` must FAIL; for `%ProgramData%`
   itself, `FILE_DELETE_CHILD`, `DELETE`, `WRITE_DAC` must FAIL (the folder's
   default ACL lets `Users` add subfolders but not remove or re-ACL them).
   Measured 2026-10-03: a directory open without `FILE_FLAG_BACKUP_SEMANTICS`
   fails with access denied whatever the token holds, so omitting the flag
   would read as "safe". Also, `FILE_DELETE_CHILD` on the folder satisfies a
   `DELETE` open on the files inside it, so a token with only that right is
   refused by the file probe (`writable_by_user`) before the folder probe runs
   (`parent_writable`). Either way it is untrusted.
4. The file is read through the opened handle with `share_mode(FILE_SHARE_READ)`,
   so no writer holds it open during the read. A sharing violation (an MDM
   agent mid-write) is a transient `busy`: the previous view stays and the next
   poll retries.

What this proves and what it does not (recorded in the doctor output and the
guide):

- Proves: the daemon's own token, with every group in it, cannot modify, delete,
  re-ACL, chown or replace the file or its directory. That is the property
  PAM needs against the agent (which runs as the same user) and against the
  human at the keyboard.
- Does **not** prove the owner is `SYSTEM`/`Administrators`, and cannot see an ACE
  that grants write to a *different* user account. On a single-user endpoint that
  gap is empty; on a shared machine (kiosk, RDS) it is not. The macOS rule reads
  the owner directly; the Windows rule cannot. Fixing it needs
  `GetNamedSecurityInfo` (a Win32 call: `unsafe` or a platform crate), which is an
  owner decision (Open question 1).
- A daemon running elevated (a user who runs PAM "as administrator") holds every
  right and reads **untrusted**, as a root-run daemon does on macOS.

Every rule above was a hypothesis about Windows behaviour. The Windows VM task
(T13) proved each one on 2026-10-03; the corrections it forced are marked
"measured" in the rules and listed in [Evidence to record](#evidence-to-record).
The CLI's `--trust` judges the fixed path exactly as spelled, never with its
parent resolved, because resolving it would hide a junction at
`%ProgramData%\PAM` that the daemon refuses.

### File format

JSON, UTF-8. It is the format the repo already parses everywhere (`serde_json`);
YAML exists only for flow files (`serde_yaml_ng`, `Cargo.toml:87`) and is wrong
for a security document (implicit typing: `no`, `0775`, `1.10`); TOML would be a
new dependency. A leading UTF-8 BOM is accepted and stripped, because Windows
PowerShell 5.1 `Set-Content -Encoding UTF8` writes one; the digest is over the
raw bytes. JSON has no comments, so the schema has a `comment` string.

Limits: 64 KiB; strings at most 1,024 bytes; lists at most 256 entries;
`reason` at most 200 characters. **Duplicate keys at any depth are an error**
(`serde_json` silently keeps the last; parsers disagree, and the admin's intent is
ambiguous), implemented with a small strict-map visitor.

**Grammar.** Top level: `version` (integer, must equal a version this binary
reads; v1 is the only one), then optional `revision` (string, shown in status and
audit; an admin's own label), `organization` (shown in the GUI), `contact` (shown
in refusals), `comment`, and the sections `security`, `scopes`, `connectors`,
`flows`, `landing`, `models`, `retention`, `network`, `service`. Every key is in
a closed table; an unknown key is a *rejected leaf*, never ignored.

A leaf is one of:

- a **mode object** where the human has a setting of the same name:
  `{ "locked": V }`, or any of `{ "default": V, "floor"|"min"|"max": N, "allow":
  [..] }` (`locked` excludes every other mode; `default` combines with the
  others), plus an optional `reason`; or
- a **plain value** for a constraint only the policy can state (`never`,
  `mirror_allowed_hosts`, `allowed_*`, `max_permissions`, `engine_source`).

Modes: `locked` = value forced and the field read-only; `default` = applied until
the human sets their own; `floor` (ordered enum: the human may choose this level
or stricter) and `min`/`max` (numbers) = a bound the human stays inside; `allow` =
the human's list is intersected with this set.

Version rule: within a version the schema only ever loses or keeps keys, never
gains one. A new key means a new `version`; an older PAM that reads a newer file
treats it as `policy_version_unsupported` (a file-level failure, handled by the
two-tier rule below) and the status line names both versions, so a mixed-version
fleet degrades to "last known good" instead of "silently half-applied".

**Sample (macOS).**

```json
{
  "version": 1,
  "revision": "2026-10-02.1",
  "organization": "Example Corp",
  "contact": "it-help@example.com",
  "comment": "Engineering laptops baseline",
  "security": {
    "profile": { "floor": "standard", "reason": "SEC-114" },
    "grants": {
      "manual": "allow",
      "remember": "deny",
      "never": ["flow.step:*/merge", "flow.step:*/deploy"],
      "never_classes": ["external"]
    }
  },
  "scopes": {
    "allowed_repository_roots": ["/Users", "/Volumes/Work"],
    "connector_wide": "deny"
  },
  "connectors": {
    "allowed_base_hosts": ["*.example.com"],
    "disabled": ["jira"]
  },
  "flows": {
    "programs": { "allow": ["git", "cargo", "npm", "node", "make"] },
    "extra_path": { "allow": ["/opt/homebrew/bin", "/usr/local/bin"] },
    "artifacts_root": { "default": "~/pam-artifacts" }
  },
  "landing": {
    "max_permissions": { "merge": false },
    "allowed_github_servers": ["github.example.com"]
  },
  "models": {
    "engine_source": "mirror_only",
    "allowed_sources": ["catalog", "import"],
    "allowed_curators": [],
    "idle_unload_min": { "default": 10, "max": 60 }
  },
  "retention": {
    "evidence_days": { "max": 90 },
    "audit_days": { "min": 365 }
  },
  "network": {
    "proxy": { "locked": { "url": "http://proxy.example.com:8080", "auth": "none" } },
    "no_proxy": { "locked": ["*.example.com", "10.0.0.0/8"] },
    "ca_bundle": { "locked": { "path": "/Library/Application Support/PAM/ca/corp-root.pem",
                               "sha256": "<64 hex characters>" } },
    "engine_mirror": { "locked": "https://artifacts.example.com/llama.cpp" },
    "models_mirror": { "default": "https://artifacts.example.com/hf" },
    "mirror_allowed_hosts": ["artifacts.example.com"]
  },
  "service": { "require_login_unit": true }
}
```

(A Windows file differs only in paths: `C:\\Program Files\\...`, `C:\\ProgramData\\PAM\\ca\\...`.
`pam policy check --for windows` validates path syntax for the target platform
regardless of the machine running the check.)

### A damaged file: the two-tier rule

States the daemon and `status` report: `none` (no file), `active` (trusted, every
leaf accepted), `degraded` (trusted, some leaves rejected), `last_good` (the file
could not be used as a whole; the last good policy is in force), `frozen` (the
file could not be used and there is no last good policy).

**Classification of a failure.**

- *File-level*: untrusted (any trust rule), unreadable, over 64 KiB, not JSON,
  duplicate keys, unsupported `version`. Every leaf is lost at once.
- *Leaf-level*: the file parses but a leaf is rejected: unknown name, wrong type,
  or failed semantic validation (a mirror host `pam_net` refuses, a program that is
  a shell, a retention pair that breaks "evidence may not outlive audit", a CA
  digest that does not match).

**Resolution, per key, one chain:**

```
valid in this file  ->  that value
else valid in the last-known-good policy  ->  that value (state degraded / last_good)
else by the key's tier:
    Tier A (authority, audit, egress):   HOLD
    Tier B (convenience):                unmanaged: the user's value stands, a diagnostic is shown
```

**HOLD** means: the key is reported as managed-but-unresolved; writes to it are
refused with `policy_frozen` (the same cause for every held key); and nothing
loosens. For a leaf whose *intent is known* (it was present and rejected) three
network keys also close their consumers: a rejected `network.proxy`, `no_proxy` or
`ca_bundle` with no last-good value makes connector calls and downloads refuse
`network_policy_invalid` (as built a new `NetFailure::PolicyInvalid`; the
corrupt-proxy refusal it was modelled on is `network_settings_invalid`;
`network_service.rs`, module docs: "falling back to a direct connection on
a corrupt proxy setting would send traffic around a proxy the organisation
requires"). Nothing else stops: flows, the gate, the GUI and agents keep working.
For a *file-level* failure with no last good policy the intent is unknown, so
nothing is refused for consumers; Tier A writes freeze, the rest is unmanaged,
and the status says `frozen`.

**Tiers.** A: `security.*`, `scopes.*`, `connectors.*`, `flows.programs`,
`flows.extra_path`, `flows.read_cache_roots`, `landing.*`, `models.allowed_sources`,
`models.allowed_curators`, `retention.*`, `network.proxy`, `network.no_proxy`,
`network.ca_bundle`. B: `flows.artifacts_root`,
`models.dir`, `models.idle_unload_min`, `models.engine_source`, `network.engine_mirror`,
`network.models_mirror`, `network.mirror_allowed_hosts`, `service.*`, and the
meta keys. Why this split, key by key:

- A key is Tier A when its failure direction is *exposure*: it widens what an
  agent may run, read, reach or ship (profile, grants, scopes, programs, PATH,
  cache mounts, curator CLI egress, connector hosts that receive a credential,
  landing permissions, custom-URL weights with no pinned digest) or shortens the
  record of it (retention). Locking the profile to `strict` and then corrupting the
  file must not return the machine to `relaxed`: the last-known-good value holds.
- A key is Tier B when its failure direction is *inconvenience*: a typo in a mirror
  host (`engine_mirror`) falls back to the user's value or upstream, and that is
  bounded by the digests pinned in the binary (the engine archive and the catalog
  weights are verified by SHA-256 whatever the source; `engine.rs`, the engine
  spec "Downgrade of the pinned digest"). The fleet's tooling keeps working and
  the diagnostic tells the administrator what to fix.
- The three proxy keys are Tier A *with closed consumers* because the failure
  direction of a bad proxy is bypass (direct traffic), the one network failure the
  existing design already refuses to fail open on.

**The last-known-good copy.** After a fully verified load, the daemon stores the
exact policy bytes with their digest and time in the `setting` row
`policy.last_good` (bounded read, 70 KiB; written after the audit row, before the
view swaps; a failed write logs and sets `lkg_persist_failed` in the status but
does not block the swap). On a file-level or leaf-level failure the stored bytes
are re-validated by the *current* binary through the same pipeline (so a schema
bump that no longer accepts them degrades to `frozen`, never to a crash). The
row is written only by the daemon from a trusted file; it carries no authority
the store does not already carry (whoever edits it can edit grants).

**Absence.** No file is `none`: unmanaged, and the last-known-good row is
deleted. A sticky policy would lock an employee out forever after the MDM profile
is removed at offboarding. To avoid acting on an MDM's delete-then-write window,
absence after a managed state is *confirmed* by two consecutive observations at
least 10 s apart (the 60 s poll supplies the second; an explicit reload counts as
an observation but never confirms by itself); a boot has no history and trusts
what it sees. During the window the last good view stays in force.

**Read path summary.**

| Condition | State | Tier A keys | Tier B keys | Network consumers |
| --- | --- | --- | --- | --- |
| No file | `none` | user | user | normal |
| Trusted, all leaves ok | `active` | policy | policy | normal |
| Trusted, a leaf rejected | `degraded` | that leaf: last good, else HOLD; others policy | that leaf: last good, else user; others policy | closed only if the rejected leaf is proxy/no_proxy/ca with no last good |
| Untrusted or unparseable, last good exists | `last_good` | last good | last good | as last good |
| Untrusted or unparseable, none | `frozen` | writes frozen; reads show the user's value | user | normal |

### Which settings can be managed

All keys; "Tier" is the failure class above; "Enforced at" is the single read
point the effective value comes from; "Refusal" is the admin op's behaviour. A
locked key makes the op refuse `setting_locked` (the existing cause,
`admin_network.rs:69`); a value outside an allowlist or bound refuses
`policy_not_allowed`; a held key refuses `policy_frozen`. Detail text names the
key, the policy's `reason` if any, the `contact`, and `(policy <digest12>, rev
<revision>)`; the recovery line is the existing "Managed by your organisation's
policy; ask your administrator." (`admin_network.rs:103`).

| Policy key | Store document | Modes / form | Tier | Enforced at | Op that refuses |
| --- | --- | --- | --- | --- | --- |
| `security.profile` | `policy.profile` | `locked`, `floor` (strict < standard < relaxed in permissiveness), `default` (first boot only: seeds the row `PolicyGate::new` writes when unset, `policy.rs:250-262`; later changes of the default never move an existing install) | A | `PolicyGate::profile()` returns `stricter(user, floor)` or the locked value; the stored row is untouched | `admin.profile.set`: refused when locked or when the request is more permissive than the floor |
| `security.grants.manual` | `grant` | `"allow"` \| `"deny"` (plain) | A | `admin.grants.add` | `admin.grants.add` refuses `setting_locked` |
| `security.grants.remember` | approvals | `"allow"` \| `"deny"` (plain) | A | `ApprovalService::resolve` (forces `remember=false`; `approval.rs:275`) and `admin.approvals.resolve` | `remember: true` refuses `setting_locked`; a plain approval still works |
| `security.grants.never`, `.never_classes` | gate | list of capability name patterns (a name; `*` matches any run of characters, no other metacharacter, anchored: `flow.step:*/merge`), list of classes (`destructive`, `external`) (plain) | A | `PolicyGate::evaluate_classified` (`policy.rs:328`): a match refuses `policy_denied` on every profile, even with an active grant; flow steps pass through the same call (`flow_service.rs:909`) | `grants.add` of a matching name refuses `policy_not_allowed`; `grants.list` marks a matching row `blocked_by_policy` (the row is the user's and stays) |
| `scopes.allowed_repository_roots` | `flows.scope_policy` | list of absolute path prefixes (plain) | A | the one effective scope loader: repositories whose canonical root is not under a prefix are dropped from the effective policy (reported, never deleted) | `admin.flows.settings.set` with such a repository refuses `policy_not_allowed` |
| `scopes.connector_wide` | `flows.scope_policy` | `"deny"` (plain) | A | effective loader turns `connector_wide` into `targets` with its listed targets | `settings.set` with `connector_wide` refuses |
| `connectors.allowed_base_hosts` | connector rows, scope policy | host patterns as `parse_no_proxy` rules (plain) | A | a connector scope whose `base_url` host does not match is dropped from the effective policy; `ConnectorService` refuses to call it | `admin.connectors.configure` with such a `base_url` refuses `policy_not_allowed` |
| `connectors.disabled` | connector rows | list of connector ids (plain) | A | `ConnectorService`: disabled connectors refuse | `configure { enabled: true }` refuses `setting_locked` |
| `flows.programs` | `flows.allowed_programs` | `allow` (user list intersected), `locked` (exact list); a shell or a path in the policy list rejects the leaf (same rule as `check_allowed_program`) | A | `FlowService::settings()` (`flow_service.rs:533`) | `settings.set` with a program outside refuses |
| `flows.extra_path` | `flows.extra_path` | `allow` (prefixes), `locked` | A | `settings()`; entries are matched after `expand_home` | likewise |
| `flows.read_cache_roots` | `flows.read_cache_roots` | `allow` (prefixes), `locked` | A | `settings()` and `read_cache_dirs()` | likewise |
| `flows.artifacts_root` | `flows.artifacts_root` | `locked`, `default` | B | `settings()` | `settings.set` refuses when locked |
| `landing.max_permissions` | `flows.landing_policy` | `{push,create_pr,merge,sync}` each `false` = ceiling (plain) | A | the landing loader ANDs the ceiling into every repository's permissions (`landing_policy.rs:268`) | `admin.flows.landing.set` refuses a `true` that the ceiling forbids |
| `landing.allowed_github_servers` | `flows.landing_policy` | host list (plain) | A | the landing loader drops other repositories | landing.set refuses |
| `landing.git_path` | `flows.landing_policy` (`git_path`) | `locked`, `default` (an absolute path for the target platform, no `~`) | A | `Snapshot::managed` sets each recipe's effective Git; the broker resolves and trust-checks it at freeze, at every stage and before every Git process | `admin.flows.landing.set` refuses `setting_locked` when locked and the save changes `git_path` |
| `landing.merge_method` | `flows.landing_policy` (per recipe `merge_method`) | `locked`, `default` (`squash` \| `merge` \| `rebase`) | A | `Snapshot::managed` replaces or fills each recipe's method | landing.set refuses `setting_locked` when locked and a recipe's method changes |
| `models.allowed_sources` | download ops | subset of `catalog`, `custom_url`, `import` (plain) | A | `admin.models.download`/`import` (`admin_models.rs:500`, `:437`) and the engine import | the refused op, `policy_not_allowed` |
| `models.allowed_curators` | `curator.agent` | list of `claude`, `codex`, `copilot`, `gemini`; `[]` disables (plain) | A | `selected_agent` (`admin_models.rs:1066`) returns none for a pick outside the list; curator runs refuse | `admin.curator.set` refuses |
| `models.engine_source` | engine ops | `download` (default) \| `mirror_only` \| `import_only` (plain) | B | `engine_install` (`admin_engine.rs:263`): `mirror_only` refuses without an effective engine mirror and never contacts upstream; `import_only` refuses install and leaves `engine.import` (`:364`) open | `admin.models.engine.install` refuses `policy_not_allowed` |
| `models.dir` | `model.models_dir` | `locked`, `default` | B | `ModelService::models_dir()` (`model_service.rs:1052`); the "overlaps base" refusal stays | `admin.models.settings.set { models_dir }` refuses |
| `models.idle_unload_min` | `model.idle_unload_min` | `locked`, `default`, `min`, `max` | B | `idle_unload_min()` (`model_service.rs:1641`) | `settings.set { idle_unload_min }` refuses |
| `retention.evidence_days`, `.audit_days` | `retention.*` | `locked`, `min` (floor: audit kept at least this long), `max` (ceiling: kept at most this long, and "forever" is refused), `default` | A | `RetentionService::settings()` (`retention.rs:373`) returns the clamped pair, so the scheduler, `run_pass` and the status all see it; the existing clock-jump guard applies unchanged to a policy-forced window | `admin.retention.set` refuses a value outside the bounds |
| `network.proxy`, `.no_proxy` | `net.settings` (+ keychain `network.proxy`) | `locked` (and `default` for no_proxy); a locked proxy whose `auth` is `none` also locks the credential; with `basic`/`anyauth` the credential stays the human's to type (D6) | A + closed consumers | `resolve()` (`network_service.rs:424`) | `admin.network.set` (`admin_network.rs:239`) |
| `network.ca_bundle` | `net.settings` | `locked { path, sha256 }` (the file passes the trust check and the digest must match the normalized copy; the loader performs the import `ManagedNetwork` already documents, `network_service.rs:269-272`) | A + closed consumers | `resolve()` + `checked_copy` | `admin.network.set` |
| `network.engine_mirror`, `.models_mirror` | `net.settings` | `locked`, `default` (null pins upstream) | B | `resolve()`; validation uses `mirror_allowed_hosts` | `admin.network.set` |
| `network.mirror_allowed_hosts` | none (policy-only) | list of rules (plain) | B | `resolve_user` (`network_service.rs:669`) | validation error `network_settings_invalid`, as today |
| `service.require_login_unit` | none | `true` (plain) | B | compliance signal only (below) | none |

Not managed, on purpose: `model.default.*` (which installed model is the default is
the human's choice among already-verified models), `retention.last_run` and the
other bookkeeping rows (`retention.rs:62-70`), connector credentials (secrets never
ride in a world-readable file), the typed confirmation phrases (they guard a human
act; a policy value needs none), and **telemetry: PAM has none** (a search of the
crates and docs finds no analytics, update check or phone-home), so there is no key.
A feature that adds one must add its policy key in the same change.

### Merge functions

All pure, in `managed_policy.rs`, one test table each.

- Scalar enum with `floor` (profile): `stricter(user, floor)`; `locked` wins over
  everything; with no stored user value the platform default is the user value.
- Number with `min`/`max` (idle unload, retention): `clamp(user, min, max)`;
  `None` (forever) becomes `max` when a `max` exists and stays `None` otherwise;
  `locked` forces.
- Set with `allow`: `user ∩ allow`; with `locked`: exactly the policy list. Path
  sets compare canonical path prefixes by component, never by string.
- Plain constraints (`never`, `allowed_*`, `max_permissions`): filter or AND the
  user's data; they never add anything.
- `default`: used only when the user has no value; a user value is never replaced
  by it, and clearing the user value falls back to it before the builtin default.

Every clamp is a function of `(user, policy)` and nothing else, so the effective
value at time `t` is reproducible from the store and the policy digest.

### Precedence and visibility

**Precedence**: policy over store over defaults, computed at read.

**Effective view on every `get`.** The shape `admin.network.get` already returns
(`admin_network.rs:175-190`, `source_json` `:771`) generalizes to every settings
`get`:

```json
"effective": {
  "<key>": {
    "source": "policy" | "user" | "default",
    "locked": true | false,
    "mode":   "locked" | "default" | "floor" | "min" | "max" | "allow" | "forbid",
    "constraint": { "allow": ["git", "cargo"] },
    "reason": "SEC-114",
    "state":  "applied" | "held" | "rejected"
  }
}
```

`source` says where the *effective value* came from: `policy` when the policy
forced it or clamped the user's value into range (`clamped: true`) or supplied its
default (`locked: false`: the GUI says "Default from your organisation"), `user`
when the human's value stands, `default` otherwise. `locked` is whether the human
can edit the key at all. `constraint` is present for `allow`/`floor`/`min`/`max`
keys so the GUI can show the permitted range. `Source` in `network_service.rs:323`
gains no variant; `Resolved.sources` becomes `(Source, Lock)` pairs (T8), the wire
shape above falls out.

Ops that gain `effective` and, where noted, extra fields: `admin.profile.get`;
`admin.grants.list` (+ `policy { manual, remember, never, never_classes }`, per-row
`blocked_by_policy`); `admin.flows.settings.get` (+ `scope_policy_dropped:
[{ root, reason }]`); `admin.flows.landing.get`; `admin.connectors.list` (per
connector); `admin.models.settings`/`status` (the models-dir and idle keys);
`admin.models.engine.status` (+ `source_policy`); `admin.retention.get`;
`admin.network.get` (already has it).

**New admin ops** (private plane only; added to the bridge whitelist as
`POLICY_ADMIN_OPS`, `pam_gui/src/bridge.rs:42`, `:106`):

- `admin.policy.get {}`: `{ state, reason_code, origin: { path, platform, trust:
  { owner, writable_by_user, symlink, parents } }, digest, revision, organization,
  contact, loaded_ts, checked_ts, last_good: { digest, loaded_ts } | null,
  keys: [{ key, tier, mode, state: applied|held|rejected, detail? }],
  diagnostics: [{ code, key, detail }], compliance: { login_unit: { required,
  present } } }`.
- `admin.policy.reload {}`: re-reads now, same body. No confirmation phrase: it
  reads the file the administrator delivered and cannot loosen what the
  administrator did not.

**`status` (public, so an agent can read it)** gains one block with no values and
no reasons: `"policy": { "state": "active", "revision": "2026-10-02.1",
"digest": "ab12cd34ef56", "loaded_ts": 1759423200, "managed": true,
"rejected_leaves": 0 }`. `pam status` prints one line
(`policy: managed by Example Corp, rev 2026-10-02.1, active`) and `--json` the block.
An agent learns *that* a policy exists; the content stays on the admin plane. A
refused agent request on a policy-denied capability says `policy_denied` and
"not available on this machine; ask your administrator" and nothing about why.

**Doctor (plan 53)** consumes the same `inspect()`: a `policy_file_trusted` check:
ok for `none`/`active`, warn for `degraded`, fail for `last_good`/`frozen`; the
required-policy variant (`--require-policy`) also fails `none`.

**Compliance signal for MDM.** The two inspectors that need no daemon, and exit
codes MDM scripts can branch on (Intune Remediations treat 0 as compliant and any
other code as not):

`pam policy check --installed [--expect-revision R] [--json]` exits `0` trusted
and valid (and, if given, the revision matches); `10` no policy installed; `11`
untrusted; `12` file-level invalid; `13` leaf problems; `14` revision mismatch. (As
built, item 5: `--installed`, `--expect-revision`, `10` and `14` were not built;
`pam policy check <fixed path> --trust --json` is the compliance command.)
`pam status --json` gives `.policy.state` for a machine whose daemon is up
(Jamf extension attribute, Intune detection script). `service.require_login_unit`
is a *compliance requirement, not an enforcement*: PAM cannot make a user-scope
unit (`service.rs:3`) permanent and does not try. The GUI shows a banner with the
existing one-click install; `status.policy.compliance.login_unit` and the doctor
report it. Fleets that need the unit guaranteed deploy it themselves (the
MDM pushes `/Library/LaunchAgents/com.github.ro-ag.pam.daemon.plist`, same label,
or registers the scheduled task for the Users group); `pam service status` already
reads a unit by label.

### Reload

At boot, before the gate, the stores, the listeners and the network service are
built (so there is no window in which the daemon runs unmanaged): one synchronous,
bounded read through the `PolicySource`. A failure never blocks boot.

Afterwards, a task started like `RetentionService::run_scheduler`
(`retention.rs`) re-reads:

- every 60 s: one `symlink_metadata` of the file; a changed `(len, mtime,
  dev/ino)` triggers a full verified re-read;
- every 10 min regardless (a re-hash and re-verify), so a changed trust fact
  without a changed file (a chmod, an ACL edit) is noticed;
- on `admin.policy.reload` (the GUI's "Check now") and when the GUI opens
  Settings.

No SIGHUP: Windows has none, and a signal an agent can send adds an input without
adding capability. A change swaps an `Arc<PolicyView>` under a lock held for the
swap only; every op takes one snapshot at entry and uses it for both the lock
check and the write, so a reload mid-op takes effect on the next op; the effective
read is still clamped, so a write that raced a tightening is harmless. After the
swap the handle calls the registered change hooks: `NetworkService::invalidate()`
(its profile cache is 2 s, `network_service.rs:64`), the gate's live profile, and
a `policy.changed` event on the hub the GUI already subscribes to, so an open
Settings screen redraws.

Tightening does not revoke grants (the rows are the user's); a `never` match makes
an active grant inert at the gate, every profile, at the next step evaluation.
Work admitted earlier under a grant that policy now denies is stopped at its next
gated step, not at placement (the revision scheme is for revoked grant rows,
`store.rs:70-78`, and policy changes none).

### Audit

Every row is `actor = policy`; its `detail` is JSON and carries the full 64-hex
`digest` and `revision`, never a leaf value. Rows hang off a request row: the
envelope's own id when an admin op caused them; otherwise a fresh daemon-owned
request (`capability = policy.load`, `caller_agent = pam-daemon`, `ingress =
admin`, inserted `running` and finished `done` in two store calls; a crash between
them leaves a row crash recovery fails with `daemon_restart`, `lifecycle.rs`,
which is the documented behaviour for any interrupted row).

| Action | Decision | When | Detail |
| --- | --- | --- | --- |
| `policy.load` | allow | a verified load whose digest differs from the one in force (boot, poll, reload) | `{ trigger, state, digest, revision, prior_digest, rejected: [{ key, code }] }` |
| `policy.reject` | refuse | a file that fails (file-level) or rejects leaves, **on change only**: the key `(verdict, digest, stat)` is remembered so a stuck file does not write a row per poll | `{ trigger, state, code, digest?, last_good_digest?, rejected }` |
| `policy.clear` | allow | absence confirmed after a managed state | `{ prior_digest }` |
| `policy.locked_write` | refuse | any admin op refused `setting_locked`, `policy_not_allowed` or `policy_frozen`, written on the op's own request in addition to the terminal `admin`/`refuse` row (`finish_refused`, `admin.rs:1080`), the pattern `network.configure` uses (`admin_network.rs:302`) | `{ op, keys, cause, digest, revision }` |
| `policy.denied` | refuse | the gate refused a capability for a `never` match | `{ capability, rule, digest }` (on the request row the gate already audits, `gate_refusal`, `daemon.rs:191`) |

Retention applies to these rows like any audit row, and `retention.audit_days` can
itself be floored by the policy.

## Threats

| Threat | Analysis |
| --- | --- |
| The sandboxed agent writes the policy | It cannot: the location is root/Administrators-owned. PAM does not rely on that alone. A file the agent could write fails the trust check (not root-owned, or the daemon's token can write it), is ignored for enforcement, is logged and audited (`policy.reject`) and is shown in `status` and the GUI. Importantly this includes a *loosening* file: a policy that sets `profile: relaxed` or broad scopes is honoured only when it passes the same check; there is no weaker bar for restrictive-looking files, so a malicious file cannot be "mostly valid". |
| The agent picks the path | Impossible: no environment variable, flag, `PAM_BASE_DIR` or file under `<base>` selects the policy file; `ProgramData` on Windows is accepted only in the one drive-letter form and then trust-checked. A separate `PAM_BASE_DIR` the agent starts gets a fresh store but the same machine policy. |
| A swap between check and read | Judged on one handle: `(dev, ino)` equality on unix, `FILE_SHARE_READ` on Windows. |
| A corrupted or half-written file | The two-tier rule and the last-known-good copy; `pam policy check` before the push; atomic replace in the delivery scripts. |
| Downgrade by deleting the file | Needs root/Administrators. Absence is confirmed over two observations. After confirmation the machine is unmanaged by design (offboarding). |
| The human edits `~/.pam/state.sqlite3` | Cannot beat a lock: the overlay is computed from the file at read, the store holds only the user's own values. Editing `policy.last_good` can only matter while the file is already unusable, and the same editor can already edit grants. |
| The human runs another PAM build or a debugger | Out of scope here as in `admin-boundary.md` ("Deployment assumption"): code integrity and application allow-listing belong to the MDM. |
| Shared Windows machine, ACE for a different user | The probe is token-relative (above, "Does not prove"). Open question 1. |
| Policy leaks a secret | The schema has no secret field and the proxy credential stays user-typed in the keychain (D6). The file is world-readable by design and says so in the guide. |
| Audit flood by a flapping file | Rows only on a change of `(verdict, digest, stat)`. |
| Policy as an information channel to the agent | `status` carries the state, revision and digest, nothing else; refusals to agents carry `policy_denied` and no rule text. |

## Delivery guidance (for administrators)

This section became [docs/policy/README.md](../policy/README.md) (written by
T10; T12 linked it from the README, the boundary document and the trust
refusals). The CA lines below are macOS only: a CA bundle a Windows policy pins
is rejected (As built, item 6).

### Layout

```
macOS    /Library/Application Support/PAM/policy.json       root:wheel 0644
         /Library/Application Support/PAM/ca/corp-root.pem  root:wheel 0644   (only with network.ca_bundle)
Windows  %ProgramData%\PAM\policy.json                      SYSTEM + Administrators: full; Users: read
         %ProgramData%\PAM\ca\corp-root.pem                 same ACL (inherited)
```

The directory and every file must be unwritable to the person who uses the
machine; PAM checks that and ignores the policy otherwise (and says so in
`pam status`, the GUI and the audit trail). Policy files are world-readable by
design: never put a secret in one. Deliver the CA bundle first, then the policy
that names it, and replace files atomically (write a temporary name, then
rename), because PAM reads while you write; a partial file is handled (last known
good), but it is noisy.

### macOS (Jamf, Kandji, Intune, Mosyle: package, or a script run as root)

```sh
set -euo pipefail
dir="/Library/Application Support/PAM"
install -d -m 0755 -o root -g wheel "$dir" "$dir/ca"
install -m 0644 -o root -g wheel corp-root.pem "$dir/ca/corp-root.pem"
install -m 0644 -o root -g wheel policy.json "$dir/.policy.json.new"
mv -f "$dir/.policy.json.new" "$dir/policy.json"
```

PAM reads exactly `policy.json`; a leftover `.policy.json.new` is never read.
Do not put the file in `/Library/Managed Preferences` yet (see D8).

### Windows (Intune platform script as System in the 64-bit host, a Win32 app, or a GPO startup script)

```powershell
$dir = Join-Path $env:ProgramData 'PAM'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
# Cut inheritance: a new ProgramData subfolder lets Users create files in it by default.
# SIDs, not names: SYSTEM and Administrators are localized on non-English Windows.
icacls $dir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
New-Item -ItemType Directory -Force -Path "$dir\ca" | Out-Null      # inherits the locked ACL
Copy-Item .\corp-root.pem "$dir\ca\corp-root.pem" -Force
$tmp = "$dir\policy.json.new"
[IO.File]::WriteAllText($tmp, [IO.File]::ReadAllText('.\policy.json'), (New-Object Text.UTF8Encoding $false))
Move-Item -Force $tmp "$dir\policy.json"
```

(`Set-Content -Encoding UTF8` in Windows PowerShell 5.1 writes a byte-order
mark; PAM tolerates one, but write without it.) The `icacls` flags and the
inheritance behaviour were measured in T13 (2026-10-03). The temporary file
must be created inside `$dir`, as above: `Move-Item` keeps the ACL the file
had where it was made, so a file moved in from another folder arrives without
the locked ACL (from `C:\Windows\Temp` it carried no `Users` entry at all and
the daemon's user could not read it).

### Validate before the push, check after

- `pam policy check policy.json --for macos|windows [--json]`: parses the file
  exactly as the daemon would, prints every rejected leaf with its key and
  reason, the digest, and a one-line summary of what the policy locks. Exit `0`
  valid; `12` file-level invalid; `13` leaf problems. It runs on the
  administrator's workstation or build agent (macOS or Windows; Linux is not a
  supported target) and checks path *syntax* for the named platform, never the
  presence or ownership of a referenced file.
- `pam policy check --installed [--expect-revision R] [--json]`: on the endpoint,
  runs the real trust check and the schema against the installed file, no daemon
  needed. Exit `0` trusted and valid; `10` none installed; `11` untrusted; `12`
  invalid; `13` leaf problems; `14` revision mismatch. This is the compliance
  command for Jamf extension attributes and Intune Remediations. (Not built
  in this form; see As built, item 5.)
- `pam status --json` `.policy` on a running machine; the GUI's Settings >
  Managed policy page for a human.

**Why a CLI command is allowed here.** The playbook says "there are no security
commands" (`docs/pam-playbook.md:6`) because grants, approvals and scopes change
what agents may do and are human acts in the GUI. `pam policy check` changes
nothing: it opens one file the caller names (or the fixed installed path), writes
nothing, opens no socket, reads no store, and its answer is derivable from a
world-readable file. It is the same kind of command as `pam service status`. There
is deliberately no `pam policy set/apply/install`: the file is the MDM's, never
PAM's, and the command stays out of `pam playbook`. A GUI-only validator was
rejected: administrators validate in CI, where there is no GUI.

## GUI

Words follow the repo's spelling (`organisation`, `admin_network.rs:103`); styling
follows the Tailwind v4 `@theme` tokens and CVA, no arbitrary values (the
`pam-gui-styling-discipline` rule; T11 loads the `frontend-design` skill).

- **Header chip** on every Settings page when `state != none`: "Managed by
  {organization}" (neutral), or a warning variant for `degraded`, `last_good`,
  `frozen`. It links to the Managed policy page.
- **`ManagedField`**, one wrapper every settings control goes through: `locked`
  renders the control disabled with a lock and "Managed by your organisation" plus
  the policy's `reason` and the `contact`; `allow`/`floor`/`min`/`max` render the
  control inside the permitted set or range, with the constraint printed beside
  it; a policy `default` prints "Default from your organisation". Network already
  renders `locked` this way (`SettingsNetwork.tsx`); it moves onto the wrapper.
- **Settings > Managed policy** (read-only): state sentence, the origin path and
  the trust verdict (owner, writable by you, symlink, parents), revision, digest,
  organisation and contact, loaded and last-checked time, last good copy, the
  per-key table (`applied`, `held`, `rejected` with the reason), and a "Check now"
  button (`admin.policy.reload`). A person sees the origin of what governs them,
  which the threat model asks for.
- **Banners**: `degraded` "Your organisation's policy has {n} problem(s); the
  settings affected are listed below. Contact {contact}."; `last_good` "The policy
  file on this computer cannot be read or trusted. PAM is using the last good
  copy (revision {rev})."; `frozen` "The policy file cannot be read or trusted.
  Changes that would widen what agents can do are paused until it is fixed.";
  login unit required and missing "Your organisation requires PAM to start at
  login" with the existing one-click install.
- The bridge's typed phrases (`relaxed`, `grant`, `network`, `bridge.rs:427-472`)
  are unchanged; a locked control never reaches them.

## Test strategy

Every row names the crate and file. New daemon tests seed the relaxed profile
explicitly and assert no unix-only lock or signal detail (memento
`pam-tests-never-ran-off-macos`: `Profile::platform_default` is `standard` off
macOS). Before `tools/check.sh`, run `cargo clippy --all-targets -- -D warnings`
on each touched crate (memento `clippy-before-full-gate`).

| Area | Cases |
| --- | --- |
| Trust matrix, macOS (`managed_policy_trust_test.rs`) | A temp root is owned by the test user, so the *production* rule (root-owned) correctly refuses every temp file; the matrix therefore runs under `TrustRules::owned_by(uid)`, and the root-owned positive case uses a real root-owned file, `/private/etc/hosts` (`root:wheel 0644`, ancestors `/private`, `/private/etc` root-owned and `0755`), under the production rule. Cases: production rule accepts `/private/etc/hosts`; production rule refuses a test-owned file; `owned_by(uid)` accepts a `0444` file in a `0555` directory and refuses `/private/etc/hosts`; mode `0644`/`0664`/`0666` file (the write probe and the mode rule each); setuid bit; the path is a symlink to a good file; a directory symlink in the chain; a parent `0775`/`0777`; a sticky parent (refused); the path is a directory; empty file; exactly 64 KiB; 64 KiB + 1; a swap of the file between the stat and the open (dev/ino mismatch, driven by a test seam that renames between the two); a file that vanishes mid-check. |
| Trust, what cannot run without root (macOS) | A root-owned file at the real `/Library/Application Support/PAM/policy.json`; an extended ACL granting the user write on a root-owned file; the install scripts. Covered by the owner's one manual pass in T13 (`sudo install ...`, then `pam policy check --installed`, a `chmod g+w` negative, a `chmod +a` ACL negative). |
| Trust matrix, Windows VM (`managed_policy_trust_test.rs`, `#[cfg(windows)]`, fixtures from `PAM_TRUST_FIXTURES`, required when `PAM_REQUIRE_WIN_ACL_FIXTURES=1`, the pattern of `PAM_REQUIRE_TLS_FIXTURE`) | `prlctl exec` runs as SYSTEM, which holds every right: run as SYSTEM, every file is **untrusted**, which proves the probe is sensitive. The matrix runs as the logged-in unprivileged user (`prlctl exec "Windows 11" --current-user`), with fixture folders built from SYSTEM by `icacls`: locked ACL -> trusted; `Users:(OI)(CI)M` -> untrusted; `Users:(OI)(CI)(W)` on the folder only; the default inherited ProgramData subfolder ACL -> untrusted (the case the delivery script exists for); owner set to the user (`/setowner`) -> untrusted via `WRITE_DAC`; `DELETE` only; `FILE_DELETE_CHILD` only (refused by the file probe: `writable_by_user`, measured); a junction as `PAM`; a symlink file; a file held open by a writer (busy, not untrusted). |
| Grammar (`managed_policy_test.rs`) | Unknown key at every depth; duplicate key at top, in a section, in a leaf; wrong type per leaf; `locked` with another mode; `default` + bounds; BOM; CRLF; exactly 64 KiB / +1; 256 / 257 list entries; control characters; a `reason` over 200; version `0`, `2`, missing; digest equals SHA-256 of the raw bytes (BOM included); every sample under `docs/managed-policy/` parses with no rejected leaf (`managed_policy_samples_test.rs`) so the documentation cannot rot. |
| Merge and precedence (`managed_policy_test.rs`) | One table per function: profile `floor` against all nine user x floor pairs and `locked`; numeric clamp including `None`/forever and `max` with `forever`; `allow` intersection, empty intersection, shells rejected in the policy list; path-prefix by component (`/Users` does not cover `/UsersX`); `never` globs; `never_classes`; `max_permissions` AND; `connector_wide` narrowing; `default` used only when the user has no value and never replaces one; retention pair that breaks evidence <= audit rejected as a leaf; user rows never mutated (compare store before/after every read). |
| Locked-key refusals through the real admin ops (`admin_*_test.rs`, one file per surface) | Per key of the table: the op refuses `setting_locked` / `policy_not_allowed` / `policy_frozen`; the store row is byte-identical afterwards; the reply detail contains the reason, the contact and `(policy <digest12>, rev ...)`; the audit has the terminal `admin`/`refuse` row **and** a `policy.locked_write` row with the full digest; a request inside the bounds succeeds; removing the policy restores the user's value; grants: `manual: deny`, `remember: deny` (a plain approval works, `remember: true` refuses), `never` (an active grant is inert at the gate on every profile and at a flow step, the public refusal is `policy_denied` with no rule text); `engine_source` `mirror_only` without a mirror never opens a socket (a fake origin sees zero requests), `import_only` refuses install and accepts import; retention `max` refuses forever and the clock-jump guard still holds on a forced window; connectors: `allowed_base_hosts` drops a scope and refuses configure. |
| Network overlay (`network_service_test.rs`, `admin_network_test.rs`) | The existing stub-layer tests move to a `PolicyHandle` built from a fake source; credential lock follows `proxy.auth == none` (D6); a managed CA is imported through the trust check, a digest mismatch rejects the leaf and closes the consumers; an invalid `engine_mirror` is Tier B (dropped, user value stands). |
| Reload (`managed_policy_service_test.rs`, `tokio::time::pause`) | Scripted `PolicySource`: valid, then corrupt, then valid; `active` -> absent once (still in force) -> absent twice (`none`, `policy.clear`, last good deleted); boot with absent; boot with corrupt and a stored last good (restart with the same store directory: the **profile stays strict**); boot corrupt with none (`frozen`: `profile.set relaxed` refused, `profile.set strict` and `grants.revoke` allowed); a version bump the binary does not read -> `last_good` naming both versions; the 60 s stat poll fires a full read only on a changed stat, the 10 min poll re-verifies a changed trust fact (a chmod); `admin.policy.reload` counts as one observation; `policy.reject` is written once per stuck digest, not per poll; an op that straddles a reload uses one snapshot. |
| Two-tier behaviour (`managed_policy_service_test.rs`, daemon integration) | (1) Profile `locked: strict`, file replaced by `{"version":` (truncated): profile stays strict; the GUI body says `last_good`; one `policy.reject` row. (2) Mirror host typo in an otherwise good file: `degraded`; every other leaf applies; the user's mirror stands; the diagnostic names the key. (3) `network.proxy` rejected and no last good: connector calls and downloads refuse `network_policy_invalid`; a flow with only command steps still runs. (4) `grants.never` entry with a bad type: Tier A held, `grants.add` refused `policy_frozen`. (5) Loosening: a trusted `relaxed` lock is honoured and shown; the *same bytes* from an untrusted source are ignored, `frozen`, `policy.reject`. |
| Daemon integration (`daemon_test.rs`) | Boot order: the gate answers under the policy from the first request; `status.policy` for each state; the public `status` carries no rule text; a lazily started daemon with a hostile `ProgramData`/`PAM_BASE_DIR` reads the same fixed path; the policy directory under `<base>` is never read. |
| CLI (`main_test.rs`, `render_test.rs`) | Every exit code of `check` and `check --installed`; `--for windows` path syntax from a mac host; `--json` shape; no daemon is started or contacted (the base dir points at nothing); `pam status` line per state. |
| Frontend (`ManagedField.test.tsx`, `SettingsPolicy.test.tsx`, each screen's test, `ipc.test.ts`) | Every mode renders (locked, default, floor/min/max, allow) with the constraint text; states and banners; "Check now" calls the op and redraws; a locked control cannot be activated; the bridge whitelist length test (`bridge.rs:106` pattern) covers `POLICY_ADMIN_OPS`. |

## Implementation plan

Branch `feat/managed-policy` from `main` after plan 52 is squash-merged
(`network_service.rs` and `admin_network.rs` are edited by both). One ptrack task
per item below. Commit messages reference `#<id>`; link squash commits with
`ptrack commit add` before `task done` (memento: ptrack commit links are manual);
conventional-prefix PR title; wait for green PR checks before the squash merge
(`docs/**`-only PRs need `--admin`). No workflow changes. A new local gate is
`bash tools/check.sh` at the end.

### Phase A (two agents in parallel; new files only)

**T1. Policy document: parse, validate, merge.**
- Files: new `crates/pam_daemon/src/managed_policy.rs`, `managed_policy_test.rs`;
  `lib.rs` (this task adds both module lines); `flow_service.rs` (only the
  visibility of `check_allowed_program`, so the policy list is held to the same
  rule as the human's).
- Work: the closed key table and `Tier`; the strict reader (duplicate keys, BOM,
  limits); leaf types and per-leaf semantic validation (reusing `pam_net`
  `MirrorBase`, `Proxy`, `parse_no_proxy`); the merge functions; `PolicyView`
  (resolved leaves, states, diagnostics); `inspect_bytes(bytes, target_platform)`;
  the `effective` entry builder. Pure: no I/O, no async, no store.
- Acceptance: the grammar and merge rows of the test table; every `Key` has a
  tier and a refusal cause (a test that fails when a key is added without them);
  `cargo clippy -p pam_daemon --all-targets -- -D warnings`.

**T2. Trust check.**
- Files: new `managed_policy_trust.rs`, `managed_policy_trust_test.rs`.
- Work: `TrustRules`, `verify_and_read`, `Untrusted` reasons (stable codes:
  `not_owned_by_root`, `writable_by_user`, `symlink`, `parent_writable`,
  `not_regular`, `too_large`, `busy`, `unreadable`); the unix rules and the
  Windows probes as specified; the platform path constants and the `ProgramData`
  rule.
- Acceptance: the macOS trust rows; `cargo check --tests` on the Windows VM
  compiles the `cfg(windows)` half (the VM is the only Windows compiler).

### Phase B (one agent, then one agent)

**T3. Policy service.**
- Files: new `managed_policy_service.rs`, `managed_policy_service_test.rs`;
  `lib.rs` (one line).
- Work: `PolicySource` trait, `FileSource::platform()` and `FileSource::at`;
  `PolicyHandle` (`view()`, `reload(trigger)`, `none()`), the state machine and
  the fallback chain, the last-good row, absence confirmation, the poll task
  with the shutdown watch, the audit rows (and the daemon-owned request row),
  change hooks, and `impl ManagedNetworkLayer for PolicyHandle`.
- Acceptance: the reload and two-tier rows against fake sources.

**T4. Plumbing.**
- Files: `daemon.rs`, `policy.rs` (constructor only), `flow_service.rs`,
  `connector_service.rs`, `model_service.rs`, `retention.rs`, `approval.rs`,
  `admin.rs` (constructor and field only), `evidence_service.rs`,
  `crates/pam_testkit/src/lib.rs`, and the constructors in the matching
  `_test.rs` helpers.
- Work: `DaemonConfig.policy_source` (default: the platform file); the boot
  order (read policy first, then the gate); every consumer takes
  `Arc<PolicyHandle>` (`PolicyHandle::none()` in tests that do not care) and
  stores it with no behaviour change; the `status.policy` block; the poll task
  started and drained with the others.
- Acceptance: the whole workspace compiles and the existing suites pass
  unchanged; the daemon rows for boot order and `status.policy`; `cargo clippy`
  on `pam_daemon` and `pam_testkit`.

### Phase C (four agents in parallel; function bodies, disjoint files)

**T5. Security: profile, grants, approvals.**
- Files: `policy.rs`, `admin.rs` (profile, grants, approvals bodies only),
  `approval.rs`, and their tests.
- Work: `profile()` returns the effective value; `set_profile` and `profile.set`
  refuse; the seed at first boot honours `default`; `evaluate_classified` refuses
  `policy_denied` (name globs and classes); `grants.add`, `grants.list`
  (`blocked_by_policy`), `remember` in both `admin.approvals.resolve` and the
  approval service; `effective` on the `get` ops; the `policy.locked_write` row
  helper shared by every refusing op (lives in T3's module, called here).
- Acceptance: the grants rows of the refusal table and the profile merge rows;
  clippy.

**T6. Flows, scopes, landing.**
- Files: `scope_policy.rs`, `flow_service.rs`, `flow_recovery.rs`,
  `flow_landing_runtime.rs`, `connector_landing_git.rs`, `evidence_service.rs`,
  `flow_result_service.rs`, `landing_policy.rs`, `admin_flows.rs`, and tests.
- Work: `ScopePolicy::load` becomes the *effective* loader taking the policy view
  and the nine callers pass the handle their service holds; the raw loader is
  renamed `load_user`, `pub(crate)`, and used only by `admin_flows.rs` (to edit
  what the human saved) and by `scope_policy.rs` itself, so no consumer can read
  the document directly (the signature change makes the compiler list every
  site); `FlowService::settings()` returns the effective settings; landing
  permissions and servers; `admin.flows.settings.set` and `landing.set` refusals;
  `scope_policy_dropped` and `effective` on the `get` ops.
- Acceptance: the flows, scopes and landing rows; a test that no call outside
  `scope_policy.rs`/`admin_flows.rs` can name `load_user`; clippy.

**T7. Connectors, models, retention.**
- Files: `connector_service.rs`, `admin_connectors.rs`, `model_service.rs`,
  `admin_models.rs`, `admin_engine.rs`, `retention.rs`, `admin_retention.rs`,
  and tests.
- Work: effective `models_dir`/`idle_unload_min`; `allowed_sources`,
  `allowed_curators`, `engine_source` in the ops listed; connector
  `allowed_base_hosts` and `disabled`; retention bounds in `settings()` so the
  scheduler, `run_pass` and the GUI all read the clamped pair; `effective` on the
  `get` ops.
- Acceptance: the connectors, models and retention rows; the fake origin sees
  zero requests under `mirror_only` without a mirror; clippy.

**T8. Network overlay.**
- Files: `network_service.rs`, `admin_network.rs`, and tests.
- Work: `Resolved.sources` becomes `(Source, Lock)`; `ManagedNetwork` gains the
  unlocked `default` layer; the credential lock follows D6; a managed CA bundle
  goes through `verify_and_read` plus the digest (the Windows CA import has no
  ownership check today, `network_service.rs:1006`); `network_policy_invalid` for
  a rejected proxy leaf with no last good; `ManagedNetworkLayer` stays the seam
  (`FixedManagedNetwork` remains for tests).
- Acceptance: the network overlay row; the plan 52 network suites pass unchanged.

### Phase D (after C; three agents in parallel)

**T9. Admin ops and bridge.**
- Files: new `admin_policy.rs`, `admin_policy_test.rs`; `admin.rs` (one dispatch
  line, as `dispatch_network`); `crates/pam_gui/src/bridge.rs` and its tests
  (`POLICY_ADMIN_OPS`, the length constant at `:106`).
- Work: `admin.policy.get`, `admin.policy.reload`.
- Acceptance: the op rows; the bridge test; clippy on `pam_daemon`, `pam_gui`.

**T10. CLI and samples.**
- Files: `crates/pam/src/main.rs` (`Cmd::Policy`), `render.rs`, `main_test.rs`,
  `render_test.rs`; new `docs/managed-policy/samples/macos.json`,
  `windows.json`, `minimal.json`; new `managed_policy_samples_test.rs`.
- Work: `pam policy check` and `check --installed`, exit codes `0/10-14`, `--for`,
  `--json`; the `pam status` line; no daemon contact; the command is absent from
  `pam playbook`.
- Acceptance: the CLI row and the samples row.

**T11. Frontend.**
- Files: `frontend/src/lib/ipc.ts`, `ipc.test.ts`; new
  `screens/ManagedField.tsx`, `ManagedField.test.tsx`, `SettingsPolicy.tsx`,
  `SettingsPolicy.test.tsx`; `Settings.tsx` (tab, chip); and the screens that own
  a managed control: `SettingsFlows.tsx`, `LandingSettings.tsx`,
  `SettingsConnectors.tsx`, `SettingsModels.tsx`, `EngineCard.tsx`, `Models.tsx`,
  `SettingsNetwork.tsx`, the retention panel and the security panel (each with its
  test).
- Work: the [GUI](#gui) section against the op contracts with a mocked bridge.
- Acceptance: `npm --prefix frontend run lint`, `build`, `test`.

### Phase E

**T12. Documentation (one agent, no code).** (As built: the guide is
`docs/policy/README.md`, written by T10; T12 also took the loose ends listed in
As built.) New `docs/managed-policy.md` (the
[delivery guidance](#delivery-guidance-for-administrators), the key table in
plain words, the compliance codes); `docs/admin-boundary.md` (a "Managed policy"
section: what the file can and cannot do, the trust rule, the residual);
`README.md` (an Enterprise row); `docs/specs/2026-10-02-enterprise-network-and-engine-delivery.md`
("Policy layer": a pointer to this spec and the D6 amendment); `CHANGELOG.md`
(Added: managed policy file, `pam policy check`, `status.policy`; Changed:
network `credential` lock rule); `docs/reviews/design-review-2026-10-02.md` (the
"native confirmation" and policy items cross-referenced). Acceptance: links
resolve; the samples test passes.

**T13. Verification (one agent plus the owner's two manual steps).**
1. `bash tools/check.sh` on macOS.
2. Windows VM (`windows-work-via-parallels`: bundle over `\\Macrano-ci\pam-xfer`,
   `prlctl exec` as SYSTEM, no `set &&` target override): `cargo test -p
   pam_daemon` with `PAM_REQUIRE_WIN_ACL_FIXTURES=1`, the SYSTEM run (all untrusted)
   and the `--current-user` run (the ACL matrix); then the delivery script
   end to end; record the facts in [Evidence to record](#evidence-to-record). Any
   contradicted rule corrects this document before merge.
3. Owner, macOS, with `sudo`: install the sample at the real path, `pam policy
   check --installed` -> 0, `daemon status` shows `active`; `chmod g+w` -> 11 and
   the GUI says why; an ACL (`chmod +a "user:<you> allow write"`) -> 11; delete the
   file -> `none` after two polls.
4. Owner's call: a pass on a real MDM-managed machine if one is available.

## Decisions

Decided here, not open:

- **D1** One JSON document at a fixed per-platform path; no environment, flag,
  `<base>` or op can move it; tests inject a `PolicySource`.
- **D2** The policy is an overlay computed at read by one `PolicyHandle`; the
  user's rows are never rewritten; removing the policy restores them.
- **D3** Trust: on macOS owner, mode, ancestors, symlinks and a write probe, all
  on one handle; on Windows effective-access probes of the daemon's own token on
  the file and its directory, with no `unsafe` and no dependency. A daemon with
  elevated rights reads untrusted.
- **D4** Two tiers with a last-known-good copy; absence is unmanaged but only
  after two observations; a sticky policy was rejected because it strands users
  at offboarding.
- **D5** Validation is per leaf; an unknown key is a rejected leaf (never ignored,
  never fatal); a version this binary does not read is a file-level failure; a
  version never gains keys.
- **D6** The policy never carries a secret. A locked proxy with `auth: none` also
  locks the credential; with `basic` or `anyauth` the credential stays the
  human's to type. This amends `admin_network.rs:181-186` (which locks the
  credential with the proxy, so a managed proxy that needs a password could never
  work) and the network spec's "may carry a pinned proxy credential reference".
  Machine-delivered proxy credentials are the deferred single-sign-on question.
- **D7** `pam policy check` exists and is read-only; there is no policy write
  command.
- **D8** Registry and configuration-profile delivery are later transports of the
  same JSON (one `REG_SZ` value `PolicyJson` under `HKLM\SOFTWARE\Policies\PAM`;
  one string key in the managed-preferences plist for the domain
  `com.github.ro-ag.pam`), added as `PolicySource`s without touching the grammar.
- **D9** Daemon-originated audit rows use a request row with `ingress = admin` and
  `caller_agent = pam-daemon`; no schema migration for a third ingress.
- **D10** The login-unit requirement is a compliance signal, not an enforcement.
- **D11** Re-read: boot, 60 s stat poll, 10 min full re-verify, explicit reload;
  no SIGHUP.
- **D12** A policy tightening makes grants inert at the gate; it revokes nothing.
- **D13** The public `status` carries the state, revision and digest only.
- **D14** Policy applies to every base directory on the machine; per-user and
  per-group policy are the MDM's scoping job.

## Open questions

Only two need the owner.

1. **Windows owner verification.** The probe proves the daemon's own token cannot
   modify the file or its folder; it cannot prove the owner is `Administrators`
   and cannot see an ACE for a *different* local account. Fine on a single-user
   laptop, a gap on a shared machine. Closing it needs `GetNamedSecurityInfo`: a
   platform crate with safe wrappers, or a scoped exception to
   `unsafe_code = "deny"` (`Cargo.toml:93`). Recommendation: ship the probe for v1
   and ask the first pilot whether any endpoint is multi-user.
2. **Which delivery channel does the first pilot use?** If it insists on a
   Configuration Profile or on GPO/ADMX registry policy, D8's adapters need `plist`
   or `winreg` (new dependencies, owner approval). Recommendation: ship the file,
   ask the pilot, add the adapter they need.

## As built (2026-10-03)

What shipped on `feat/managed-policy` for T1 to T12, and where it departs from
the design above. Where this section and an earlier one disagree, this one is
the behavior; the sections above stay as the reasoning. Line references in the
design sections are to the tree it was written against and have moved.

### Names and shapes

1. **Trust rules.** `TrustRules::production()` is the only constructor
   production code calls (the spec's name; an earlier brief said
   `platform()`). The fixed path is `managed_policy_trust::policy_path()`, not a
   field of the rules. `FileSource::platform()` uses both; `FileSource::at` is
   `#[cfg(test)]`, so production has no way to name another path. Tests outside
   the crate inject a `PolicySource` (`pam_testkit::ScriptedPolicy`).
2. **The effective scope loader is `ScopePolicy::load_effective(store,
   &PolicyView)`**, not a changed `load`. The raw loader is `load_user`,
   `pub(crate)`, named only in `scope_policy.rs` and `admin_flows.rs`, and a
   source-grep test holds it there. The rename to `load` was left as optional.
   Landing follows the same pattern (`Snapshot::load_effective`); the landing
   sweep keeps the raw `Snapshot::load` on purpose, because which workspace
   roots exist is the human's document, not a permission.
3. **Network defaults are a layer method, not a field.**
   `ManagedNetworkLayer` gained `defaults()` (the in-force `default` of
   `no_proxy`, `engine_mirror`, `models_mirror`) and `closed()`; production
   wires `NetworkService::with_policy(handle)` (`PolicyNetwork`), whose
   `closed()` is `PolicyHandle::network_closed()` and therefore includes a CA
   pin that failed its trust check or digest. `ManagedNetwork` has no
   `default` field. `network.proxy` takes `locked` only; `no_proxy` and the
   mirrors take a default.
4. **`network_policy_invalid` is a new cause**, `NetFailure::PolicyInvalid`
   ("The managed network policy cannot be used: ..."; recovery: ask your
   administrator, nothing was sent). It is never retried and its recovery never
   points at Settings. The design called it an existing failure; the existing
   one is `network_settings_invalid`.
5. **`pam policy check`** is `pam policy check <file> [--platform
   macos|windows] [--trust] [--json]`, with `--for` as an alias of
   `--platform`. Exit `0` valid, `13` leaf problems, `12` file-level invalid,
   `11` not trusted (`--trust` only; it takes precedence over 12 and 13
   because the daemon never reads an untrusted file's content), `1` unreadable
   (missing, not a regular file), `2` usage (including `--trust` with another
   platform). **`--installed`, `--expect-revision` and exits `10` and `14` were
   not built:** `--trust` answers the installed-file question for any file it
   is given, at the fixed path or not, and the JSON document carries
   `meta.revision`, `digest` and `trust.at_fixed_path`, so a script compares a
   revision itself. A missing file at the fixed path is exit `1`, not `10`. The
   one-line compliance command an MDM script uses today is
   `pam policy check "/Library/Application Support/PAM/policy.json" --trust --json`
   on macOS and
   `pam policy check "$env:ProgramData\PAM\policy.json" --trust --json`
   (PowerShell) on Windows; exit `0` is compliant. The samples are
   `docs/policy/{minimal,network-only,strict-fleet}.json`, kept valid by
   `crates/pam/tests/policy_cli.rs` (not `docs/managed-policy/samples/` and a
   `managed_policy_samples_test.rs`).
6. **A CA bundle pinned on Windows is rejected (decision note 751).** A
   `network.ca_bundle.locked: {path, sha256}` in a Windows policy is a rejected
   leaf with the code `network_ca_unsupported_on_windows` and the recovery
   "install the CA in the Windows certificate store through MDM". It is not
   held and not taken from a last-good copy, so it never closes the network:
   the pin has no effect and PAM stays on store trust. `locked: null` (store
   trust) is valid. `pam policy check --platform windows` reports it (exit
   `13`). Reason: the measured Schannel behaviour (plan 52) is that a `cacert`
   file replaces the store's trust and breaks public hosts, and closing the
   network over it would take a fleet's connectors down over a policy mistake.
7. **The control plane is exempt from never-grant rules (decision note
   752).** `grants.never` and `never_classes` refuse `policy_denied` on every
   profile, before the grant lookup and any auto-grant, for every class except
   Control (`status`, `query`, `cancel`, `doctor.report`), so `never: ["*"]`
   cannot take down the control plane. Read-only capabilities are denied.
   `flow.inspect` applies the same rule (`inspect_admission`), so it never
   shows a step admissible that the gate refuses.
8. **D6 as implemented.** A proxy locked with `auth: none`, or pinned direct
   (`locked: null`), also locks the password; a locked proxy with `basic` or
   `anyauth` leaves the password field the human's to type, and a patch that
   sets only the password is not counted as a proxy change.
9. **`admin.policy.get`** is T3's `admin_json()` plus `origin.trust` and
   `compliance`: `trust { verdict: trusted|untrusted|busy|absent, code,
   recovery, owner, writable_by_user, symlink, parents }`, each fact `ok`,
   `failed` or `unknown` (the check stops at the first failure, so the facts
   after it are `unknown`). `compliance.login_unit.present` is `true`/`false`
   on macOS (a plist under `~/Library/LaunchAgents` or `/Library/LaunchAgents`
   with the unit's label) and **`null` on Windows**, because only `schtasks`
   can tell and a read op spawns no program; the GUI's own `service status`
   answers there. The compliance block is on the admin op only, not in
   `status.policy`.
10. **Audit `trigger` wording.** Rows written by the policy service carry
    `trigger: boot | poll | reload`; `reload` is the word for an explicit
    re-read, so the `policy.load`, `policy.reject` or `policy.clear` rows an
    `admin.policy.reload` causes say `reload` and sit on the op's own request.
    The op's terminal `admin` row says `trigger: "admin"` with the prior and
    new state and digest. `policy.clear` carries `{trigger, prior_digest}`.
    `policy.reject` is written once per `(code, digest, fingerprint)`.
11. **Last-good row.** `setting` row `policy.last_good`: a JSON header line
    `{format, digest, loaded_ts}`, a newline, then the exact file text
    (escaping the text would push a 64 KiB file past the 70 KiB bound). It is
    read through a new bounded store accessor, ignored when the text's
    SHA-256 differs from the header, and re-parsed by the running binary. A
    copy is not replaced while one of its leaves is what holds a rejected leaf
    of the newer file.
12. **The `status` block and the `pam status` line.** `status.policy` is
    `{state, revision, digest (12 hex), loaded_ts, managed, rejected_leaves}`,
    from memory. The `pam status` line carries no organization (D13 keeps it
    off the public plane, which the design's example line contradicted):
    `policy: none (unmanaged)`, `active, rev R, digest D`, `degraded, rev R,
    digest D; N leaves rejected, the rest applies`, `last_good, ...; the
    policy file cannot be used, the last good copy is in force`, or `frozen;
    ... changes that widen what agents can do are paused`; `?` for an older
    daemon.

### Behaviour that differs from the design

13. **Trust check.** The positive unix fixture is a `0444` file: under the
    write probe a `0644` file the daemon's own user owns is writable by that
    user and is refused, which is correct; `0644` is the production case for a
    root-owned file. A swap between the stat and the open is `busy`
    (transient: the previous view stays and the next poll reads in full), not a
    hard refusal, because the delivery script's `mv -f` produces exactly that
    race. A file that disappears after the first look is `busy`, not absent.
    Execute bits and setuid/setgid/sticky are refused (`not_regular`). On
    Windows `FILE_WRITE_ATTRIBUTES` is probed too, since a token with it can
    clear a read-only attribute. A path that is not canonical is refused, so a
    CA bundle path must be canonical (on macOS `/etc` is a symlink).
14. **Grammar.** Host lists use the no-proxy grammar, which refuses wildcards:
    `*.example.com` is a rejected leaf (write `example.com`; a domain covers its
    subdomains). String, list, control-character and `reason` limits are leaf
    level, not file level (D5). An empty `network.mirror_allowed_hosts: []` is
    rejected (the network service would read it as any host), while an empty
    `allowed_base_hosts` or `allowed_github_servers` means none. A section that
    is not an object rejects every key it would hold, and dotted member names
    are unknown keys. A retention pair breach is reported on
    `retention.evidence_days`. `models.dir` must be absolute (no `~`); an idle
    `max` must be at least 1.
15. **Frozen.** A frozen view (a file-level failure with no last good copy)
    holds every Tier A key and leaves the network open (intent unknown).
    `profile.set` to a value at least as strict as the effective profile and
    `grants.revoke` still pass; the exception lives in
    `policy::check_profile_write`. A CA pin that failed its import refuses a
    human edit with `setting_locked`, not `policy_frozen`, because the view
    has no way to mark a leaf held after the fact (`reject_leaf` was left as
    optional).
16. **Defaults.** A profile `default` seeds the row on first boot, so the
    effective entry reads `source: user` afterwards. A retention window the
    human never set that the policy manages stays unset on save, so the
    policy default keeps applying; a garbled stored window stays forever (a
    `max` still clamps it).
17. **Paths.** `scopes.allowed_repository_roots` prefixes are compared by
    component against canonical repository roots: write canonical prefixes
    (`/private/var`, not `/var`, on macOS). `PathRule::covers` strips the
    Windows verbatim prefix (`\\?\C:\...`) itself.
18. **Consumers.** Connector summaries report `enabled` as the row enabled and
    not policy-disabled. A reload that moves the effective `models.dir`
    unloads the loaded model (a change hook). The follow path of public
    results authorizes under the policy view, so a repository the policy drops
    cannot keep following an earlier ticket. A program the policy removes is
    refused before the gate and again before spawn.
19. **Reload and the GUI.** No `policy.changed` hub event was registered:
    both admin ops reply with the fresh body, and the GUI re-reads on mount,
    on window focus and after Check now (which invalidates every `effective`
    query). Opening Settings reads `admin.policy.get`; it does not reload,
    because a reload writes audit rows.
20. **GUI.** The Managed policy view is a panel in Settings › Security, not a
    tab; a status line in the Settings header says "Managed by your
    organization's policy." or the warning for a degraded, last-good or frozen
    state. A policy default is labelled only for `source: policy` with
    `locked: false` (`source: default` means no policy is in play). Every
    user-facing string, daemon and GUI, is spelled "organization" (the design
    said "organisation"; T12 unified it). Checked in jsdom only, not in the
    Tauri shell.
21. **Not built.** The doctor's `policy_file_trusted` check and
    `--require-policy`; the `status.policy.compliance` block (compliance is on
    `admin.policy.get`); the reload when Settings opens (19).

### Open items

- **T13, Windows VM: done 2026-10-03** (branch `win-fix/policy`): the `cfg(windows)`
  halves, the ACL fixture matrix as the interactive user and the all-untrusted
  run as SYSTEM, the delivery script end to end, the daemon against the real
  file, and the [evidence](#evidence-to-record) facts. What the OS contradicted
  is corrected in the rules above. Not done: a run as a true standard user (the
  VM's interactive account is a UAC-filtered administrator) and a run as an
  elevated administrator other than SYSTEM.
- **T13, owner's macOS pass with `sudo`:** install a sample at the real path;
  `pam policy check "/Library/Application Support/PAM/policy.json" --trust`
  exits `0` and `pam status` shows `active`; `chmod g+w` exits `11` and the GUI
  says why; an ACL (`chmod +a "user:<you> allow write"`) exits `11`; deleting
  the file reads `none` after two polls.
- Open questions 1 and 2 were decided by the owner's delegation (note 743):
  the token probe ships for v1, and the file is the only transport until a
  pilot needs another.
- Optional cleanups left as they are: `load_effective` to `load`, a
  `reject_leaf` on the view, the frozen-tightening exception moved into
  `check_profile`.

## Evidence to record

Facts this design assumes about Windows and macOS, to be proved in T13 and
appended here (a contradicted fact corrects the text above before merge):

1. `icacls` on a fresh `%ProgramData%\PAM` shows `BUILTIN\Users` with create-file
   or write rights (the reason for cutting inheritance), and after the delivery
   script shows only the three SIDs.
2. `OpenOptions::access_mode(FILE_WRITE_DATA)` (and each other right in the file
   and directory lists) fails with access denied for a standard user on the locked
   ACL and succeeds under each negative fixture; a directory open needs
   `FILE_FLAG_BACKUP_SEMANTICS`; an open with an access mask and no write
   disposition changes neither content nor timestamps.
3. `file_type().is_symlink()` is true for a junction and for a symlink on the
   runner's Rust version.
4. `FILE_SHARE_READ` makes a concurrent writer fail, and an MDM-style writer
   mid-write yields `busy` here, not `untrusted`.
5. PowerShell 5.1 `Set-Content -Encoding UTF8` writes a BOM; the policy with one
   parses and its digest covers it.
6. `Move-Item -Force` within the folder keeps the inherited locked ACL on the
   replacement, and the `ca` subfolder created after `icacls` inherits it.
7. macOS: `/Library/Application Support` is `root:admin 0755` (checked on this
   machine, 2026-10-02) and the group has no write; the real-path install passes
   the production rule; `chmod g+w` and an added ACL are each refused.
8. `prlctl exec ... --current-user` is available on the VM image and runs as the
   unprivileged logged-in user.

### Recorded 2026-10-03: Windows VM (T13 step 2)

Host: Parallels "Windows 11", ARM64, Windows 10.0.26200.8873, Rust 1.98.1,
tree `cd43846` plus the fixes on `win-fix/policy`. The interactive account
(`prlctl exec --current-user`, item 8) is `rodrigoagur2864\rodox`, a member of
`Administrators` whose medium-integrity token carries that group deny-only (UAC
filtered); it is not a standard user. Every row is measured unless it says
otherwise.

1. **Measured.** A fresh `%ProgramData%\PAM` (`icacls`): `SYSTEM` and
   `Administrators` `(I)(OI)(CI)(F)`, `CREATOR OWNER` `(I)(OI)(CI)(IO)(F)`,
   `Users` `(I)(OI)(CI)(RX)` and `Users` `(I)(CI)(WD,AD,WEA,WA)`, so `Users` can
   add files and subfolders. After the delivery script the folder shows only
   `Users:(OI)(CI)(RX)`, `Administrators:(OI)(CI)(F)`, `SYSTEM:(OI)(CI)(F)`;
   `policy.json` and a later `ca` subfolder carry the same three inherited
   (`(I)`); owner `BUILTIN\Administrators`.
2. **Measured, one rule corrected.** On the locked ACL the interactive account
   is trusted (exit 0). Each fixture (`Users` modify on the file; write on the
   folder only, with and without inheritance; the default ProgramData subfolder
   ACL; owner set to the account; `DELETE` only; `FILE_DELETE_CHILD` only)
   reads untrusted with the expected code, except that `FILE_DELETE_CHILD`
   reports `writable_by_user`, not `parent_writable`, because that folder right
   also grants `DELETE` on the files in it (rules above). A directory open
   without `FILE_FLAG_BACKUP_SEMANTICS` fails with error 5 for every right; with
   it, the right is granted or not as the ACL says. A probe open with each of the
   six file rights leaves length, modified, accessed and created times and the
   content unchanged. `the_acl_fixture_matrix` (all ten cases, `busy` included)
   passes as the interactive account.
3. **Measured.** `is_symlink()` is true for a symbolic link to a file and for a
   junction: a junction as `%ProgramData%\PAM` reads `symlink` (the folder). A
   junction *at the file path* never reaches the trust check from the CLI:
   `pam policy check` exits 1 ("not a regular file") because it follows the link
   to read the content; the daemon's `verify_and_read` judges the link first.
   Correction: the CLI used to resolve the parent folder before the trust check,
   so a junction at `%ProgramData%\PAM` pointing at a locked folder read
   trusted from `pam policy check` while the daemon refuses it; the fixed path is
   now judged as spelled (`trust_check_path`).
4. **Measured.** A writer holding the file with `FileShare` `Read` or
   `ReadWrite` gives `busy` (exit 11) as the account; the unprivileged probes
   fail with access denied before any sharing check, so the sharing violation
   comes from the final read open. With `FileShare.None` the daemon check gives
   `busy` (matrix `busy` case) but `pam policy check` exits 1 ("used by another
   process", os error 32) because its own content read opens the file first.
   Retry later. As SYSTEM the probe itself can hit the violation first
   ("holds it exclusively") or, with a `ReadWrite`-sharing writer, succeed and
   read `writable_by_user`.
5. **Measured.** `Set-Content -Encoding UTF8` in Windows PowerShell 5.1 writes
   `EF BB BF`; the policy parses (trusted, exit 0) and its digest equals
   `Get-FileHash` SHA-256 of the file including the BOM.
6. **Measured.** `Move-Item -Force` of a temporary file made inside the folder
   keeps the inherited locked ACL (trusted). A file moved in from
   `C:\Windows\Temp` keeps its own ACL (no `Users` entry): `pam policy check` exits
   1, "Access is denied" (the daemon would report it unreadable; not measured
   at the daemon). `Copy-Item -Force` over the existing file keeps the
   destination's ACL (trusted).
7. **Measured on macOS 26, 2026-10-03** (the owner's `sudo` pass, a scratch daemon
   base, the built binary): the sample installed with `install -m 0644 -o root
   -g wheel` under a `root:wheel 0755` `PAM` folder reads trusted (`pam policy
   check --trust` exit 0: owner uid 0, mode 0644, every parent rule ok) and the
   daemon reports `policy: active, rev 2026-10-02.1` within one poll;
   `chmod g+w` is refused `writable_by_user` (mode 0664), exit 11; an ACL
   `user:<owner> allow write` that the mode bits do not show is refused
   `writable_by_user` by the write probe, exit 11; deleting the folder returns
   the daemon to `policy: none (unmanaged)` within the absence-confirmation
   window. Everything the pass created was removed. PAM itself ran as the user
   throughout; `sudo` stood in for the MDM that installs the file.
8. **Measured.** `prlctl exec ... --current-user` is available and runs as the
   interactive account (above).

Run as SYSTEM (every right held): every case is untrusted, as the spec intends
for an elevated daemon: the locked delivery reads `writable_by_user` (the file
probe opens `FILE_WRITE_DATA`), a symlink or junction reads `symlink`, and a
writer that excludes sharing reads `busy`; `the_acl_fixture_matrix` with
`PAM_TRUST_FIXTURES_ELEVATED=1` passes. The consequence is the one the spec
states: PAM must not run as SYSTEM or elevated if it is to honour a policy.

Daemon against the real file, `PAM_BASE_DIR=C:\pampol`, started by `pam status`
as the interactive account, policy at `%ProgramData%\PAM\policy.json` (locked
profile `strict`, `grants.never` `flow.step:*/deploy`): `pam status --json`
reports `policy.state: active`, revision, digest prefix `f94aac30ddb6` (equal
to the file's SHA-256); `admin.profile.set` to `relaxed` and `standard` is
refused `setting_locked`, `admin.grants.add flow.step:x/deploy` is refused
`policy_not_allowed`, `admin.policy.get/reload` answer (the admin plane was
driven by `pam_client::client::send_admin` from a scratch test, as no CLI
command sends admin ops). Granting the account write on the file and reloading
reads `last_good`; removing the ACE and reloading reads `active`. Deleting the
file reads `none (unmanaged)` about 110 s later (two 60 s polls).

Windows-only test breakage found and fixed: nine CA-bundle import tests pinned
a bundle on a Windows host and failed against the intended rule
(`network_ca_unsupported_on_windows`); they run off Windows only and a Windows
test (`a_pinned_ca_bundle_on_windows_is_rejected_and_never_closes_the_network`)
asserts the rejected, never-held, network-open behaviour. A `pam` lib test
import was unused on Windows (clippy `-D warnings`).
