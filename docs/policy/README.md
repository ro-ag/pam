# Managed policy: delivering and checking the file

An organisation can manage PAM on its machines with one read-only JSON file,
delivered by MDM. This page is for the administrator who writes and ships it.
The design, with every rule and its reasons, is in
[the managed policy spec](../specs/2026-10-02-managed-policy-file.md).

## What the file governs

The file can lock, default or bound the settings a person otherwise chooses in
the PAM GUI, and add constraints only an organisation can state:

| Section | What it can manage |
| --- | --- |
| `security` | The security profile (`locked`, `default`, or a `floor`), whether grants may be given by hand or remembered, and capabilities that are never granted (`never`, `never_classes`). |
| `scopes` | The repository roots PAM may work in; whether a connector may be granted across every repository. |
| `connectors` | The hosts a connector may send a credential to; connectors that are switched off. |
| `flows` | The programs flow steps may run, extra `PATH` entries and read-cache mounts (`locked` or an `allow` set), the artifacts folder. |
| `landing` | The most a landing may do (push, create a pull request, merge, sync) and the GitHub servers it may talk to. |
| `models` | Where the engine comes from (`download`, `mirror_only`, `import_only`), which model sources and curators are allowed, the models folder, idle unload. |
| `retention` | Evidence and audit windows (`locked`, `default`, `min`, `max`). |
| `network` | The proxy, the no-proxy list, a pinned CA bundle (macOS), and the engine and model mirrors with the hosts they may use. |
| `service` | Whether PAM is required to start at login (a compliance signal, not an enforcement). |

Top-level `version` (must be `1`), and optionally `revision`, `organization`,
`contact` and `comment`. The person sees `organization` and `contact` beside
every managed setting and in every refusal. Every key is in a closed table: an
unknown key is reported and rejected, never silently ignored.

The file never carries a secret, and it is world-readable by design. A proxy
that needs a password keeps the password in the person's keychain.

Two rules catch most first drafts:

- **Host lists take hosts and domains, not wildcards.** A domain already covers
  its subdomains, so write `example.com`, never `*.example.com` (the wildcard is
  rejected). CIDR ranges such as `10.0.0.0/8` are accepted in `no_proxy`.
- **Paths are checked for the target platform.** A macOS file uses
  `/Users/...`; a Windows file uses `C:\\Users\\...` (backslashes doubled in
  JSON). Check a Windows file with `--platform windows` from any machine.

## Where it lives

PAM reads exactly one path per platform. No flag, environment variable or PAM
setting can move it.

| Platform | Path | Owner and permissions |
| --- | --- | --- |
| macOS | `/Library/Application Support/PAM/policy.json` | `root:wheel`, mode `0644`; the `PAM` folder `root:wheel 0755`; every folder above it owned by root and not group- or world-writable. |
| Windows | `%ProgramData%\PAM\policy.json` | Inheritance cut on `%ProgramData%\PAM`; `SYSTEM` and `Administrators` full control, `Users` read and execute. |

A CA bundle the policy pins (macOS only) sits beside it, by convention in
`/Library/Application Support/PAM/ca/`, with the same ownership. On Windows,
install the CA into the Windows certificate store through MDM instead; a pinned
`network.ca_bundle` in a Windows file is rejected and has no effect.

PAM verifies all of this every time it reads the file. On macOS it checks the
owner, the mode bits, every parent folder, that nothing in the path is a
symlink, and that the PAM process cannot open the file for writing. On Windows
it asks the operating system whether the PAM process's own account could
modify, delete or re-permission the file or its folder. A file that fails any
of these is ignored, and PAM says so in `pam status`, in the GUI and in the
audit trail. A PAM running as root or as an elevated administrator reads every
file as untrusted, because it could write it.

## Delivering it

Deliver the CA bundle first, then the policy that names it. Replace the file
atomically (write a temporary name, then rename), because PAM may read while you
write. PAM reads only `policy.json`; a leftover temporary file is never read.

### macOS: installer package, or a Jamf, Kandji, Intune or Mosyle script

In a package, install the files with owner `root`, group `wheel`, mode `0644`,
under folders with mode `0755`. As a script run as root:

```sh
set -euo pipefail
dir="/Library/Application Support/PAM"
install -d -m 0755 -o root -g wheel "$dir" "$dir/ca"
# Only with network.ca_bundle:
install -m 0644 -o root -g wheel corp-root.pem "$dir/ca/corp-root.pem"
install -m 0644 -o root -g wheel policy.json "$dir/.policy.json.new"
mv -f "$dir/.policy.json.new" "$dir/policy.json"
```

Do not use `/Library/Managed Preferences` (configuration profiles) for this
file: that channel is not read yet.

### Windows: Intune platform script, Win32 app, or GPO startup script

Run as SYSTEM in the 64-bit host. A new `%ProgramData%` subfolder lets `Users`
create files in it by default, so the script cuts inheritance and sets the ACL
by SID (the names are localized on non-English Windows):

```powershell
$dir = Join-Path $env:ProgramData 'PAM'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
icacls $dir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
$tmp = "$dir\policy.json.new"
[IO.File]::WriteAllText($tmp, [IO.File]::ReadAllText('.\policy.json'), (New-Object Text.UTF8Encoding $false))
Move-Item -Force $tmp "$dir\policy.json"
```

`*S-1-5-18` is SYSTEM, `*S-1-5-32-544` Administrators and `*S-1-5-32-545`
Users. Write the file without a byte-order mark as above; PAM tolerates one
(Windows PowerShell 5.1 `Set-Content -Encoding UTF8` writes it), but the digest
then differs from the file you checked.

## Checking it

`pam policy check` reads the file you name exactly as the daemon would. It needs
no daemon, writes nothing and opens no socket, so it runs on your workstation or
build agent (macOS or Windows) before the push.

```sh
pam policy check policy.json                     # this machine's path syntax
pam policy check policy.json --platform windows  # a Windows file, from a Mac
pam policy check policy.json --json              # one JSON document
```

It prints every key the file sets: its state (`applied` or `rejected`), its
tier, each mode with what it means, and the value or the reason it was
rejected. Then come unknown keys, the keys the file locks, the SHA-256 digest
and a verdict line. `--for` is accepted as another spelling of `--platform`.

| Exit | Meaning |
| --- | --- |
| `0` | Valid: every key applies. |
| `13` | Valid with rejected leaves or unknown keys: those do not apply, the rest does. |
| `12` | Invalid as a whole (not JSON, over 64 KiB, a duplicate key, a `version` other than `1`): PAM would use none of it. |
| `11` | With `--trust`: the file is not trusted where it sits. |
| `1` | The file cannot be read (missing, not a regular file). |
| `2` | Usage error (for example `--trust` with another platform's `--platform`). |

`--trust` also runs this machine's production trust check (owner, modes,
symlinks, parent folders, the write probe) on the file where it sits, and
reports each rule as `ok`, `failed` or `unknown`. The check stops at the first
failure, so the rules after it read `unknown`. On the endpoint, point it at the
installed file for a compliance check, for example in a Jamf extension attribute
or an Intune detection script:

```sh
pam policy check "/Library/Application Support/PAM/policy.json" --trust
```

```powershell
pam policy check "$env:ProgramData\PAM\policy.json" --trust
```

Exit `0` means that the installed file is trusted and valid. On a machine where
PAM is running, `pam status --json` reports the policy the daemon has in force
under `.policy` (state, revision and digest).

## Samples

Each sample passes `pam policy check --platform macos` with exit `0`; a test in
`crates/pam/tests/policy_cli.rs` keeps it that way. Copy one, then change the
labels, hosts and paths to yours.

| File | What it shows |
| --- | --- |
| [`minimal.json`](minimal.json) | The smallest useful policy: labels and a profile `floor` (people may pick `standard` or `strict`, never `relaxed`). |
| [`network-only.json`](network-only.json) | Network only: a locked proxy with no password, a locked no-proxy list of concrete hosts and a CIDR range, mirror defaults restricted to one mirror host. Nothing else is managed. |
| [`strict-fleet.json`](strict-fleet.json) | A strict fleet (macOS paths): the `strict` profile locked, approvals never remembered, capabilities that are never granted, a repository allowlist, a connector host allowlist, programs and `PATH` allow sets, no merge from a landing, a mirror-only engine with `mirror_allowed_hosts` and locked mirrors, a locked proxy with a default no-proxy list, retention minimums, and the login unit required. |

For Windows, change the two path lists in `strict-fleet.json`
(`scopes.allowed_repository_roots`, `flows.extra_path`) to Windows paths; as it
is, `--platform windows` rejects them (exit `13`).

## How PAM picks up a change

The daemon reads the file once at boot, before it serves anything. After that:

- every 60 seconds it looks at the file's size, time and identity, and re-reads
  it when any of them changed;
- every 10 minutes it re-reads and re-verifies the file regardless, so a changed
  owner or permission is noticed even when the content is not;
- the GUI's **Check now** button re-reads it at once.

A change applies to the next operation. Tightening a policy does not delete
anyone's grants: a grant the policy now denies stops working at its next use. A
removed file is confirmed by two checks at least 10 seconds apart, and the
machine is then unmanaged (that is what offboarding looks like).

## What the person sees

In the GUI, every settings page shows "Managed by {organization}" when a policy
is in force. A locked setting is shown disabled with a lock, the policy's
`reason` and the `contact`. A bounded setting shows the permitted range or set
next to the control, and a policy default is labelled as coming from the
organisation. **Settings > Managed policy** shows the file's path and how its
trust check went, its revision, digest, organisation and contact, when it was
loaded and last checked, and every key with its state and the reason for any
problem. Banners explain a degraded, last-good or frozen policy, and a missing
login unit the policy requires. An agent learns only that a policy exists, with
its state, revision and digest, never what it says. A request it makes that the
policy denies is refused with `policy_denied`.

## When the file is damaged

A file that cannot be used at all (untrusted, not JSON, over 64 KiB, a
duplicate key, an unsupported version) loses every key at once. PAM then keeps
the last good policy it verified, and with none it freezes every change that
would widen what agents may do. A file that parses but has a bad key loses only
that key, which takes its value from the last good policy when there is one;
otherwise it follows its tier. A Tier A key (authority, audit, egress: profile,
grants, scopes, connectors, programs, landing, retention, proxy, no-proxy, CA)
is held: its setting cannot be changed until the file is fixed, and a held
proxy, no-proxy or CA key stops connector calls and downloads rather than let
them bypass the proxy. A Tier B key (convenience: mirrors, folders, idle
unload, the login unit, the labels) falls back to the person's own value with a
diagnostic. A bad file therefore never loosens anything. Run
`pam policy check` before every push.
