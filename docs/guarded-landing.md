# Guarded landing

Task #135 adds `guarded-land` to the existing flow executor. It uses no model.
The CLI submits a ticket through PAM's internal Unix socket; the daemon owns
approval, credentials, bounded execution, evidence and recovery. This document
describes the implementation under qualification. The sync adapter landed on
2026-09-12 (see the [guarded sync contract](specs/2026-09-12-guarded-sync.md));
the complete recipe runs end to end against the fixtures, and the enterprise
checkpoint (#94) is what still separates it from a supported claim. Inspection
reports `landing_permission_missing` for any stage the GUI policy has not
granted, sync included.

Guarded landing runs on macOS only. Its local Git (checkout, checks, sync) runs
inside [command containment](command-containment.md), which Windows does not
have, so on Windows a landing refuses `command_containment_unavailable` before
any local Git starts. `pam status` and Settings › Daemon say so ahead of time.

## Configure and inspect

In **Settings → Flows → Landing**, configure the canonical local repository,
exact HTTPS remote, GitHub API server and owner/repository, base branch, exact
allowed feature branches, private workspace directory, mandatory local checks,
required PR and main checks, the merge method, and separate push/PR/merge/sync
permissions. One Git path, optional, applies to every recipe. The connector must
also have a current repository scope and credential. Editing this policy
requires the private GUI administration channel. A flow cannot grant itself any
of these permissions. Stale GUI editors must reload before saving.

**Required checks** are written one per line as `name`, or `name @app-id` to
pin the check to the GitHub App that reports it (GitHub Actions is app 15368);
the stored form is `{ "name": …, "app_id": … }`. A pinned check is satisfied only
by a check run whose `app.id` is that app: a same-named check run from any other
app, or one with no app identity, is ignored (and counted in the evidence as
`other_apps`), and a commit status never satisfies it, since statuses carry no
app identity. A name-only check still works as before, matched by name across
check runs and commit statuses, and the form shows it as "Unpinned app" with the
recommendation to pin it. A recipe whose checks are all pinned reads check runs
only.

**Merge method** is `squash` (the default), `merge` or `rebase`. Before
journalling the merge, `merge` reads the repository (`GET /repos/{owner}/{repo}`)
and refuses `landing_merge_method_forbidden`, naming the methods it does allow,
when GitHub reports the chosen one as not allowed (`allow_squash_merge`,
`allow_merge_commit`, `allow_rebase_merge` false). A field GitHub does not report
(a credential without enough access to see the settings) does not refuse there;
GitHub's own refusal of the merge is then typed (below).

**The Git** the landing runs is never looked up on `PATH`. With no Git path set,
the broker takes the first qualifying entry of a fixed allowlist: on macOS the
active developer directory's Git (Apple's `/usr/bin/git` is an `xcrun` shim and
is never run; PAM reads the root-owned `/var/db/xcode_select_link`, which is what
`xcode-select -p` reports, and takes `<developer dir>/usr/bin/git`), then
`/Library/Developer/CommandLineTools/usr/bin/git`, then `/opt/homebrew/bin/git`;
on Windows `C:\Program Files\Git\clangarm64\bin\git.exe` (ARM64) or
`C:\Program Files\Git\mingw64\bin\git.exe` (x64), then
`C:\Program Files\Git\cmd\git.exe` (the launcher for it). A candidate qualifies
when it is an existing executable regular file and the spelled path, its
canonical target and every directory above each are owned by root or the
daemon's user and writable by neither a group nor others (on Windows: no link or
junction on the way, and the daemon's account holds no right to write, delete,
re-permission or re-own the file or any folder above it). Homebrew's default
prefix is group-writable for `admin`, so a default Homebrew Git does not qualify.
An explicit Git path is checked the same way when it is saved and at every use,
and is never replaced by an allowlist entry when it fails. None qualifying
refuses `landing_git_untrusted`, naming each candidate and why it failed. The
freeze records the resolved path, who chose it (`policy`, `settings` or
`allowlist`) and its `git --version` in the landing session and the freeze
receipt; every later stage must resolve to the same executable or refuses
`landing_git_changed`, and the Git broker re-checks it before every Git process
it starts.

A managed policy can set these too: `landing.git_path` (an absolute path) and
`landing.merge_method` each take `locked` or `default`. A locked value replaces
the human's in every check, shows read-only in the form, and refuses a save that
changes it (`setting_locked`).

The workspace directory must already exist, be private to the daemon user
(`0700` on Unix), and be outside both the source repository and PAM's private
data directory. Optional cache directories are explicit read-only grants; PAM
does not discover and grant all personal caches automatically.

From the approved repository, inspect the exact identity before execution:

```sh
pam flow inspect guarded-land repository=https://github.com/ORG/REPO commit=FULL_COMMIT_SHA --json
pam flow run guarded-land repository=https://github.com/ORG/REPO commit=FULL_COMMIT_SHA --no-wait --json
pam wait TICKET --json
pam flow result TICKET --json
```

Replace placeholders with the configured identity and full commit. Inspection
does not contact GitHub, unlock a credential or approve execution. Existing
profile and per-stage approval rules still apply at execution time.

## Stage contract

| Stage | Required evidence before advancing |
| --- | --- |
| `freeze` | Clean ordinary Git checkout, exact HEAD/branch/base/remote, bounded verified source manifest and private sealed checktree |
| `validate` | Every GUI-configured command succeeds against that checktree, with command identity, retained output and manifest binding |
| `push` | Fresh unchanged source and policy; exact authorized remote ref receives the frozen SHA, with an explicit old-ref lease |
| `ensure_pr` | One matching same-repository PR has the exact head, base and frozen head SHA: open, or already merged at that exact head |
| `verify_pr` | Every declared required check is successful for that exact head SHA; a PR merged at that head is accepted, one closed without a merge conflicts |
| `merge` | Fresh PR and check evidence, separate permission, a merge method the repository does not forbid, and GitHub's expected-head-SHA merge condition |
| `verify_main` | Every declared main check succeeds for the merge SHA returned by GitHub |
| `sync` | The verified merge commit fetched as a bounds-proven thin pack through the HTTP broker, indexed privately, installed into the source object store, and the base branch fast-forwarded under an exact old-value lease; working tree untouched |

The YAML parser accepts only this ordered sequence or an ordered prefix, with
successful direct prerequisites. It rejects custom commands, URLs, retries or
effect overrides on landing stages. A successful prefix is not a landed branch.
Tags, publishing and branch deletion are outside this recipe. The flow result
lists each completed mutation under `effects` with its landing operation, so a
`freeze, validate, push` prefix reads as exactly that and not as a landing.

A new ticket can finish a landing that an earlier ticket merged and then ran out
of polls on: `ensure_pr` accepts a PR already merged at the exact frozen head,
`verify_pr` still requires the checks for that head, and the ticket continues
through `verify_main` and `sync` without a new POST or PUT. One wrinkle remains:
if GitHub deleted the head branch on merge, the new ticket's `push` stage
re-creates it at the frozen commit before `ensure_pr` finds the merged PR.

GitHub's merge API atomically checks the head SHA. The observed base SHA is not
an atomic base guard. PAM must not claim otherwise or treat a preceding GET as
closing that race. Required checks must have unique, complete membership;
missing, duplicate, pending, skipped or ambiguous results cannot produce green,
and a pinned check is matched by `{ name, app_id }`, never by name alone.

## Local checks and boundaries

Checks have a bare allowlisted program and literal argument vector. No shell is
involved. `${source}` expands to the sealed source directory; `${artifacts}`
expands to its separate private writable output directory. Other shell variables
are not expanded. Cargo output, temporary files, HOME and npm cache are directed
to private output directories. Configure tools with their appropriate output
arguments and provide approved offline caches where needed. A recipe that needs
network access during validation refuses under the command containment policy.

Source files stay read-only during checks. Build scripts cannot read PAM's
private store or keychain, use network/Mach services, or write into the original
checkout. Explicit cache mounts cannot replace existing tracked source data.
The current OS command profile is qualified on macOS; other platforms refuse.

The initial checkout implementation supports ordinary SHA-1 repositories only.
It refuses linked worktrees, shallow source repositories, source alternates,
submodules and tracked symlinks. Capture is capped at 4,096 files, 4 MiB per file,
64 MiB total source and a 512 KiB serialized manifest. Before any Git process
runs, PAM also walks the source repository's `.git` directory itself and refuses
a metadata tree with more than 32,768 entries, or one containing a symlink or
any other non-regular file. These are explicit product limits, not evidence
that all enterprise repositories have been qualified.

The sealed checktree lives in `<workspace directory>/landing-<ulid>/tree`, with
its private build outputs beside it. PAM removes that whole `landing-<ulid>`
directory when the ticket ends, whatever the outcome, so that mandatory checks
have somewhere to run while the ticket can still resume and nothing is left
behind once it cannot. A ticket parked between required-check polls keeps its
workspace. The directory is only ever removed when it still has exactly that
shape under the currently configured workspace directory.

## Durable effects and bounded waiting

Each mutation has a private prepared intent on the original ticket. A crash,
timeout or lost response does not authorize repeating it. Recovery reads the
remote state and compares it with the frozen intent. Conflicting or inconclusive
state remains uncertain and requires reconciliation. Ordinary stateful command
steps do not acquire this typed recovery behavior.

For push and sync the intent also records what the Git process itself reported
once it has run: `uncertain` until it reports, then `reported_success` or
`rejected`. A push that Git rejected, leaving the exact remote ref at the
old value PAM observed, refuses as `landing_push_rejected` — on the attempt
that ran it and again on resume, when the journalled verdict says `rejected`
and the ref is still unchanged. A prepared push or sync found unchanged on
resume with no verdict journalled (the daemon died before Git reported), one
Git reported complete while the ref stayed put, and a ref that moved to
anything else all refuse as `landing_effect_uncertain`, with the detail saying
which of the three it was. None of them is resent automatically.

PR creation and merge are classified the same way. GitHub answering the POST or
PUT with a refusal is definite: nothing changed, the intent is settled
`rejected`, and the step blocks with a typed cause and its recovery instead of
`landing_effect_uncertain`. The causes are `landing_pr_already_exists`,
`landing_pr_no_commits` and `landing_pr_rejected` (422 on creation), and
`landing_merge_head_modified` (409, or "head branch was modified"),
`landing_merge_method_not_allowed`, `landing_merge_checks_required` ("required
status checks are expected"), `landing_merge_conflict`,
`landing_merge_not_mergeable` (405) and `landing_merge_rejected` (another 422).
A rejected credential, a forbidden or missing resource and throttling (401, 403,
404, 429) are definite too, as is anything refused before the request left. The
response body only selects the cause; it is never kept. Only a failure after the
request was sent that leaves the outcome unknown (a lost answer, a timeout, a
5xx, a redirect, a success body PAM cannot read) keeps the intent prepared and
stays uncertain.

Policy revision, original admission, grant revision, scope, expiry and shared
budget are checked again before work. Git credentials are supplied only to the
fixed broker operation; source Git configuration, hooks and credential helpers
are not evaluated by the network process. Its private object store is disconnected
from source objects before credentials are supplied.

Before each write to the source repository, `sync` walks `.git/objects/pack`,
the ref's directory and the reflog directory one component at a time and refuses
anything that is not a real directory (an existing reflog must be a regular
file), so a directory swapped for a symlink stops the write. A swap in the
instants between that walk and the write is not excluded: the workspace has no
`openat`-style handle API.

PR and main verification poll with exponential backoff: about five seconds
before the second look, doubling to a sixty-second cap, each wait shortened by a
jitter of up to a fifth drawn from the ticket and step. There is no fixed poll
count: the landing keeps polling while the original request deadline leaves
room, cutting the last wait to what remains after a two-second headroom, and
refuses `request_deadline_exhausted` only when less than one second would be
left (the recovery: a new ticket for the same commit resumes from GitHub's state
without repeating any effect). The deadline (one hour at most) therefore bounds
the number of polls, about sixty at the cap. The request's HTTP allowance is a
separate bound: a poll that would leave fewer than twelve calls for the
remaining verification refuses `landing_poll_budget_exhausted`, and a pinned
check list spends one call per poll instead of two. Waiting releases the
repository lane. Unchanged polls reuse the protected checkpoint rather than
copying it.
The CLI receives compact published evidence; private intents and manifests are
not exposed as public evidence pages.

Native Git accounting reserves a conservative transfer allowance; it does not
claim to count every HTTP exchange inside Git. Object, metadata, output and time
limits remain independent of that reservation. Insufficient budget refuses work
before its external effect. Synchronization never runs Git against the network:
the pack arrives through the bounded HTTP transport (64 MiB), every entry is
inflated by the pure-Rust decoder to prove object count, per-object and expanded
totals before `index-pack`, and the only writes to the source repository are one
complete pack and one ref file. Large-history projection remains under
qualification in task #135.

## Completion evidence

The implementation checkpoint requires actual contained checkout/check fixtures,
temporary-repository Git transfer tests, fake-provider runtime tests with exact
SHA checks, and crash/revocation/failure cases proving that mutations are not
replayed. Fake providers do not establish compatibility with a live enterprise
GitHub server. A terminal ticket alone is not success: inspect its outcome and
the final stage receipts. Failed validation, checks or synchronization must never
be reported as a fully landed branch.
