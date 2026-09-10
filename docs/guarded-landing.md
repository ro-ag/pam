# Guarded landing

Task #135 adds `guarded-land` to the existing flow executor. It uses no model.
The CLI submits a ticket through PAM's internal Unix socket; the daemon owns
approval, credentials, bounded execution, evidence and recovery. This document
describes the implementation under qualification. Until the sync adapter and
end-to-end checkpoint pass, the complete recipe is not ready for use. Inspection
reports `landing_sync_unavailable`; running a recipe that contains sync refuses
before any checkout capture, validation command or remote operation.

## Configure and inspect

In **Settings → Flows → Landing**, configure the canonical local repository,
exact HTTPS remote, GitHub API server and owner/repository, base branch, exact
allowed feature branches, private workspace directory, mandatory local checks,
required PR and main check names, and separate push/PR/merge/sync permissions.
The connector must also have a current repository scope and credential. Editing
this policy requires the private GUI administration channel. A flow cannot grant
itself any of these permissions. Stale GUI editors must reload before saving.

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
| `ensure_pr` | One matching same-repository PR has the exact head, base and frozen head SHA |
| `verify_pr` | Every declared required check is successful for that exact head SHA |
| `merge` | Fresh PR and check evidence, separate permission and GitHub's expected-head-SHA merge condition |
| `verify_main` | Every declared main check succeeds for the merge SHA returned by GitHub |
| `sync` | Guarded local synchronization confirmed by a typed receipt; currently pending adapter qualification |

The YAML parser accepts only this ordered sequence or an ordered prefix, with
successful direct prerequisites. It rejects custom commands, URLs, retries or
effect overrides on landing stages. A successful prefix is not a landed branch.
Tags, publishing and branch deletion are outside this recipe.

GitHub's merge API atomically checks the head SHA. The observed base SHA is not
an atomic base guard. PAM must not claim otherwise or treat a preceding GET as
closing that race. Required checks must have unique, complete membership;
missing, duplicate, pending, skipped or ambiguous results cannot produce green.

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
64 MiB total source and a 512 KiB serialized manifest. These are explicit product
limits, not evidence that all enterprise repositories have been qualified.

## Durable effects and bounded waiting

Each mutation has a private prepared intent on the original ticket. A crash,
timeout or lost response does not authorize repeating it. Recovery reads the
remote state and compares it with the frozen intent. Conflicting or inconclusive
state remains uncertain and requires reconciliation. Ordinary stateful command
steps do not acquire this typed recovery behavior.

Policy revision, original admission, grant revision, scope, expiry and shared
budget are checked again before work. Git credentials are supplied only to the
fixed broker operation; source Git configuration, hooks and credential helpers
are not evaluated by the network process. Its private object store is disconnected
from source objects before credentials are supplied.

PR and main verification each allow at most 20 polls at five-second intervals,
within the original request deadline and budget. Waiting releases the repository
lane. Unchanged polls reuse the protected checkpoint rather than copying it.
The CLI receives compact published evidence; private intents and manifests are
not exposed as public evidence pages.

Native Git accounting reserves a conservative transfer allowance; it does not
claim to count every HTTP exchange inside Git. Object, metadata, output and time
limits remain independent of that reservation. Insufficient budget refuses work
before its external effect. Large-history projection and bounded synchronization
are still under qualification in task #135.

## Completion evidence

The implementation checkpoint requires actual contained checkout/check fixtures,
temporary-repository Git transfer tests, fake-provider runtime tests with exact
SHA checks, and crash/revocation/failure cases proving that mutations are not
replayed. Fake providers do not establish compatibility with a live enterprise
GitHub server. A terminal ticket alone is not success: inspect its outcome and
the final stage receipts. Failed validation, checks or synchronization must never
be reported as a fully landed branch.
