# Guarded local synchronization (landing `sync`)

Status: contract for task #135's last stage, written 2026-09-12 after the
pure-Rust inflate decoder (flate2 with the miniz_oxide backend) was approved as
a direct dependency (ptrack issue #18). Companion to
[guarded landing](../guarded-landing.md) and the landing implementation in
`pam_daemon::landing_git`.

## What `sync` does

After `verify_main` confirms the merge commit `M` returned by GitHub, `sync`
brings `M` into the canonical local repository and fast-forwards the configured
base branch to it. Nothing else changes: no working tree write, no branch
deletion, no tag, no remote effect. The stage has exactly two effects on the
source repository, in this order:

1. one verified pack (`.pack` + `.idx`) appears under `.git/objects/pack/`;
2. `refs/heads/<base>` moves from the observed old value `B0` to `M` through a
   compare-and-swap `update-ref` that refuses if the ref moved meanwhile.

## Preconditions (all refuse before any effect)

- The policy grants the separate `sync` permission and the repository, remote,
  base branch and workspace are unchanged since freeze (same live checks as the
  other stages).
- `verify_main` receipt present; `M` is the `sha` of the `merge` receipt, a
  40-hex lowercase SHA-1.
- `HEAD` of the canonical repository is a branch other than the base branch
  (`landing_sync_base_checked_out` otherwise: fast-forwarding a checked-out
  branch would have to touch the working tree, which this stage never does).
  Through the orchestrator this is a second guard: the live check every stage
  runs already requires HEAD to remain the frozen feature branch and refuses
  with `landing_checkout_changed` first.
- `refs/heads/<base>` resolves to `B0`. If `B0 == M` the stage is already
  complete and returns the receipt without any transfer.
- The source repository is still an ordinary SHA-1 repository without
  alternates, linked worktrees or shallow state (`validate_layout`).

Every stage's live check compares the base ref with the frozen base commit.
Once the `merge` receipt exists, the live check also accepts the base ref at
that merge commit — the one value this ticket's own sync can move it to — so a
sync that landed just before a crash reconciles on resume instead of being
refused as a changed source identity. Any other base value still refuses with
`landing_checkout_changed` before any transfer.

## Transfer

The pack is fetched by the fixed broker HTTP transport (`pam_connectors::curl`),
not by Git, so the network process never evaluates source configuration and the
response size is capped before any byte is decoded:

- `POST <remote_url>/git-upload-pack`, content type
  `application/x-git-upload-pack-request`, the connector credential as
  `Authorization: Basic`, no redirects, 64 MiB response cap.
- The body is the only non-JSON body the transport admits:
  `0033want M \n0000` followed by at most two `0032have <sha>\n` lines and
  `0009done\n`. Haves are `B0` and the frozen head commit, so the server sends a
  thin pack holding only what is new relative to what the local repository
  already proves.
- The response preamble may only be `NAK`, `ACK <sha>[ …]` or a flush before the
  raw `PACK` bytes; `ERR` refuses with `landing_sync_remote_error`.

## Pre-index bounds (the decoder's job)

`pam_daemon::landing_pack::preflight_pack` walks every entry of the pack with
the pure-Rust inflater before Git sees it, and refuses on the first violation:

| Bound | Value |
| --- | --- |
| pack entries | 16,384 (`MAX_OUTBOUND_OBJECTS`) |
| single decoded object or delta result | 4 MiB (the source capture per-file cap) |
| sum of expanded sizes | 64 MiB (the source capture total) |
| compressed pack | 64 MiB (transport cap) |

Decoded lengths must equal declared lengths, delta result sizes are read from the
delta header, offsets must point inside the pack, and the trailer must be exactly
20 bytes. Native `index-pack` limits compressed input only; this preflight is what
substantiates the expanded bounds that ptrack issue #18 asked for. The measured
`PackBounds` are recorded on the receipt.

## Indexing and proof

Indexing runs in the private landing workspace (private `GIT_DIR`, scrubbed
environment, no credentials, `objects/info/alternates` pointing read-only at the
canonical object store so thin deltas can be completed):

1. `git index-pack --strict --fix-thin --stdin <workspace>/metadata/objects/pack/pack-sync.pack`
   with the verified bytes on stdin; the resulting pack name comes from Git's
   `pack\t<hash>` output line.
2. `git cat-file -t M` must be `commit`.
3. `git merge-base --is-ancestor B0 M` must hold (a fast-forward, nothing
   rewritten).
4. `git rev-list --objects --count B0..M` must stay under the entry bound.

## Installing the effect

The `.pack` and `.idx` are copied into `<repo>/.git/objects/pack/` under temporary
names and renamed into place (`pack-<hash>.pack` first, then `.idx`), so the
canonical repository only ever sees a complete pack. Then
`git update-ref -m "pam guarded-land sync" refs/heads/<base> M B0` runs against
the canonical repository with the same scrubbed environment as the other stages
(hooks disabled, no credential helper). Git's own reflog records the move.

## Durable intent and read-only reconciliation

Before the pack copy a prepared intent `{ref_name, expected_old: B0,
requested_commit: M}` is journalled on the ticket, exactly like `push`. On
resume with a prepared intent the stage only reads: it resolves
`refs/heads/<base>` and applies the shared `reconcile` rule — `M` means matched
(the receipt is emitted), `B0` means the effect never happened (the stage
refuses with `landing_effect_uncertain` and is not replayed automatically), any
other value is conflicting and refuses. A crashed copy can leave a temporary
`tmp_pam_*.pack` file under the pack directory; it is never referenced and Git's
garbage collection removes it.

## Receipt

```json
{"ref_name":"refs/heads/main","old":"<B0>","commit":"<M>","pack":"pack-<hash>",
 "bounds":{"objects":N,"deltas":D,"compressed_bytes":C,"decoded_bytes":X,"expanded_bytes":E},
 "confirmed_by":"exact_local_ref"}
```

## Refusal causes

`landing_sync_base_checked_out`, `landing_sync_remote_error`,
`landing_sync_response_invalid`, `landing_sync_pack_invalid`,
`landing_sync_pack_bounds`, `landing_sync_ancestry_unproven`,
`landing_sync_install_failed`, `landing_effect_uncertain`, plus the shared
landing causes (policy, budget, deadline, cancellation).

## Out of scope

Working-tree updates, branch deletion, tags, SHA-256 repositories, submodules,
shallow or partial clones, and any retry of a prepared intent.
