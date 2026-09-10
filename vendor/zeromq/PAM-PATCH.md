# PAM patch to zeromq 0.6.0

Origin: crates.io `zeromq` 0.6.0, upstream <https://github.com/zeromq/zmq.rs>.
Original crates.io archive SHA-256: `efb2c254fd8f366755335c9e43b865f8484fe3bd717d65ffe7c3f28852863030`.

The upstream Rust library source and MIT license (`LICENSE.md`) are retained.
`Cargo.toml.orig` preserves upstream's original manifest.

The upstream decoder reserves a peer-declared frame length before an application
can inspect it. PAM therefore pins this same-version local patch through the root
`[patch.crates-io]`; a check after `RouterSocket::recv` cannot fix that allocation.

Receive limits apply to **both daemon and client** codecs:

- At most 1 MiB per declared frame, including protocol command frames.
- At most four frames and 2 MiB cumulative data-frame wire bytes (headers included) per multipart message.
- Checked lengths and aggregate counters are validated before `reserve` or
  accumulation; counters reset on a completed message.

A routing identity and a 1 MiB application frame fit. Larger application responses
must use bounded results/evidence reads or explicit refusals; do not silently
truncate them.

Inbound IPC/TCP accepts share a process-wide 256-connection limit. A permit is
acquired before spawning the handshake callback and remains held by both socket
halves until disconnect/drop. Inbound handshakes time out after five seconds;
excess accepted sockets are closed immediately. This limits established peers
and unfinished handshakes together, including across multiple listeners.

ROUTER receive polls peer streams directly; stopping application reads provides
socket backpressure, without a background queue of complete messages. FairQueue
coalesces readiness per live peer generation, removes disconnected events, and
ignores stale wakes after identity replacement. ROUTER skips the unused
round-robin identity queue, preventing connection churn from accumulating IDs.
PAM must additionally bound its active request tasks and admission queue.

Resource regressions cover permit exhaustion and release across both IO halves,
a real refused socket and timed-out greeting, paused-receiver backpressure,
repeated/stale wakes, and ROUTER connection churn. Run with
`cargo test --manifest-path vendor/zeromq/Cargo.toml --lib --offline`.


Production dependencies and version are unchanged. The normalized vendored
manifest disables upstream example/integration/benchmark targets and removes their
unused development dependencies, including native `zmq2`; `hex` 0.4 is retained for
existing Rust codec fixtures. Upstream example/integration/benchmark sources are omitted because these targets
are not built in PAM; the crate archive checksum above identifies the original.
Two upstream six-frame codec fixtures now expect rejection under PAM's four-frame
policy. New regressions live in `src/codec/zmq_codec_limits_test.rs`.

To update: compare the new upstream decoder and manifest against this version,
retain or replace the pre-allocation, multipart, inbound lifetime, and readiness
checks, verify frame/count boundaries and counter reset, then run the pure-Rust codec library tests and PAM
transport tests. Do not remove the patch until a supported upstream configuration
provides equivalent checks before allocation.

The vendor package is excluded from PAM workspace membership so upstream tests
and lints do not enter unrelated workspace gates. Its separate test lock pins the
existing optional runtime metadata; the PAM root lock changes only zeromq from
registry to this path, with no production version changes.

Focused validation: `cargo test --manifest-path vendor/zeromq/Cargo.toml --lib codec --offline` from the PAM workspace.
