# Public transport without ZeroMQ — design and implementation plan

Status: approved for implementation 2026-10-02 (ptrack plan 49). Implements
the owner decision recorded on plan 49 (closes issue 39). Sequenced after plan
48, the design-review fix round. Implementation branch:
`feat/framed-public-transport`, stacked on the design-review fix branch
(`fix/design-review-2026-10`) until that lands, then rebased onto `main`.
Review record: [design review, 2026-10-02](../reviews/design-review-2026-10-02.md).

Line references are to `HEAD` (c8b939d, v0.4.3). `crates/pam_client`,
`crates/pam_gui`, `crates/pam_store`, `crates/pam/src/main.rs` and
`crates/pam_daemon/src/admin_flows.rs` are being edited by plan #48 while this
is written; re-anchor line numbers before implementing. Plan #48 task #200
(reply guard, restart handshake, cancel ownership) overlaps the "Daemon
structure" and "Identity and audit" sections here; whatever #200 lands is the
starting point and this document is the target. Part of that work has landed
(see [Already landed](#already-landed)); the four questions that were open when
this was drafted are decided (see [Decisions](#decisions)).

## Already landed

The design-review fix round implemented these items ahead of this plan, on the
fix branch. The plan starts from them and drops whatever its tasks already
cover (T1's `ingress.rs` and `image.rs`, and most of T2).

- **Image-based restart policy.** `image.rs` records the daemon's boot image
  (path, canonical path, length, modification time, device and inode on Unix;
  standard metadata only) and exposes an `ImageProbe` trait, injectable through
  `DaemonConfig::image_probe`. The re-check runs off the async threads, is cached
  for one second, single-flight, and latches once it has seen a replacement. A
  version mismatch with a replaced image answers `daemon_outdated` and moves the
  phase to `Restarting`; with an unchanged image it answers
  `client_version_mismatch`, naming the daemon's version and path, leaves the
  phase alone and writes no row. The same rule applies on the admin plane,
  `client_version` is bounded to 128 bytes at ingress, public requests get
  `daemon_outdated` while the phase is `Restarting`, and `respawn_daemon` uses
  `DaemonHandle::boot_image_path()`.
- **Handler deadline and reply guard.** `Pipeline::serve` runs admission, the
  gate, execution and the terminal write under one hard deadline; on expiry the
  caller gets `deadline_exceeded` at once, the slot is freed, and a detached task
  writes the terminal row through the retrying writer, releases attached waiters
  and publishes `refused`. A `ReplyGuard` owns the reply sender and the
  dispatcher permit, so every way a handler can end answers the caller and frees
  the slot; a handler parked on the completion router lets go when its caller
  goes away. The transport takes no permits any more: `dispatch_loop` owns the
  pools (128 work, 16 status, 16 query, 8 cancel, 32 admin-submitted).
- **Cancel actor by ingress.** `ingress.rs` defines `Origin { Public, Admin }` on
  `IncomingRequest` and `ExecContext`. A public `cancel` is `Actor::System`
  whatever `caller.agent` says and acts only on a ticket admitted under the
  caller's own canonical repository; `Origin::Admin` is `Actor::Human`.
- **Bounded completion router.** `completion_router.rs` keeps at most 256
  entries and 8 MiB for 60 seconds, evicts the oldest and prunes closed waiters;
  a late attacher whose answer is gone gets a ticket to read the durable result.
- **Admin cancel operation.** `admin.requests.cancel { ticket }`
  (`OP_REQUESTS_CANCEL`) submits a `cancel` of `Origin::Admin`, audited `human`;
  the GUI's cancel uses it, and the bridge's public `request_capability` command
  is gone.

One deviation from this document: control requests (`status`, `query`,
`cancel`) use the smaller of their deadline and 10 seconds, plus 2 seconds, as
the hard handler deadline, not the request deadline plus 30 seconds that
"Admission, permits and the handler deadline" below specifies. The grace for
other requests is `DaemonConfig::handler_grace`, 30 seconds. Keep the shorter
control bound or revert it deliberately when T2 lands.

Two limits of what landed matter to T2. `Origin` carries no peer fields yet, and
a leased execution is given `Origin::Public` because origin is not stored on the
request row until this plan's migration; only `cancel` reads it, and `cancel` is
never laned. The fix round's `transport.rs` changes are small: no semaphores,
`origin` on `IncomingRequest`, and the version length bound.

## Goal and non-goals

Goal: the public plane (agent CLI to daemon) speaks the same length-prefixed
JSON frame protocol the administration plane already speaks, on a plain unix
stream socket at the same path, `<base>/run/pam.sock`. Events stop being a
broadcast and become a per-connection stream for one ticket. The GUI gets the
all-events stream over the private admin socket. The daemon records the
kernel's view of who connected. ZeroMQ, its vendored patch and its gate step
are deleted.

Fixed inputs (owner decisions, not reopened here):

1. Same frame protocol as admin, unix stream socket, same path, no new crates,
   no `unsafe`, pure Rust.
2. Events are a per-connection server push for one followed ticket, ending
   with the durable result. No broadcast to public clients. `events.sock` is
   removed.
3. The GUI receives all events over the private admin socket, where richer
   content is acceptable.
4. Kernel peer uid/pid are captured per public connection and recorded.
   Self-reported labels stay attribution. A `pam-gui` label on the public
   socket never makes an audit actor `human`.
5. A small transport seam is kept so HTTP could be added later. HTTP is not
   designed or built.
6. `zeromq`, the `[patch.crates-io]` entry, `vendor/zeromq`, its step in
   `tools/check.sh` and any other reference are removed as the last step.
7. Existing limits keep their values and meaning.

Non-goals:

- No HTTP adapter, no TLS, no remote access. Everything stays same-host.
- No per-agent authentication. Repository and product scopes remain global
  permissions for public clients (docs/admin-boundary.md, "Global target
  authority"). Peer credentials are recorded, not used to authorize.
- No change to capabilities, policy, queueing, budgets or the store's
  terminal choke point, beyond what identity recording needs.
- No Windows session relay. `pam listen` stays unix-only.
- No new graceful stop mechanism for Windows. `pam daemon stop` stays
  unsupported there (crates/pam_client/src/client.rs:810).
- No request multiplexing on one connection (see "Wire protocol").

## Current state

### What the public transport does today

`crates/pam_daemon/src/transport.rs` owns two ZeroMQ sockets bound with
`ipc://` endpoints built in `runtime_dir.rs:129-137`:

- `pam.sock`, a `ROUTER`. `recv_loop` (207-236) reads `[identity, payload]`
  multipart messages. `handle_frames` (238-336) refuses anything that is not
  exactly one payload frame, a payload over 1 MiB (261), or an envelope whose
  id, capability, agent label, idempotency key (128 bytes each) or repository
  spelling (4,096 bytes) exceed their limits (272-292). It takes one of 128
  work or 16 control reply permits (213-214, 293-307; control is `status`,
  `query`, `cancel`), sends an `IncomingRequest { identity, envelope, reply }`
  to the daemon core over an `mpsc`, and spawns a forwarder that waits on the
  `oneshot` and pushes `(identity, Response)` onto a shared reply channel
  (318-326). `reply_loop` (360-389) serialises through `bounded_response`
  (420-451, an oversized reply becomes a small `response_budget_exhausted`
  refusal) and sends it to the routing identity. A reply for a peer that has
  gone is dropped.
- `events.sock`, a `PUB`. `EventPublisher::publish` (98-121) replaces every
  progress note with the constant `PUBLIC_PROGRESS_NOTE` (33), then
  `try_send`s `(request id, Event)` into a 256-slot channel, dropping when
  full. `publish_loop` (391-416) sends `[topic = request id, JSON event]`.
  Every subscriber can receive every ticket's events; topic filters are not
  access control (module docs 7-10).

Shutdown (`Transport::shutdown`, 181-187) flips a watch flag and joins the
three tasks. `reply_loop` leaves its `select!` on that flag without draining
the reply channel, so a reply queued at that instant is lost.

The daemon core (`crates/pam_daemon/src/daemon.rs`):

- `run_daemon_with` takes the instance lock (507) before `Transport::bind`
  (537), which is what makes removing stale socket files safe.
- `dispatch_loop` (759-813) applies the aggregate rate windows (256 work/s,
  64 control/s, 767-768) and a second pair of 128/16 semaphores (764-765),
  then spawns `Pipeline::handle` per request with the permit moved in. There
  is no deadline around the handler. On stop it waits five seconds and aborts
  what is left (807-812); an aborted handler drops its `oneshot`, and the
  client then waits out its own timeout.
- `Pipeline::handle` (899-1010) refuses `admin.*` on public ingress, refuses
  while not `Serving`, and runs the version handshake: any envelope whose
  `client_version` differs from `DAEMON_VERSION` is answered
  `daemon_outdated` and moves the phase to `Restarting` (915-935). The claim
  is not checked against anything.
- `CompletionRouter` (252-331) fans the terminal `Response` out to waiting
  pipeline tasks. Entries for waiters whose receiver was dropped stay in
  `waiting` until the request finishes, and `finished` keeps whole responses
  (up to 1 MiB each) for one minute, pruned only when another request
  finishes.
- `DaemonHandle::shutdown` (400-409) joins the lifecycle, dispatch and other
  tasks, then stops the admin transport, then the public transport.
- `crates/pam/src/main.rs` `serve` (799-835) observes `Restarting`, shuts the
  handle down and calls `respawn_daemon` (861-870), which spawns
  `std::env::current_exe()` with `daemon`.

Identity today: the envelope's `caller { agent, repo, pid }` is produced by
the client (`crates/pam_client/src/caller.rs`) and is the only identity the
public plane has. `executor.rs:402-406` picks `Actor::Human` for a `cancel`
whose `caller.agent` equals `pam-gui`. The only internal producer of that
label is `admin_flows.rs` (336-342, 405-409), which submits `flow.run` and
`flow.inspect` through the same `IncomingRequest` channel; any public client
can send the same label.

The client (`crates/pam_client/src/client.rs`):

- `send_envelope` (490-506) ensures a daemon, calls `exchange` (520-540),
  which opens a new `DEALER` per request, sends the envelope and waits
  `deadline_ms` plus five seconds. After a `daemon_outdated` refusal it
  retries once.
- `daemon_ready` (237-242) is the instance lock being held plus the socket
  file existing. The working tree replaces the file check with a real
  connect.
- `follow_ticket` (576-657) authorises with a `query` request, connects a
  `SUB` to `events.sock`, subscribes to the ticket topic, and because `PUB`
  has no replay and subscribing races publishing, re-runs `query` on a
  backing-off interval (`query_terminal`, 660-685). Terminal events on the
  stream are treated as hints that trigger another `query`.
- `stop_daemon` (771-787) reads the pid from `<base>/run/daemon.lock`, runs
  `kill -TERM <pid>` (789-807; unsupported off unix, 810) and waits for the
  lock to be released.

The relay (`crates/pam_client/src/relay.rs`) binds `pam.sock` and
`events.sock` in a session directory and copies bytes to the daemon's two
sockets (`pipe`, 159-163). It never looks at frames.

The GUI (`crates/pam_gui/src/events.rs`) connects one `SUB` to `events.sock`
with an empty prefix (108-113) and forwards `{ ticket, event }` to the
frontend. Its own `status` polls are public requests and come back as events.

Windows today: the `zeromq` feature `ipc-transport` pulls `win_uds` on
Windows (vendor/zeromq/Cargo.toml:48, 173-176;
vendor/zeromq/src/transport/ipc.rs:10-11), so `ipc://<base>\run\pam.sock` is
an `AF_UNIX` socket reached through that crate's FFI. `runtime_dir.rs` has no
Windows-specific endpoint code. Removing `zeromq` removes `win_uds`; std and
tokio have no unix sockets on Windows.

The admin plane (`admin_transport.rs`, `admin_transport_frame.rs`,
`admin_transport_unix.rs`, `admin_transport_windows.rs`) is one request and
one reply per connection: a 4-byte big-endian length and a JSON body, 1 MiB
requests, 16 MiB replies, a five-second header timeout, 32 connections, a
five-second drain. Unix admits by kernel peer uid and pid; Windows by a
server-first nonce proof over loopback TCP. Its accept loops end on the first
accept error (`admin_transport_unix.rs:186`, `admin_transport_windows.rs:214`)
and silently drop connections over the cap (unix 187). `frame::answer`
(admin_transport_frame.rs:40-50) has the same unchecked version restart.

### Consumer inventory

Every use of the ZeroMQ API or of the two endpoint accessors, at `HEAD`.

Manifests and gate:

| Location | What |
| --- | --- |
| Cargo.toml:2 | workspace `exclude` lists `vendor/zeromq` |
| Cargo.toml:46-48 | `zeromq` workspace dependency |
| Cargo.toml:102-104 | `[patch.crates-io] zeromq = { path = "vendor/zeromq" }` |
| Cargo.lock:6803 (`zeromq`), 6100 (`win_uds`), 338 (`asynchronous-codec`) | lock entries; the last two exist only through `zeromq` (verify with `cargo tree -i` at removal) |
| crates/pam_daemon/Cargo.toml:38 | `zeromq.workspace = true` |
| crates/pam_client/Cargo.toml:18 | same |
| crates/pam_gui/Cargo.toml:23 | same |
| crates/pam_testkit/Cargo.toml:3, 20 | description and dependency |
| tools/check.sh:33-38 | "bounded ZeroMQ codec regression tests" step |
| crates/pam_flow/flows/pam-pr-readiness.yaml:24 | the same `cargo test --manifest-path vendor/zeromq/Cargo.toml` as a flow step |
| .github/workflows/ci.yml:45 | runs `tools/check.sh`; no direct reference |
| vendor/zeromq/ | 51 tracked files, including PAM-PATCH.md |

Daemon:

| Location | What |
| --- | --- |
| crates/pam_daemon/src/transport.rs:22-25 | imports `PubSocket`, `RouterRecvHalf`, `RouterSendHalf`, `RouterSocket`, `Socket`, `SocketRecv`, `SocketSend`, `ZmqMessage` |
| transport.rs:54 | `TransportError::Bind { source: zeromq::ZmqError }` |
| transport.rs:139-149 | stale removal, `RouterSocket::new`, `PubSocket::new`, `bind` on both endpoints |
| transport.rs:155 | `router.split()` |
| transport.rs:207-236 | `recv_loop`, `router.recv()` |
| transport.rs:238-336 | `handle_frames`, `ZmqMessage::into_vec` |
| transport.rs:360-389 | `reply_loop`, `ZmqMessage::from(identity)`, `router.send` |
| transport.rs:391-416 | `publish_loop`, `pub_socket.send` |
| crates/pam_daemon/src/runtime_dir.rs:57-58, 79-80, 98-99, 117-137 | `router`/`events` paths, `router_socket()`, `events_socket()`, `router_endpoint()`, `events_endpoint()` |
| crates/pam_daemon/src/admin_flows.rs:336-342, 405-409 | `IncomingRequest { identity: Vec::new(), .. }` |
| crates/pam_daemon/src/daemon.rs:102, 536-537, 541, 587 | imports, `Transport::bind`, `event_publisher()` |
| crates/pam_daemon/src/executor.rs:40, 61 | `EventPublisher` in `ExecContext` |
| crates/pam_daemon/src/approval.rs:41, 103, 115, 156 | `EventPublisher` |
| crates/pam_daemon/src/flow_service.rs:1789 | `publish` (progress) |

Daemon tests:

| Location | What |
| --- | --- |
| crates/pam_daemon/src/transport_test.rs:100, 111-114 | `SubSocket` against a bound `Transport` |
| crates/pam_daemon/src/runtime_dir_test.rs:39-42, 215-216, 245-246 | endpoint and `events.sock` assertions |
| crates/pam_daemon/tests/transport.rs:10, 54-57, 72, 116, 160, 189-190 | `DealerSocket`, `SubSocket`, `ZmqMessage`; line 82 asserts `request.identity` |
| crates/pam_daemon/tests/daemon.rs:25, 96-99, 107-109, 154-157, 162, 169, 208 | own `DEALER`/`SUB` harness for 27 tests |
| crates/pam_daemon/tests/transport_stress.rs:18, 26, 255, 262, 280-282 | `DealerSocket`, held `SubSocket`s |
| crates/pam_daemon/tests/session_relay.rs:14, 27, 30, 48 | `DealerSocket` through the relay |
| eleven `*_test.rs` files under crates/pam_daemon/src | `EventPublisher::for_tests()` (API kept; no change needed) |

Client, relay, GUI, testkit, CLI tests:

| Location | What |
| --- | --- |
| crates/pam_client/src/client.rs:29 | imports `DealerSocket`, `Socket`, `SocketRecv`, `SocketSend`, `SubSocket`, `ZmqMessage` |
| client.rs:325, 339, 346 | `zeromq::ZmqError` as the source of `Connect`, `SessionUnreachable`, `Transport` |
| client.rs:237-242 | `daemon_ready` on `router_socket()` |
| client.rs:508-516 | `connect_error` |
| client.rs:520-540 | `exchange`: `DealerSocket::new`, `connect`, `send`, `recv` |
| client.rs:576-657 | `follow_ticket`: `SubSocket::new` (598), `connect` (599), `subscribe` (605), `recv` (631) |
| crates/pam_client/src/client_test.rs:29, 59, 231 | socket-file fixtures |
| client_test.rs:268-326 | fake daemon binding a `RouterSocket` |
| client_test.rs:507-513 | `events_socket()` assertions |
| crates/pam_client/src/relay.rs:92-96, 201-214, 230, 237-240 | two listeners, two forward loops, both endpoints printed |
| crates/pam_gui/src/events.rs:23, 108-117 | `SubSocket`, `connect`, `subscribe("")`, `recv` |
| crates/pam_gui/tests/bridge.rs:24, 168-180 | `SubSocket` against a real daemon |
| crates/pam_testkit/src/lib.rs:30, 340-341, 363-364, 504, 538, 565 | `TestClient` over one `DealerSocket`, `EventStream` over a `SubSocket`, `SUB_SETTLE` |
| crates/pam/tests/cli.rs:264, 320 | workarounds for "PUB has no replay" |
| crates/pam/tests/live_subscribe.rs | the cross-process subscribe race |
| crates/pam/tests/support/broker-macos.sb:12-13 | sandbox profile allows `pam.sock` and `events.sock` |

Documents naming the old transport: README.md:82, AGENTS.md, CLAUDE.md,
MEMENTO.md, docs/admin-boundary.md, docs/scoped-admission-and-budgets.md
(81-83, 99-103), docs/session-socket-relay.md, docs/macos-sandbox-acceptance.md,
docs/vision.md:144, 167, docs/enterprise-evidence-checkpoint.md:40,
docs/agent-companion-roadmap.md, docs/specs/2026-09-01-spine-design.md:58-59,
docs/specs/2026-09-09-local-model-triage.md, frontend/src/lib/ipc.ts
(comments near 1480).

## Wire protocol

### Connection model: one request per connection

A connection carries a hello, then exactly one request, then its answer, and
is closed by the daemon. The request is either a unary call (one reply) or a
follow (a stream that ends with one final frame). There are no request ids to
correlate on a connection and no second request.

Why this and not multiplexed ids:

- The CLI is one-shot. The existing client already opens a new `DEALER` per
  exchange (client.rs:520-523), and the admin plane is already one frame in,
  one frame out. Nothing shipped depends on reusing a connection.
- `wait` and `subscribe` need a stream for one ticket. One connection whose
  lifetime is that follow is the direct expression of it.
- The GUI bridge makes concurrent calls by making concurrent `send_request`
  calls. Each is a short unix-socket connection; the GUI's concurrency is a
  handful, far under the 256-connection cap.
- The testkit is the one consumer that sends several requests and reads
  replies in completion order on one socket. It keeps that API over a set of
  connections (a `JoinSet` of reply readers); see "Test strategy".
- Peer credentials belong to a connection. With one request per connection
  the recorded identity is unambiguous.
- Permits are RAII on the connection task. Disconnect detection, drain and
  backpressure are per request with no shared writer, no correlation table,
  no head-of-line rules and no partial-failure semantics to specify.

Multiplexing would buy fewer connects, which cost microseconds here, at the
price of all of the above.

### Frames

A frame is a 4-byte big-endian unsigned length `N` followed by `N` bytes of
UTF-8 JSON holding one object. `N` is at least 1 and at most the direction's
limit; the length is checked before any buffer is allocated. This is the
admin plane's codec (admin_transport_frame.rs:142-167) unchanged.

Every object has a `"t"` member naming the frame type. Unknown members are
ignored. A frame whose `"t"` the receiver does not know is a protocol error
on the daemon side and is skipped on the client side inside a follow stream.

Because the limit is 1 MiB (16 MiB for admin replies), the first byte of any
valid frame is `0x00`. That makes the first byte a discriminator:

- `0x00`: this protocol.
- `0xFF`: a ZMTP greeting (64 bytes beginning `FF 00 00 00 00 00 00 00 00
  7F`; both ZMTP peers send it before reading,
  vendor/zeromq/src/util.rs:136-146, codec/greeting.rs:42-54). See "Upgrade
  and restart handshake".
- An ASCII letter: reserved. An HTTP adapter on the same listener could be
  recognised this way later. Not built.

Client to daemon: `hello`, then one of `request`, `follow` (public) or
`request`, `events` (admin).

Daemon to client: `hello_ack`, then `reply`; or `following`, `event`*, `end`;
or `event`* (admin all-events); or `error` at any point, after which the
daemon closes.

A client may write `hello` and its request frame back to back without
waiting. The daemon always answers the hello first. If the hello is refused
the request frame is never read.

### Hello

```json
{"t":"hello","proto":2,"version":"0.5.0","via":"direct"}
```

- `proto`: wire protocol number. This protocol is 2 (the ZeroMQ envelope
  protocol was `PROTOCOL_VERSION = 1`, pam_proto/src/lib.rs:17).
- `version`: the client binary's `CARGO_PKG_VERSION`, at most 64 bytes. It is
  a hint. The daemon never restarts on it alone (see "Upgrade and restart
  handshake").
- `via`: `direct` or `relay`. Self-reported; the client sets `relay` when
  `PAM_SOCKET_DIR` is in effect. Attribution only.

The hello frame is limited to 4 KiB.

```json
{"t":"hello_ack","proto":2,"version":"0.5.0","epoch":"01JB2M5T8Q0V7K3W9X4Y6Z1ABC"}
```

- `version`: the daemon's version.
- `epoch`: a ULID minted at daemon boot. Followers use it to tell a resumed
  stream from a restarted daemon.

Hello failures are `error` frames (below): `protocol_mismatch`,
`client_version_mismatch`, `daemon_outdated`.

### Request and reply

```json
{"t":"request","envelope":{"v":2,"id":"req_01JB2M6A","capability":"echo",
 "client_version":"0.5.0","caller":{"agent":"claude","repo":"/work/app","pid":4242},
 "args":{"text":"hi"},"deadline_ms":60000,"wait":true}}
```

`envelope` is `pam_proto::Envelope` unchanged. `envelope.client_version` and
`envelope.v` stay on the type (stored rows, admin-submitted envelopes and
tests construct it) but no longer drive any decision; the hello does.

The daemon applies the existing checks before anything is retained: frame at
most 1 MiB; id non-empty and at most 128 bytes; capability, agent label and
idempotency key at most 128 bytes; repository spelling at most 4,096 bytes. A
body that is JSON but not a valid envelope gets a `bad_request` refusal
carrying the salvaged `id` when there is one, as today (transport.rs:328-334,
349-358).

```json
{"t":"reply","response":{"kind":"result","id":"req_01JB2M6A","outcome":"solved",
 "body":{"echo":{"text":"hi"}},"evidence":[]}}
```

`response` is `pam_proto::Response` unchanged: `result`, `refusal` or
`ticket`. A reply that would exceed 1 MiB becomes the existing
`response_budget_exhausted` refusal (`bounded_response`). After writing the
reply the daemon closes the connection.

On the wire the first example is `00 00 00 38` followed by the 56 bytes of
the hello JSON, then the next length and frame.

### Follow stream

```json
{"t":"follow","envelope":{"v":2,"id":"req_01JB2M7F","capability":"query",
 "client_version":"0.5.0","caller":{"agent":"claude","repo":"/work/app","pid":4242},
 "args":{"ticket":"req_01JB2M6A"},"deadline_ms":15000,"wait":true},
 "after_seq":0,"epoch":null}
```

The envelope must be a waiting `query` for one ticket. It is the
authorisation and is run through the normal pipeline exactly as a `query`
request is today: one request row, one terminal audit row, a control rate
token and a control slot for as long as the query takes. `after_seq` and
`epoch` are the resume position: the last sequence number this client saw and
the epoch it saw it under, or `0`/`null` for a fresh follow.

If the query is refused, or the ticket is already terminal, the daemon writes
`end` (below) and closes. Otherwise:

```json
{"t":"following","ticket":"req_01JB2M6A","epoch":"01JB2M5T8Q0V7K3W9X4Y6Z1ABC",
 "state":"running","seq":2}
```

`state` is the durable state at attach (`queued`, `running`,
`waiting_approval`) and `seq` the ticket's latest sequence number. Then events:

```json
{"t":"event","seq":3,"event":{"kind":"progress","pct":40,"note":"Task progress updated"}}
```

`seq` is per ticket, starts at 1, and increases by one per published event
within an epoch. A gap in `seq` means events were dropped for this follower
or fell out of the replay window; it needs no action because the stream never
carries state the store does not have. The stream ends with:

```json
{"t":"end","seq":5,"event":{"kind":"done"},
 "response":{"kind":"result","id":"req_01JB2M7F","outcome":"solved",
  "body":{"ticket":"req_01JB2M6A","state":"done","outcome":"solved","capability":"flow.run"},
  "evidence":[]}}
```

`response` is the scoped `query` answer read from the store at that moment
(`flow_result_service::scoped_query`'s body), authorised again at that
moment. `event` is `done` or `refused`, the terminal event a subscriber sees
today; it is absent when the follow itself was refused:

```json
{"t":"end","response":{"kind":"refusal","id":"req_01JB2M7F","cause":"request_unavailable",
 "detail":"…","recovery":"…"}}
```

After `follow` the client sends nothing. Any byte from the client is a
protocol error; end of file from the client ends the follow.

### Admin all-events request

Admin connections only (see "Events"):

```json
{"t":"events","include_probes":false}
```

answered by a stream of

```json
{"t":"event","n":1042,"ticket":"req_01JB2M6A","capability":"flow.run",
 "repo":"/work/app","agent":"claude","ingress":"public",
 "event":{"kind":"progress","pct":40,"note":"step build: cargo test"}}
```

### Errors

Transport-level failures that have no request to answer are `error` frames,
after which the daemon closes:

```json
{"t":"error","cause":"protocol_mismatch",
 "detail":"this daemon speaks pam wire protocol 2; the client sent 3",
 "recovery":"Use the pam binary that matches the running daemon (0.5.0)."}
```

| Cause | When |
| --- | --- |
| `protocol_mismatch` | `proto` is not one this daemon speaks |
| `client_version_mismatch` | hello version differs and the daemon's on-disk image is unchanged |
| `daemon_outdated` | hello version differs and the daemon's on-disk image was replaced; the daemon is restarting |
| `bad_frame` | not JSON, no `"t"`, unknown or out-of-order frame type, bytes after `follow` |
| `handshake_timeout` | hello plus request frame not delivered within five seconds (best effort) |
| `connection_capacity_exhausted` | the 256-connection cap is reached (best effort, one non-blocking write) |
| `daemon_shutting_down` | a follow stream is cut by the drain |
| `follow_expired` | a follow reached its maximum lifetime |
| `subscriber_lagged` | an admin all-events subscriber overflowed its queue |

Everything that concerns a parsed request keeps today's shape: a `reply` (or
`end`) carrying `Response::Refusal` with the existing causes (`bad_request`,
`request_capacity_exhausted`, `request_rate_exhausted`,
`daemon_shutting_down`, `daemon_outdated`, `deadline_exceeded`, and the
pipeline's own). The client's transient-cause list (client.rs working tree,
`TRANSIENT_CAUSES`) gains `follower_capacity_exhausted`.

### Limits

Unchanged in value and meaning:

| Resource | Ceiling |
| --- | --- |
| Public JSON request, reply or event frame | 1 MiB |
| Inbound public connections, including handshakes | 256 process-wide |
| Inbound handshake (hello and the request frame) | five seconds |
| Request id, capability, caller label, idempotency key | 128 bytes each |
| Caller repository spelling | 4,096 bytes |
| Public dispatcher/reply slots | 128 work; 16 reserved control |
| Aggregate admission rate | 256 work/second; 64 control/second |
| Admin frames, connections, header timeout, drain | 1 MiB / 16 MiB, 32, five seconds, five seconds |

The "ZMTP multipart message: four frames; 2 MiB" row disappears with
multipart. The two stacked 128/16 semaphore pairs (transport.rs:213-214 and
daemon.rs:764-765) become one pair; a pending reply and an active handler are
the same thing once each connection has one request, so the ceiling does not
move.

New, introduced by the follow stream:

| Resource | Ceiling | Why |
| --- | --- | --- |
| Hello frame | 4 KiB | nothing legitimate is larger |
| Public followers | 96 total; 16 per ticket | 144 reply slots plus 96 followers leaves 16 connections for handshakes; refusal `follower_capacity_exhausted` (transient) |
| Follower queue | 64 events | see backpressure |
| Replay ring per live ticket | 32 events | resume and late attach |
| Event hub entries | 512 tickets | bounded when a terminal publish never comes |
| Frame write | five seconds | a peer that does not read is disconnected |
| Follow lifetime | one hour | the request wall-time ceiling; the client reconnects if its own timeout is longer |
| Follow reconcile | every 15 seconds | server-side store re-check, see "Events" |
| Admin all-events subscribers | 4; queue 1,024 events | GUI windows |

## Unix adapter

- Path: `<base>/run/pam.sock`, a `SOCK_STREAM` unix socket. The run directory
  stays `0700` (`runtime_dir.rs:222-232`). The socket is set to `0600` after
  bind. The 104-byte path check stays.
- Bind order is unchanged: instance lock, then remove a stale `pam.sock`
  (`remove_stale`), then bind. For the same reason the daemon also removes a
  stale `events.sock` an older daemon left behind.
- tokio's `UnixListener` does not unlink on drop. The listener's shutdown
  removes the socket file while the instance lock is still held, as ZeroMQ's
  drop did.
- Peer identity: `UnixStream::peer_cred()` at accept gives uid, gid and pid
  from the kernel (the call the admin adapter already uses,
  admin_transport_unix.rs:71-79). The public policy records them and does not
  admit or refuse on them; who can connect is decided by the filesystem modes,
  as today. A uid different from the daemon's is recorded and logged at warn.
  A missing pid is recorded as null.
- Client side: `UnixStream::connect(path)`. The client never creates or
  chmods the run directory.
- `PAM_SOCKET_DIR` keeps meaning "dial `<dir>/pam.sock`" (`paths_at_dir`).

`RuntimeDir` loses `events`, `events_socket()`, `router_endpoint()` and
`events_endpoint()`. `router_socket()` is superseded by `public_socket()`
(see the implementation plan for the transitional value).

## Windows adapter

Std and tokio have no unix sockets on Windows, and `win_uds` leaves with
`zeromq`. The public adapter is the admin adapter's pattern with its own
control file, nonce and label, kept outside the private admin directory.

- The daemon binds `127.0.0.1:0` and writes `<base>\run\public.json`:

  ```json
  {"schema_version":1,"port":49731,"nonce":"<64 hex characters>"}
  ```

  written whole (temporary file, then rename) after the bind and removed at
  shutdown. The nonce is 32 fresh bytes from `getrandom` per daemon boot and
  is unrelated to the admin nonce.
- Handshake, before any frame: the daemon sends
  `sha256("pam-public-server" ‖ nonce)`; the client compares it in constant
  time and only then sends the raw nonce; the daemon compares that in
  constant time. A client therefore never hands the nonce to a process that
  took the port after a stale control file. Non-loopback peers are dropped.
  The nonce exchange runs under the five-second handshake timeout and at most
  32 connections may sit in it at once.
- What proves ownership: being able to read `<base>\run\public.json`, whose
  NTFS ACL is inherited from the profile directory (owner, SYSTEM,
  Administrators). That is the standing a unix peer has by being able to
  traverse the `0700` run directory.
- What a sandboxed Windows client needs: read access to `<base>\run`
  (`public.json` and, for the lock probe, `daemon.lock`) and an outbound TCP
  connection to `127.0.0.1` on the published port. It must not be given
  `<base>\admin`, the state database or write access to anything under the
  base. The port is ephemeral, so a policy that whitelists by port cannot
  name it in advance; a fixed or preferred port is not built now.
- The public nonce confers nothing on the admin plane. The admin listener is
  a different port with a different nonce in `<base>\admin\control.json`, and
  the public policy refuses `admin.*` regardless.
- Peer identity: safe Rust has no way to ask Windows which process owns the
  other end of a loopback connection. The recorded identity is "holder of the
  owner-readable public nonce"; uid and pid are null. This is a platform
  limitation of decision 4, not a fallback.
- Readiness for the client: instance lock held, control file present and the
  server proof verifies. A held lock with no control file is a daemon still
  booting, or a pre-migration daemon (see below).
- `pam listen` remains unsupported.

## Events

### One hub in the daemon

`EventPublisher::publish(request_id, event)` keeps its signature and its
"never blocks, never fails a request" contract; its twenty-odd call sites and
`EventPublisher::for_tests()` do not change. Behind it an in-memory event hub
replaces the `PUB` socket:

- Per live ticket: a sequence counter, a replay ring of the last 32 events,
  optional metadata (capability, repository, agent label, ingress) registered
  at admission, and the list of attached followers.
- Each follower has its own bounded queue (64) and a wake-up. `publish`
  takes a `std::sync::Mutex`, appends, and returns; the lock is never held
  across an await and nothing in `publish` waits on a peer.
- Public followers receive the sanitised event (the constant progress note),
  exactly what `PUB` carried. This document does not widen public event
  content.
- Admin subscribers receive the unsanitised event plus the metadata.
- An entry is created at first publish or first attach and removed when its
  terminal event has been published. The table is capped at 512; beyond that
  the oldest entry with no followers is dropped, which only loses replay.

### Public follow semantics

Attach. The handler (1) runs the authorising `query` through the pipeline;
(2) on a pending state takes a follower permit and attaches to the hub, which
registers the queue and returns the ring entries after `after_seq` in one
critical section; (3) writes `following` and the replayed events; (4) reads
the store again. The daemon publishes a terminal event only after the durable
terminal write (daemon.rs:1553-1566 and the other terminal paths), so after
step 2 either step 4 sees the terminal state or the terminal event arrives on
the queue. The subscribe-after-publish race is closed without client polling.

Attach after terminal. Step 1's answer is already terminal; the daemon writes
`end` and closes. Nothing waits.

Late attach. A follower that attaches after `queued` and `started` were
published receives them from the ring. Today they are unrecoverable.

Resume. The client remembers `epoch` and the highest `seq` it delivered. On
reconnect it sends both. Same epoch: the daemon replays ring entries above
`after_seq`. Different epoch (daemon restarted, counters reset): the client
resets to 0 and takes whatever the new daemon replays. Either way the durable
state in `following` and the eventual `end` come from the store.

Termination. On a terminal event, and every 15 seconds as a backstop, the
handler re-runs the scoped authorisation against the store
(`flow_result_service::authorized_metadata`) without creating a request row.
Terminal state gives `end` with the durable answer. Authorisation that no
longer holds (repository scope changed, grant revision moved) gives `end`
with `request_unavailable`. The backstop covers terminal transitions whose
event was never published, which is what the client's reconcile query covers
today.

Backpressure. A follower that reads slowly fills its 64-event queue. On
overflow the oldest queued `progress` event is dropped; lifecycle events are
at most a handful per ticket and are dropped only if nothing else can be.
The terminal condition is a flag, not a queue entry, so it cannot be dropped.
A frame write that does not complete in five seconds disconnects the
follower; it can reconnect and resume. No follower can slow `publish`, another
follower or a request.

Disconnect. A follower going away detaches its queue and releases its permit.
It never cancels work. The same holds for a unary caller: an observer timing
out or disconnecting never cancels the request, as today.

Many followers. Up to 16 per ticket and 96 in total, each independent.

Authorisation. The rules are the existing ticket rules, unchanged: the
caller's repository must be an approved root, equal to the ticket's stored
canonical repository, the stored path must still canonicalise to itself, and
the ticket's authorisation revision must equal the current grant-revocation
revision (flow_result_service.rs:179-212). A ticket that does not exist is
`request_unavailable`, indistinguishable from one the caller may not see.

Drain. When the daemon leaves `Serving`, followers get
`error daemon_shutting_down` and are closed. The client reconnects with
backoff and resumes against the next daemon.

### GUI all-events over the admin socket

The GUI opens one admin connection (owner uid and pid verified on unix, admin
nonce on Windows), sends `hello` and `events`, and receives every event with
its ticket, capability, repository, agent label and ingress, and the real
progress note. `n` is a daemon-wide counter; a gap tells the GUI it missed
events and should refresh its lists from `admin.activity.list`.

`status` and `query` traffic is left out unless `include_probes` is true.
That removes the loop in which the GUI's own status polls come back as
events, at the source rather than by filtering in the webview.

At most four subscribers. A subscriber whose 1,024-event queue overflows
loses the oldest progress events first and, if that is not enough, is closed
with `subscriber_lagged`; the GUI reconnects and refreshes. An event
subscriber occupies one of the 32 admin connections for its lifetime.

`crates/pam_gui/src/events.rs` keeps its shape (lazy singleton, reconnect
forever with backoff, `pam://event` channel). The payload stays
`{ ticket, event }` with the new members added, so existing frontend
listeners keep working.

## Identity and audit

Every `IncomingRequest` carries an origin instead of a routing identity:

- `Public { peer, relayed }`: arrived on the public listener. `peer` is the
  kernel's uid, gid and pid on unix or `OwnerNonce` on Windows. `relayed` is
  the hello's `via`.
- `Admin`: submitted by `AdminService` on behalf of a request that arrived on
  the private admin listener (`admin_flows.rs` `flows_run`, `flows_inspect`).

What is recorded: the `request` row gains `ingress` (`public` or `admin`),
`peer_uid`, `peer_pid` (both nullable) and `relayed`, through the next store
migration. Audit rows join to the request by id, so every audited decision
has the kernel's view of the connection that asked for it. Transport-level
refusals that create no row (hello errors, capacity, bad frames) log the peer
with the refusal. `admin.activity.list` and `admin.audit.request` can expose
the new columns; changing the GUI views is out of scope here.

What is not changed: `caller.agent`, `caller.repo` and `caller.pid` are still
self-reported, still stored, still attribution. The peer pid is attribution
too: it names the short-lived `pam` process, and pids are reused. Nothing is
authorised by either.

The audit actor is decided by origin, never by label. `executor.rs:402-406`
becomes: `Actor::Human` only for `Origin::Admin`; a public `cancel` is
`Actor::System` whatever its `caller.agent` says. `queue.rs`'s module docs
(31-32) are corrected to match. The GUI's cancel button used to go through the
public plane; it now uses the admin operation `admin.requests.cancel`, which
records `human` (see Decisions, 3, and Already landed).

The public policy refuses `admin.*` before any row is written. The existing
tripwire (`admin.rs:308`) remains for defence in depth.

## Upgrade and restart handshake

### Restart policy for a current daemon

The daemon restarts itself for one reason: the binary it was started from has
been replaced on disk. A client's claimed version is only the occasion to
look.

- At boot the daemon records its image: the path it was started as
  (`std::env::current_exe()`, and `argv[0]` when that is an absolute path),
  the canonical path each resolves to, and for the canonical file its length,
  modification time and, on unix, device and inode.
- When a hello on either plane carries a `version` different from the
  daemon's, the daemon re-reads those facts (off the async threads; the
  answer is cached for one second so a flood of mismatched hellos costs one
  check per second). The image counts as replaced when a regular file is
  present at a recorded path and its canonical path or any recorded attribute
  differs. A missing file is not a replacement.
- Replaced: the phase moves to `Restarting`; this connection gets `error
  daemon_outdated`. While the phase is `Restarting`, every public request is
  answered with a `daemon_outdated` refusal (today later arrivals get
  `daemon_shutting_down`), which the client already treats as "wait for the
  replacement, retry once".
- Not replaced: `error client_version_mismatch`, naming the daemon's version
  and executable path. The phase does not move. No request row is written.
- Equal versions: no check.

The check in `Pipeline::handle` (daemon.rs:915-935) and in
`admin_transport_frame::answer` (40-50) is deleted. A public client can no
longer cause a restart by what it says; a restart requires the on-disk file
to have changed, which the deployment assumption already places outside an
agent's reach (docs/admin-boundary.md, "Deployment assumption").

The respawn uses the path recorded at boot. Today `respawn_daemon` calls
`current_exe()` at respawn time (main.rs:861-862), which on Linux names a
deleted file after the usual rename-into-place install.

Client and daemon ship as one binary and the protocol types are free to
change between releases (pam_proto/src/lib.rs:3-6). The handshake therefore
stays strict: a client of a different version is never served. What changes
is that it is refused without the daemon restarting.

### Old daemon, new client

The old daemon speaks ZMTP on `pam.sock` and sends its greeting as soon as a
client connects.

1. The new client connects, writes its hello, and reads four bytes. A first
   byte of `0xFF` is a ZMTP greeting: the peer is a pre-migration daemon. No
   ZMTP is spoken back.
2. If `PAM_SOCKET_DIR` is set the client stops here with an error: the daemon
   behind the relay predates this protocol; run `pam daemon stop` outside the
   sandbox and try again.
3. Otherwise the client supersedes the daemon by the mechanism `pam daemon
   stop` uses (`stop_daemon`, client.rs:771-787): read the pid from
   `<base>/run/daemon.lock` while the lock is held, dial once more (if a
   hello now succeeds, another client already did this; skip to 5), run
   `kill -TERM <pid>`, and wait up to 20 seconds for the lock to be released.
   The old daemon drains for up to ten seconds, cancels what is left and
   exits 0.
4. If the signal cannot be sent (no pid, `kill` not permitted, as under the
   macOS broker profile, which denies signal operations) the client fails
   with: a pre-migration pam daemon (pid N) is running and this process may
   not stop it; run `pam daemon stop` outside the sandbox, then retry. If the
   daemon is still draining after the wait the client says so and exits; the
   error is transient.
5. The client lazy-starts its own binary (`ensure_daemon`) and retries the
   request once.

This is the only case in which a client stops a daemon on its own. The
authority used is the operating system's (a process allowed to signal the
daemon), not anything said on the wire.

Login-service-managed daemon. The units restart only on failure
(`KeepAlive { SuccessfulExit = false }`,
crates/pam_client/src/service.rs:286; `Restart=on-failure`, 318). A SIGTERM drain exits 0, so the manager leaves it
down, and step 5 starts a loose daemon, the same state `pam daemon stop`
followed by any pam command produces today. At next login the manager starts
the pinned executable. If the upgrade replaced that file in place, that is
the new daemon; `pam daemon` exits 0 on "already running", so a manager and a
loose daemon do not fight. If the unit pins a path that still holds the old
binary, the next login starts an old daemon and the next new client
supersedes it again; `pam service status` already reports the stale pin and
`pam service install` fixes it.

Windows. A pre-migration daemon listens on an `AF_UNIX` socket the new client
cannot open. The client sees the instance lock held, no
`<base>\run\public.json` after the boot wait, and a `pam.sock` file in the
run directory (a current daemon removes it at bind). It reports a
pre-migration daemon with its pid and the instruction to end that process,
then retry. There is no automatic stop: Windows has no SIGTERM and
`stop_daemon` is unsupported there today. A running executable cannot be
overwritten on Windows, so an installer has normally stopped the daemon
already.

The GUI. `pam gui` is unsandboxed. Its first public call (`daemon_status`)
goes through steps 1 to 5. `send_admin` ensures the daemon through the same
hello probe before dialling the admin socket, so a GUI never talks to an old
daemon's admin listener with new frames.

`pam listen`. The relay probes the daemon with a hello when it starts and
performs steps 3 to 5 if it meets a ZMTP greeting, since it runs outside the
sandbox and its clients cannot.

### New daemon, old client

- Public socket: the old client's `DEALER` sends its greeting on connect. The
  daemon reads four bytes, sees `0xFF`, closes, and logs one line (at most
  once a minute) with the peer's uid and pid so the stale binary can be
  found. The old client reports a connect failure and exits 1. It cannot stop
  or restart the daemon.
- `events.sock`: gone. An old GUI's subscriber retries with backoff forever
  and receives nothing.
- Admin socket: an old GUI process sends a bare envelope as its first frame.
  The admin policy recognises a first frame without `"t"` that parses as an
  `Envelope` and answers it in the old shape, a bare
  `Response::Refusal { cause: "client_outdated" }` telling the human to quit
  and reopen PAM, then closes. The old GUI displays it like any refusal.
- An old `pam listen` process keeps working for new clients: it is a byte
  pipe to `pam.sock`. Its `events.sock` listener is simply never dialled.

### Version skew after the migration

Both sides speak this protocol. A hello with a different version leads to
`daemon_outdated` (image replaced; wait and retry once) or
`client_version_mismatch` (image unchanged; the message names the running
daemon's version and path and says to run `pam daemon stop` outside the
sandbox, or to use the matching binary). The client does not stop the daemon
in this case; see Decisions, 1.

## Relay

`pam listen <dir>` binds one socket, `<dir>/pam.sock`, and copies bytes to
`<base>/run/pam.sock`. `events.sock` and its forward loop are removed. A
follow is just a long-lived connection through the same pipe. The relay stays
a byte pipe: it holds no credential, parses no frame and makes no decision.
Its accept backoff and 64-connection cap (working tree) stay.

Identity through the relay. The daemon's kernel peer for a relayed connection
is the relay process, not the sandboxed client. What is recorded: `peer_uid`
and `peer_pid` of the relay, `relayed = true` from the client's hello, and
the envelope's self-reported `caller` as always. This is acceptable because:

- nothing is authorised by pid on either path;
- the uid is the same owner on both paths (the relay directory is `0700`, its
  socket `0600`);
- the relay is started by the human, outside the sandbox, as a deliberate
  grant of reach; its pid identifies that grant;
- the alternative, having the relay vouch for its client's pid, would make
  the relay parse or wrap the stream and would still be only as trustworthy
  as a same-user process's word.

`relayed` is self-reported by the client. A relayed client that omits it is
recorded with the relay's pid and `relayed = false`; the pid still resolves
to a `pam listen` process for anyone investigating. A direct client that
claims it gains nothing.

At start the relay probes the daemon (see "Old daemon, new client") and
prints one forwarding line instead of two.

docs/session-socket-relay.md is updated: one socket; sandbox policies need
only `<dir>/pam.sock`.

## Daemon structure

### Modules

- `framed.rs`: the frame codec, the limits, the first-byte sniff, the generic
  accept loop, and the client-side dial primitives (connect, hello, one call,
  one follow), generic over `AsyncRead + AsyncWrite`.
- `framed_unix.rs`, `framed_windows.rs`: endpoints. Unix: bind with mode and
  stale handling, accept with peer credentials, connect. Windows: loopback
  bind, control file, server-first nonce proof, connect.
- `ingress.rs`: `Origin`, `PeerIdentity`, and the seam. The public adapter
  calls two things and nothing else in the daemon: `call(origin, envelope) ->
  Response` (an `IncomingRequest` on the existing `mpsc` and a wait on its
  `oneshot`) and `follow(origin, envelope, resume)` (the follow handler
  above). An HTTP adapter added later would call the same two entry points.
- `event_hub.rs`: the hub and `EventPublisher`.
- `image.rs`: the boot image record and the replaced check.
- `public_transport.rs`: the public policy and per-connection handler.
- `admin_transport*.rs`: the admin policy on the same listener code.

One framed module, two policies:

| | Public | Admin |
| --- | --- | --- |
| Endpoint (unix) | `<base>/run/pam.sock`, 0600 in 0700 | `<base>/admin/control.sock`, 0600 in 0700, base and ancestors validated |
| Endpoint (Windows) | `<base>\run\public.json`, label `pam-public-server` | `<base>\admin\control.json`, label `pam-admin-server` |
| Peer | recorded | must be the daemon's uid with a pid, else refused and logged |
| Frames in / out | 1 MiB / 1 MiB | 1 MiB / 16 MiB |
| Connections | 256 | 32 |
| Requests | any non-`admin.*` envelope; `follow` | waiting `admin.*` envelope with deadline 1..=300000 ms; `events` |
| Retry | client may retry transient refusals | never replayed |

Base validation, the admin directory checks and `prepare_base` stay in the
admin files. Everything else that the two adapters do today in duplicate
(framing, caps, timeouts, accept loop, drain, nonce handshake) exists once.

### Listener and accept loop

One accept loop per listener:

- A semaphore of the connection cap. A connection over the cap gets one
  non-blocking write of `error connection_capacity_exhausted` and is closed.
  It is never left without an answer, so a client can tell a full daemon from
  a legacy one.
- Accept errors never end the loop. `EMFILE`, `ENFILE`, `ENOBUFS` and
  `ENOMEM` back off (10 ms doubling to one second) and retry;
  `ECONNABORTED` and `EINTR` retry at once; anything else is logged and
  retried with the same backoff. The acceptor is behind a small trait (the
  pattern in relay.rs working tree, `Accept`) so tests can script errors.
  This also fixes the admin loops.
- Each accepted connection is a task in a `JoinSet`, holding its connection
  permit for its whole life.
- Stop: the loop stops accepting and unlinks the socket file (or removes the
  control file), signals followers, waits up to five seconds for connection
  tasks, then aborts the rest.

### Per-connection task (public)

1. Under the five-second handshake timeout: read four bytes. `0xFF`: log and
   close. Otherwise read the hello (4 KiB), check `proto`, apply the version
   rule, write `hello_ack` or `error`. Read the request frame (1 MiB).
2. `request`: validate the envelope's limits; refuse `admin.*`; if the phase
   is `Restarting` answer `daemon_outdated`, if `Draining` answer
   `daemon_shutting_down`; otherwise send `IncomingRequest { origin,
   envelope, reply }` and wait on three things at once: the `oneshot`, end of
   file from the peer, and the listener's stop.
   - Reply: write it under the write timeout, close.
   - Peer gone: close. The connection permit is released; the request is not
     cancelled and its result stays in the store.
   - Sender dropped without a reply (handler aborted or overdue): write
     `deadline_exceeded` if the request's deadline has passed,
     `daemon_shutting_down` if draining, else `internal_error`. A client
     never sees a bare end of file for a request the daemon accepted.
3. `follow`: the follow handler in "Events".

### Admission, permits and the handler deadline

`dispatch_loop` stays the single admission point and keeps the
`IncomingRequest` channel, which `AdminService` also submits to. Changes:

- One pair of 128/16 semaphores, here. The transport takes none.
- The permit is moved into the handler task and dropped when it ends, as
  today, and the handler now runs under a hard deadline: the envelope's
  `deadline_ms` clamped to the lease ceiling, plus 30 seconds. If it elapses
  the handler future is dropped and the task writes the request's terminal
  row through the store's choke point (first-wins, so a row that is already
  terminal is untouched), releases router waiters and publishes `refused`. A
  handler that hangs can therefore hold a slot for at most its own deadline
  plus the grace. This is the class of failure in issue #35.
- A handler that is only parked (waiting on the completion router for a laned
  or attached request, daemon.rs:978-981 and `place_and_wait`) also watches
  its reply channel. When the connection task has gone it stops waiting and
  frees its slot; the laned work continues under its lease. Bypass execution
  and all bookkeeping are never interrupted by a disconnect.
- The origin travels into `ExecContext` and into admission, where the peer is
  written to the request row.

### Reply routing and the completion router

Replies are no longer routed by the transport: each connection task owns the
`oneshot` for its one request and writes the reply itself. The reply channel,
the routing identity and the forwarder tasks go away.

`CompletionRouter` remains as the in-daemon fan-out of a terminal `Response`
to the pipeline tasks waiting for it (the requester and attached duplicates);
the response body is not durable for every capability, so it cannot be
replaced by a store read. Its retention is bounded:

- `waiting`: senders whose receiver is closed are pruned on every `register`
  and `finish`, and empty entries are removed.
- `finished`: at most 256 entries and 8 MiB in total, with the existing
  one-minute lifetime, pruned on insert and on the reaper's tick rather than
  only when another request finishes.

### Drain

The order in `DaemonHandle::shutdown` is unchanged. While draining, the
public listener keeps accepting so that newcomers get a refusal frame rather
than a refused connect. Followers are closed with `daemon_shutting_down` as
soon as the phase leaves `Serving`. By the time the transport is stopped the
dispatcher has finished or aborted every handler, so every connection task's
`oneshot` has resolved or been dropped and each writes its final frame and
exits; the five-second wait only covers peers that are not reading. The
socket file is unlinked before the instance lock is released.

## Client structure

- `crates/pam_client/src/transport.rs` (new) is the client's side of the
  seam and the only client file that knows about frames: `call(dirs,
  envelope)` and `follow(dirs, envelope, resume, on_frame)`, built on the
  dial primitives in `pam_daemon::framed` (the client already links
  `pam_daemon` for `admin_transport::exchange`). It maps a ZMTP first byte to
  a legacy-daemon error and `error` frames to typed errors. An `error
  daemon_outdated` at hello is surfaced exactly like a `daemon_outdated`
  refusal, so the existing wait-for-replacement and single retry apply.
- `client.rs`:
  - `exchange` becomes `transport::call`. `send_envelope` keeps its loop
    (ensure, exchange, one retry after `daemon_outdated`) and gains the
    supersede step for a legacy daemon, at most once per call.
  - The connect retry pauses and `connect_error` stay. The `zeromq::ZmqError`
    sources in `RequestError` become `io::Error`. New variants: a legacy
    daemon that could not be stopped (with the pid and the instruction), and
    a version or protocol mismatch (with the daemon's version and path).
    Neither is transient.
  - `follow_ticket` keeps its signature. Inside it is one loop: dial, hello,
    `follow` with the resume position, deliver each `event` whose `seq` is
    above the last delivered, return on `end`. `end` with a transient refusal
    or an `error` with a transient cause, end of file and connect failures
    back off (the existing 0.5 s to 8 s schedule) and reconnect until the
    caller's timeout. The reconcile timers, `query_terminal` polling and the
    `SUB` socket are deleted.
  - `socket_accepts` on Windows reads the control file and connects.
  - `send_admin` ensures the daemon with a hello probe (so a legacy daemon is
    superseded first) and then calls the admin exchange.
- `relay.rs`: one listener, one forward loop, the startup probe.
- `crates/pam_gui/src/events.rs`: the pump calls the admin all-events stream
  (`pam_daemon::admin_transport`, client side) instead of a `SUB` socket. The
  idle lock probe is unnecessary on a stream socket (end of file is
  reported) and is removed. `bridge.rs` is unchanged.
- `crates/pam/src/main.rs`: `follow` and `terminal_result` keep working
  unchanged. `terminal_result`'s extra `query` may later be replaced by the
  `end` frame's response; not required.

Lazy start, the lock probe, the spawn isolation, `PAM_SOCKET_DIR` handling
and exit codes do not change.

## Test strategy

Standing rules from the repository apply: harness daemons seed the relaxed
profile explicitly; shared tests do not assert unix-only lock or signal
details (those tests are `cfg(unix)`); unit tests live in sibling `_test.rs`
files; every await in a test is bounded.

### What replaces each existing socket test

| Existing | Replacement |
| --- | --- |
| vendor/zeromq codec and resource tests (check.sh:38) | `framed_test.rs`: zero and over-limit lengths refused before the body is read or allocated (a reader that would block on the body proves no read happened); connection cap with the capacity frame; handshake timeout; permit release on every exit path |
| transport_test.rs: saturated event queue drops without blocking | `event_hub_test.rs`: publish returns immediately with a full follower queue; oldest progress dropped; terminal still observed |
| transport_test.rs: oversized response gets a small refusal | same assertion against `bounded_response` in its new home |
| transport_test.rs: publisher strips prose | hub: follower view is the constant note, admin view is the real note |
| transport_test.rs: wildcard subscriber sees only generic progress | public socket: `events` is `bad_frame`; a follower of ticket A never receives B's events |
| tests/transport.rs: round trip to core and back | `tests/public_transport.rs`: hello, request, reply; the `IncomingRequest` origin carries this process's uid and pid |
| tests/transport.rs: malformed payload; salvaged id | same over frames: not JSON gives `bad_frame`; bad envelope gives `bad_request` with the salvaged id |
| tests/transport.rs: subscriber receives only its topic | `tests/public_follow.rs` |
| tests/transport.rs: shutdown stops tasks, publisher errors after | socket file gone, connect refused, `publish` errors, an in-flight reply was written first |
| tests/daemon.rs (27 tests on a private DEALER/SUB harness) | the same tests on the testkit client; `version_mismatch_refuses_outdated_and_the_daemon_restarts_itself` is rewritten around an injected image probe (two cases: replaced, unchanged) |
| tests/transport_stress.rs: GUI polling and abandoned subscribers | same scenario with abandoned followers (connected, never reading) and status polling; control requests keep being answered; follower count and file descriptors stay bounded |
| tests/session_relay.rs | request and follow through the relay; the session directory holds only `pam.sock` |
| pam_testkit `TestClient` (one DEALER, pipelined) | per-request connections; `send` starts a reader task, `recv` returns the next completed reply; API unchanged, so spine, admin, flows and the other suites do not change |
| pam_testkit `EventStream` (SUB, `SUB_SETTLE` sleep) | the admin all-events stream (`include_probes: true`) filtered to the requested ids, in the hub's publish order; subscribing before the ids exist keeps working; no settle sleep. Where no admin adapter exists the harness reads the hub in process |
| client_test.rs fake ROUTER daemon (268-326) | a fake framed daemon (unix listener, lock, scripted frames) and a fake ZMTP daemon (writes the 64-byte greeting) |
| client_test.rs: refused follow queries once, never subscribes | one connection, one `end` refusal, no retry |
| client_test.rs: no reply within deadline plus margin; two outdated refusals stop after one retry | same over frames |
| pam_gui/tests/bridge.rs: event frames decode like the subscriber | admin all-events from a real daemon decode to the payload; status polls are absent by default |
| pam_gui/tests/bridge.rs: idle probe sees the daemon come and go | end of file on daemon stop, reconnect on start |
| pam/tests/cli.rs:264, 320 | the workarounds go: a follow after terminal returns at once; `subscribe` prints the replayed `queued` and `started` |
| pam/tests/live_subscribe.rs | kept; additionally asserts one `query` row for the whole follow |
| pam/tests/sandbox_macos.rs and broker-macos.sb | profile allows only `pam.sock`; adds: a sandboxed client facing a fake ZMTP daemon fails with the instruction and the fake daemon's pid is still alive |
| runtime_dir_test.rs endpoint assertions | removed with the accessors |

### Injection tests

- Slow follower: a follower that never reads while thousands of progress
  events are published. `publish` calls return without waiting, the queue
  never exceeds 64, a second follower of the same ticket receives `end`, the
  slow one is disconnected at the write timeout (paused clock), and a
  reconnect with its `after_seq` gets `following` and `end`.
- Disconnect mid-request: a waiting `echo` with a delay; the client closes.
  The connection permit returns, the slot returns once the parked handler
  notices, the request finishes `done` with its audit row, and no cancel
  audit row exists.
- Legacy ZMTP greeting to the daemon: write the 64 greeting bytes to
  `pam.sock`. The connection is closed, one warning is logged, and the next
  framed client is served.
- Old-daemon takeover (`cfg(unix)`): a fake pre-migration daemon holds the
  instance lock, writes the pid of a child it owns into it, binds `pam.sock`
  and greets in ZMTP; when the child dies it releases the lock. The client
  detects, signals, waits, calls an injected spawner that starts a framed
  fake, and the retried request succeeds. Variants: signalling refused gives
  the instruction error and no spawn; `PAM_SOCKET_DIR` set gives the relay
  wording and no signal; a second client racing the first does not signal a
  daemon that already answers hello.
- `EMFILE`: a scripted acceptor returns `EMFILE` several times, then a
  connection. The loop is still running, the backoff was observed, the
  connection is served. Run against both policies.
- Version claim: hello with version `9.9.9` and an unchanged image gives
  `client_version_mismatch`, the phase stays `Serving`, a normal client is
  then served. With the probe reporting a replaced image the phase is
  `Restarting` and requests get `daemon_outdated`.
- Label: a public `cancel` with `caller.agent = "pam-gui"` is audited as
  `system`; the request row has `ingress = public` and this process's pid.
- Drain flush: a waiting request is in flight when shutdown starts; the
  client reads a reply frame (result or refusal), never a bare end of file.
- Overdue handler: an injected handler that never returns frees its slot at
  deadline plus grace, the row is terminal with one audit row, and the client
  gets `deadline_exceeded`.
- Attach race: a hook publishes the terminal event between authorisation and
  attach; `end` is still delivered.
- Resume: disconnect after `seq` 3, reconnect with `after_seq` 3, receive 4
  onward only. A different epoch replays from the start.
- Follower caps: the seventeenth follower of one ticket and the ninety-seventh
  overall get `follower_capacity_exhausted`; a slot freed by a disconnect is
  reusable.
- Windows (CI Windows job and the Parallels VM): public nonce handshake
  succeeds; a wrong nonce is refused before any frame; a listener that does
  not know the nonce fails the server proof and never receives it; the
  control file is removed at shutdown; the public nonce is refused by the
  admin listener.

## Removal of ZeroMQ

Done last, when nothing in the workspace imports the crate:

1. Delete the legacy `ROUTER`/`PUB` code and `TransportError::Bind`'s ZeroMQ
   source from `transport.rs`; delete `tests/transport.rs` and
   `transport_test.rs` cases that exist only for it.
2. `RuntimeDir`: `public_socket()` returns `<run>/pam.sock`; remove
   `router_socket()`, `events_socket()`, `router_endpoint()`,
   `events_endpoint()` and the `events` field.
3. Cargo.toml: remove the `zeromq` workspace dependency (46-48), the
   `[patch.crates-io]` line (104) and its comment (102), and `vendor/zeromq`
   from `exclude` (2). Remove `zeromq.workspace = true` from
   `crates/pam_daemon`, `pam_client`, `pam_gui` and `pam_testkit`; fix the
   testkit description.
4. Delete `vendor/zeromq`.
5. Regenerate `Cargo.lock` with the pinned toolchain and confirm `zeromq`,
   `win_uds` and any crate that was only its dependency are gone
   (`cargo tree -i zeromq` and `-i win_uds` find nothing).
6. tools/check.sh: delete lines 33-38.
   crates/pam_flow/flows/pam-pr-readiness.yaml: delete the step at line 24.
   `.github/workflows/ci.yml` needs no edit.
7. broker-macos.sb: delete line 13 (`events.sock`).
8. `PROTOCOL_VERSION = 2`; module docs in `pam_proto` stop mentioning
   `ROUTER`/`PUB`.
9. Documents: docs/admin-boundary.md (public endpoint wording, the "Public
   events" paragraph, Windows public adapter), docs/scoped-admission-and-budgets.md
   (limits table, the paragraph and link at 99-103),
   docs/session-socket-relay.md, docs/macos-sandbox-acceptance.md (last
   paragraph), README.md:82, docs/vision.md, docs/enterprise-evidence-checkpoint.md:40,
   AGENTS.md/CLAUDE.md/MEMENTO.md mentions, CHANGELOG.md, and a one-line
   pointer from docs/specs/2026-09-01-spine-design.md to this document. The
   ptrack goal text still says "zmq-over-unix-socket transport".

Acceptance for the removal: `grep -ri "zeromq\|zmq\|zmtp"` over the tree
finds only CHANGELOG history, this specification, the legacy-greeting
detection (constants and tests) and the upgrade notes.

## Implementation plan

Branch `feat/framed-public-transport`, stacked on the design-review fix branch
`fix/design-review-2026-10` until that lands and then rebased onto `main`; one
PR, squash-merged, CI green first; commits name their ptrack task (`#<id>`). No
release is cut from an intermediate state.

To let tasks land independently and keep every commit green, the new public
listener is introduced next to the ZeroMQ one and the path is swapped at the
end:

- During the work, `RuntimeDir::public_socket()` returns
  `<run>/pam.next.sock` and the daemon serves both transports into the same
  `IncomingRequest` channel and the same hub (the hub feeds the legacy `PUB`
  loop as one more sink). Windows uses `public.json` from the start; there is
  no path conflict there.
- The last task makes `public_socket()` return `<run>/pam.sock` and deletes
  the old transport. In-band legacy detection goes live against real old
  daemons at that moment.

Tasks within a phase own disjoint files and can run in parallel. A file not
listed for a task is not touched by it. For each task: `cargo clippy -p
<crate> --all-targets -- -D warnings` on every touched crate before the full
gate.

### Phase A (one agent)

T1. Foundation: wire types, framed module, hub, image record, wiring.

- New: `crates/pam_proto/src/wire.rs`, `wire_test.rs`;
  `crates/pam_daemon/src/framed.rs`, `framed_test.rs`, `framed_unix.rs`,
  `framed_unix_test.rs`, `framed_windows.rs`, `framed_windows_test.rs`,
  `ingress.rs`, `ingress_test.rs`, `event_hub.rs`, `event_hub_test.rs`,
  `image.rs`, `image_test.rs`, and an empty `public_transport.rs` with
  `public_transport_test.rs` (module docs only, so `lib.rs` has one owner).
- Edited: `crates/pam_proto/src/lib.rs`; `crates/pam_daemon/src/lib.rs`
  (module lines); `runtime_dir.rs`, `runtime_dir_test.rs` (`public_socket()`,
  `public_control()`); `transport.rs` (`EventPublisher` moves to the hub and
  is re-exported; the hub feeds `publish_loop`; `IncomingRequest` gains
  `origin` and keeps `identity` until T8; `Transport::bind` stays for tests
  and a `bind_with` taking store, phase, hub and image is added);
  `admin_flows.rs` (two construction sites set `Origin::Admin`);
  `admin_transport.rs` (`bind` accepts the hub, unused for now); `daemon.rs`
  (wiring only: build the hub, image record and phase before the transports
  and pass them).
- The framed endpoints are written fresh from the admin adapters' code; the
  admin files are not touched here.
- Acceptance: unit tests for frame limits before allocation, the first-byte
  sniff, the scripted-acceptor `EMFILE` loop, connection cap and handshake
  timeout, unix peer credentials equal to the test process, Windows proof and
  nonce (on Windows), hub sequence/ring/drop policy/caps, image replaced
  versus unchanged versus missing. No behaviour change: `bash tools/check.sh`
  passes with every existing test untouched.

### Phase B (three agents in parallel)

T2. Daemon core: origin, identity, restart policy, handler guard.

- Files: `crates/pam_daemon/src/daemon.rs`, `daemon_test.rs`, `executor.rs`,
  `executor_test.rs`, `queue.rs`, `queue_test.rs`;
  `crates/pam_store/src/migrations.rs`, `migrations_test.rs`, `store.rs`,
  `store_test.rs`; `crates/pam/src/main.rs`; `crates/pam_daemon/tests/daemon.rs`.
- Work: origin into `ExecContext` and admission; request row columns and
  migration; `cancel` actor by origin; hub metadata registered at admission;
  version check replaced by the image check (both outcomes) with an image
  probe injectable through `DaemonConfig`; one semaphore pair; hard handler
  deadline with the terminal write; parked handlers release on a closed reply
  channel; `CompletionRouter` bounds; respawn from the recorded path.
- Acceptance: new unit tests for each item above (label test, overdue
  handler, router bounds, migration up from the previous version);
  `tests/daemon.rs` version test rewritten and green over the still-present
  ZeroMQ harness; `bash tools/check.sh`.

T3. Public listener and follow.

- Files: `crates/pam_daemon/src/public_transport.rs`,
  `public_transport_test.rs`, `transport.rs` (`bind_with` starts and
  `shutdown` stops the public listener; nothing else),
  `crates/pam_daemon/tests/public_transport.rs` (new),
  `crates/pam_daemon/tests/public_follow.rs` (new).
- Work: the public policy and per-connection task; hello and version rule
  using `image.rs`; request path with the three-way wait; follow handler;
  drain behaviour; unlink at shutdown. Tests use the dial primitives from
  `framed.rs` against a real daemon on `public_socket()`.
- Acceptance: the public rows of the replacement table and the injection
  tests for slow follower, disconnect mid-request, legacy greeting to the
  daemon, drain flush, attach race, resume and follower caps;
  `bash tools/check.sh`.

T4. Admin plane on the framed module, and the all-events stream.

- Files: `crates/pam_daemon/src/admin_transport.rs`,
  `admin_transport_frame.rs`, `admin_transport_frame_test.rs`,
  `admin_transport_unix.rs`, `admin_transport_windows.rs`,
  `admin_transport_windows_test.rs`, new `admin_transport_events.rs` and
  `admin_transport_events_test.rs` (declared from `admin_transport.rs` like
  the existing `#[path]` modules), `crates/pam_daemon/tests/admin_events.rs`
  (new).
- Work: admin listener and `exchange` on `framed`/`framed_unix`/
  `framed_windows` with the admin policy; hello on the admin plane; the
  `client_outdated` answer to a bare first-frame envelope; `events` stream
  server side and a client-side `events(base)` stream; delete the duplicated
  codec and accept loops; base and directory validation stay.
- Acceptance: existing admin tests green (`crates/pam_testkit/tests/admin.rs`,
  `admin_test.rs`, frame and Windows tests); `EMFILE` no longer ends the
  admin listener; all-events stream delivers rich events in publish order,
  omits probes by default, enforces the subscriber cap and lag rule; a bare
  envelope gets `client_outdated`; `bash tools/check.sh`.

### Phase C (three agents in parallel)

T5. Client.

- Files: `crates/pam_client/src/transport.rs`, `transport_test.rs` (new),
  `client.rs`, `client_test.rs`, `lib.rs`, `Cargo.toml`;
  `crates/pam/tests/cli.rs`, `live_subscribe.rs`, `sandbox_macos.rs`,
  `crates/pam/tests/support/broker-macos.sb` (adds the transitional path).
- Work: everything in "Client structure" except the relay and the GUI;
  legacy detection and supersede; Windows dial.
- Acceptance: client rows of the replacement table; the old-daemon takeover
  injection test and its three variants against fakes; `pam wait` and
  `pam subscribe` against a real daemon create one `query` row; the crate no
  longer depends on `zeromq`; macOS sandbox test green; `bash tools/check.sh`.

T6. Testkit and the daemon's integration suites.

- Files: `crates/pam_testkit/src/lib.rs`, `Cargo.toml`,
  `crates/pam_testkit/tests/spine.rs`, `admin.rs` (only if a helper's
  behaviour forces it), `crates/pam_daemon/tests/daemon.rs`,
  `transport_stress.rs`.
- Work: `TestClient` and `EventStream` on the new transport with the same
  API; `tests/daemon.rs` moved onto the testkit client and its private
  harness deleted; the stress scenario with abandoned followers; the
  end-to-end assertion that request rows carry `ingress` and the peer pid.
- Acceptance: every suite that uses the testkit passes unmodified apart from
  the listed files; `SUB_SETTLE` is gone; the testkit no longer depends on
  `zeromq`; `bash tools/check.sh`.

T7. GUI events and the relay.

- Files: `crates/pam_gui/src/events.rs`, `events_test.rs`, `Cargo.toml`,
  `crates/pam_gui/tests/bridge.rs`, `frontend/src/lib/ipc.ts` (payload type
  and comments) and its test if one covers the payload;
  `crates/pam_client/src/relay.rs`, `relay_test.rs`;
  `crates/pam_daemon/tests/session_relay.rs`.
- Work: the GUI pump on the admin all-events stream; the single-socket relay
  with the startup probe (using `stop_daemon` and `ensure_daemon`, which
  exist today, and the `framed` dial primitives, so there is no dependency on
  T5).
- Acceptance: GUI rows of the replacement table; a status poll does not come
  back as an event; relay test carries a request and a follow and the session
  directory holds one socket; `pam_gui` no longer depends on `zeromq`;
  frontend lint, build and tests; `bash tools/check.sh`.

### Phase D (one agent)

T8. Cut-over, removal, documents.

- Files: everything in "Removal of ZeroMQ" (root `Cargo.toml`, `Cargo.lock`,
  `crates/pam_daemon/Cargo.toml`, `vendor/zeromq`, `tools/check.sh`,
  `crates/pam_flow/flows/pam-pr-readiness.yaml`, `runtime_dir.rs` and its
  test, `transport.rs`, `transport_test.rs`, `tests/transport.rs`,
  `crates/pam_proto/src/lib.rs`, `envelope.rs`, `event.rs`, `response.rs`
  doc comments, `broker-macos.sb`, the listed documents), plus
  `crates/pam/tests/legacy_takeover.rs` (new, `cfg(unix)`: the compiled CLI
  against a fake ZMTP daemon on the real `pam.sock` path).
- Acceptance: the grep check above; `cargo tree -i zeromq` and `-i win_uds`
  find nothing; `bash tools/check.sh`; the Windows public adapter tests in
  the Parallels VM and the CI Windows job; `cargo test -p pam --test
  sandbox_macos`.

T9. Integrate and verify (the plan's closing task).

- No source ownership; fixes go back to the owning task's files.
- Rehearse the upgrade with real binaries on macOS: a v0.4.3 daemon running
  loose, then under the LaunchAgent; install the new build over it; run
  `pam status`, open the GUI, run a sandboxed client, run `pam listen`.
  Record what the service manager does with the superseded and the respawned
  daemon before any document states it. Confirm an old `pam` binary against
  the new daemon fails with a connect error and the daemon logs it once.
- Acceptance: the rehearsal notes are recorded on the ptrack task; documents
  match what was observed; the summary and goal text are refreshed.

Order: T1; then T2, T3, T4 together; then T5, T6, T7 together; then T8; then
T9. T6 must start from T2's `tests/daemon.rs`.

## Risks

Risks:

- Service-manager behaviour around a self-restart is not established by any
  test in the repository. `respawn_daemon` now starts the child through the
  client's shared spawn helper (its own process group, a reduced environment),
  but launchd or systemd may still reap it with the unit, leaving the next
  client to lazy-start a loose daemon. Nothing in this design depends on
  the answer, but T9 must observe it before documents describe it.
- The image check can miss a replacement when the daemon's recorded path
  still holds the old file (a versioned install directory reached through a
  path the kernel had already resolved, as `/proc/self/exe` does on Linux).
  The result is a `client_version_mismatch` refusal that names the fix, not a
  restart loop, which is strictly better than today.
- The first pam command after an upgrade, if it runs inside a sandbox, cannot
  stop the pre-migration daemon and fails with an instruction. Any
  unsandboxed pam process (GUI, a terminal command, `pam listen`, the login
  service) clears it.
- A GUI left running across an upgrade is refused on the admin plane until it
  is reopened.
- Peer pid is recorded at accept. It identifies a short-lived process and can
  be reused; it must not grow into an authorisation input.
- On Windows the public plane has no kernel peer identity and no automatic
  takeover. Windows is CI-only today.
- The transitional socket path must not ship. The implementation plan forbids
  a release before T8; if one is forced, sandbox profiles would need the
  transitional path.
- Plan #48's task #200 touches the same handler, restart and cancel code. T2
  starts from its result and drops whatever it already covers.
- Sandbox profiles in the field that still allow `events.sock` are harmless;
  profiles that allow only `events.sock`-style patterns are unaffected
  because the request path keeps its name.

Decisions, taken 2026-10-02 on the four questions this design raised, are
recorded in the next section.

## Decisions

1. **Version skew after the migration with an unchanged image is refused, with
   no automatic takeover.** The client is refused with
   `client_version_mismatch` and told to stop the daemon or use the matching
   binary. A newer unsandboxed client does not stop an older daemon itself,
   because that would let any newer pam binary (a development build, a second
   install) take over the daemon. Only the pre-migration case, where the greeting
   proves an old daemon speaking ZMTP, is stopped by an unsandboxed client.
2. **Public follow events stay content-free.** A follower receives the constant
   progress note, not real progress notes, even though it has passed the check
   that lets it read the ticket's result. Detail stays behind the scoped result
   and evidence reads.
3. **The GUI's cancel uses an admin operation audited as human.** It was added
   in the design-review fix round as `admin.requests.cancel` rather than tracked
   separately, so it is not part of this plan's work (see Already landed).
4. **On Windows a pre-migration daemon is stopped manually.** Windows is CI-only
   today, so no forced `taskkill` takeover is added.
