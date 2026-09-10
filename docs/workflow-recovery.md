# Workflow restart recovery

Task #133 extends the existing flow engine. It does not introduce another
workflow service or change the CLI/Unix IPC boundary. Job polling and guarded
landing remain tasks #134 and #135.

## Durable boundary

Schema 9 stores a request-linked flow journal and cumulative work counters.
A journal binds the recipe digest, canonical repository and resolved-input
fingerprint. Before each step, the daemon commits its intent. After the step,
it saves a bounded protected checkpoint and atomically advances the journal
revision. The journal holds evidence references rather than log bodies.
Checkpoints have no public evidence view and cannot be retrieved through the
agent evidence interface.

A saved checkpoint contains completed reports, variable state and evidence
origins. Recovery validates the binding, retained checkpoint, and current
repository/product access before using it. Completed steps are skipped; a
completed workflow can regenerate its final result without running its steps.
Missing or pruned snapshots or cited source evidence stop recovery rather than causing a fresh execution.

The daemon restores only an originally admitted, unexpired flow request under
its existing ticket and authorization revision. It does not reset the deadline,
refresh revoked authority, or turn a terminal ticket back into queued work.
Old pending approval records are timed out; any remaining step passes current
runtime gates. Legacy in-flight requests without a journal retain the explicit
`daemon_restart` failure.

## Uncertain effects

A crash after intent is committed and before completion is recorded leaves a
prepared step. A prepared read can be attempted again, charged to the same
budget. A prepared state-changing step becomes `flow_effect_uncertain`; the
original request fails and its journal remains uncertain. The same rule applies
to cancellation, lease expiry and persistence failure after a possible effect;
the shared terminal writer records uncertainty atomically. This includes a
crash immediately before spawn: absence of a recorded result is not proof that
nothing happened. PAM never automatically replays this step.

A nonzero exit from a state-changing command also disables the recipe's
ordinary retry loop. Such a command may have partially changed the repository.
An explicit subsequent recovery step may still run under its own policy gate.
Typed remote-effect reconciliation belongs to guarded landing; generic command
output cannot prove whether a push, merge or publication happened.

## Budgets across crashes

Attempts, physical HTTP sends and maximum capture bytes are reserved in the
store before external I/O. Exactly completed captures refund unused bytes
through a consuming operation. Cancellation or an ambiguous persistence failure
retains a conservative charge; no automatic refund retry is permitted.
Thus `budget_usage` means actual completed bytes plus outstanding reservations,
not necessarily bytes received. Attempts and HTTP call counts are never refunded.
Original ceilings remain 256 attempts, 128 HTTP sends, 128 MiB HTTP capture,
128 MiB command capture and the admitted deadline (at most one hour).

All store operations serialize access to the Turso connection. Journal state
transitions and budget reservations/refunds use individual atomic statements,
avoiding a cancelled future leaving an explicit transaction open.

## Verification requirements

The acceptance boundary is restart behavior, not serialization alone:

- A completed read is not repeated when a later read is interrupted.
- A prepared effect never executes after restart, including repeated restarts.
- The original ticket, expiry and spent budget survive reopening the store.
- Recipe, input, repository or access changes stop checkpoint use.
- Missing evidence and persistence failures stop dependent work.
- A failed stateful command with three configured retries executes once.

Store and daemon fixtures use local test transports and fake credentials. They
do not establish compatibility with a live enterprise deployment or constitute
qualification of the optional local model.
