# Bounded evidence for agent callers

PAM evidence reads use the normal CLI, internal socket, admission and audit path.
An evidence ID is a reference, not permission. Each read checks its original
request, canonical repository, current repository/product scope and grant
revocation revision. Administration and protected source inspection stay in the
GUI. Existing evidence without a safe view is explicitly unavailable to agents;
PAM does not export a raw legacy blob as a fallback.

```sh
pam evidence read ev_example --request req_example --json
pam evidence read ev_example --request req_example --offset 16384 \
  --view view_from_first_response --digest digest_from_first_response --json
```

Use the actual reference returned by a flow. Pages default to 16 KiB and are
limited to 64 KiB. `--length` controls decoded bytes. A nonzero offset requires
the view ID and digest from the first response. JSON carries `encoding: "hex"`
and exact bytes in `data`; offsets may split a UTF-8 character. Text mode escapes
control and binary bytes instead of letting evidence manipulate the terminal.

The first valid read starts one persisted allowance for the original request
and repository: one hour, 64 MiB of requested bytes and 4,096 pages. New command
invocations, retries and different evidence IDs from that request share it.
Reservations remain spent if delivery is cancelled. This read lifetime is
separate from the completed workflow's execution deadline.

The response includes the immutable view digest, source identity, capture time,
redaction policy, byte ranges, provenance and the next offset. EOF means the
view ended; it does not prove the collected evidence explains the failure.
Completeness remains explicit. Retention removes view content but preserves a
scoped tombstone until request retention, allowing `evidence_expired` to be
distinguished from unknown evidence only after authorization.

## Redaction and provenance

Protected originals and public views have separate identities. Redaction runs
over the bounded complete artifact before pagination, so splitting a secret
across pages does not expose it. Detection covers specified credential patterns;
it is not a guarantee that arbitrary sensitive business content can be detected.
Do not place secrets in flow definitions or task arguments.

Logs are redacted before deterministic compaction, then redacted again after
normalization before model input. Optional semantic selection and model output
also pass through redaction. A redaction or provenance failure never selects
raw content as a fallback. Connector origin metadata captures the connection
and resolved arguments actually used; it stays private. Derived local evidence
conservatively retains the preceding connector authorities.

Mappings distinguish unchanged byte ranges, redacted ranges, covering source
records, omitted regions and synthetic text. ANSI removal and UTF-8 rendering
mean that a compact substring can identify a covering record without providing
an arithmetic character offset into the original log. Synthetic footers and
omission markers are not source quotations. Semantic spans map to the compact
view that was actually scored, then to the redacted source, then to protected
source ranges. Never compare a view's offsets or digest against raw source bytes.

## Implementation checks

Run the repository gate, `bash tools/check.sh`. Relevant regressions cover
immutable binary ranges, continuation identity, ownership, revocation, retained
tombstones, persistent allowances, secret boundaries, normalized logs, semantic
span validation and CLI rendering. Local model usefulness and compressor quality
remain separate qualification tasks in the delivery roadmap.
