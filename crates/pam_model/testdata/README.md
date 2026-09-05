# `pam_model` test data

Deliberately empty of binaries.

GGUF weights are gigabytes; no fixture of a useful size can live in git, and
a truncated one would only prove the truncation. So the unit tests
**synthesize** GGUF headers in memory instead: `gguf_test.rs` writes real
little-endian headers (magic, version, metadata KV pairs, tensor infos) byte
by byte and feeds them to the parser. That lets each test name exactly the
malformation it is about — a bad magic, an absurd tensor count, an
overlapping offset — instead of hoping a captured file happens to contain
one.

The download tests (task #33) serve their bytes from a tokio TCP server
started inside the test, and the runtime bench (task #34) reads a real model
from the path in `PAM_BENCH_MODEL`. It is explicitly ignored by default;
run it with `PAM_BENCH_BACKEND=cpu` or `metal` and `--ignored --nocapture`.
An ordinary test pass does not establish real-model inference qualification.

Nothing here is read at runtime; this directory exists to say why it is
empty.
