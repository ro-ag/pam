# Model acquisition and ownership

PAM never owns or bundles model weights. `pam_model` verifies an existing GGUF
in place or downloads one to a path the user controls. The default path helper
returns:

```text
<platform home>/llm/<vendor>/<filename>.gguf
```

Callers may supply another absolute Unicode path. Vendor, model, and filename
segments are bounded and cannot contain traversal or separators.

## Integrity and consent boundary

A `ModelDescriptor` binds one model identity to:

- an exact byte length and SHA-256 digest;
- one `.gguf` filename;
- a license identifier, credential-free HTTPS notice URL, and exact notice
  digest.

`LicenseConsent` is bound to the complete descriptor: model identity, filename,
expected digest and byte length, and the exact license identifier and notice
digest. Import and download validate consent before filesystem or network
effects. Changing either the artifact or its license therefore requires new
consent.

Local import rejects symlinks and non-regular files, validates a bounded GGUF
structure before trusting its tensor and metadata counts, hashes the complete
file, and returns its canonical external path. It does not copy, move, delete,
or rewrite the selected weight. A hard 1 TiB acquisition ceiling is applied
before path or network effects in addition to the descriptor's exact size.

## HTTPS and resume behavior

`ReqwestDownloadTransport::secure` uses rustls with native platform
verification and system/environment proxy discovery. It enforces HTTPS,
identity content encoding, bounded connect/read waits, and manual redirects.
Every redirect must remain HTTPS and match a descriptor-supplied host allowlist;
credentials are not accepted in source URLs, and transient signed query strings
are never placed in the durable model record.

Literal non-public targets and non-443 ports are rejected. With direct
connections, the HTTPS peer is resolved by the platform-backed HTTP stack. If
a system proxy is configured, that proxy is an explicit trusted network
boundary and may perform its own DNS resolution; PAM does not claim DNS pinning
through an administrator-configured proxy.

Downloads use same-directory `.pam-model.part`, `.pam-model.json`, and lock
siblings. The stable lock file is protected by a process-owned advisory lock,
so a crash does not strand ownership. The checkpoint binds the partial to the
canonical source, expected digest and size, and license digest. A resumable
response requires a strong entity tag, must start at the exact retained byte
offset, preserve the expected total and validator, and match its declared
segment length. A server that ignores a range with `200 OK` causes a safe
truncate-and-restart; bytes are never appended to that full response.

Before publication PAM verifies exact length, SHA-256, and bounded GGUF
structure, syncs the partial, and hard-links the verified inode to the final
destination without replacement. Recovery accepts an already-published final
path only after it independently matches the descriptor. The final path is
never overwritten. Invalid digest or excess bytes discard the partial so it
cannot be mistaken for a resumable artifact.

Filesystem setup, checkpoint mutation, integrity inspection, and publication
run outside the async executor. Platform-sensitive permission, file-identity,
and directory-durability operations stay behind narrow helpers. This slice
validates the macOS path; Windows implementation and execution evidence are
deliberately deferred, and no Windows support is claimed yet.

## Durable metadata

Schema v7 adds a `models` table containing only:

- vendor/name identity and absolute user-owned path;
- exact digest, byte length, and GGUF version/tensor/metadata counts;
- the exact license snapshot;
- sanitized local/HTTPS source identity and registration time.

There is no weight-content column. Registration is idempotent for an identical
record and rejects identity or path conflicts. The runtime must revalidate the
external file before loading it; a registry row does not make replaced or
missing bytes trustworthy.

## Deliberate non-goals for this slice

This slice does not automate gated-model account approval, create or persist
Hugging Face credentials, infer legal compatibility, decode tensor payloads,
recommend quantization, or expose inference. Memory estimation is task #23;
target-machine profiling is task #24; runtime/API ownership is task #25.
