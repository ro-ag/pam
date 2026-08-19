CREATE TABLE models (
    model_id TEXT PRIMARY KEY NOT NULL
        CHECK (length(CAST(model_id AS BLOB)) BETWEEN 3 AND 257),
    vendor TEXT NOT NULL
        CHECK (length(CAST(vendor AS BLOB)) BETWEEN 1 AND 128),
    name TEXT NOT NULL
        CHECK (length(CAST(name AS BLOB)) BETWEEN 1 AND 128),
    path TEXT NOT NULL UNIQUE
        CHECK (length(CAST(path AS BLOB)) BETWEEN 1 AND 4096),
    digest TEXT NOT NULL
        CHECK (
            length(digest) = 71
            AND substr(digest, 1, 7) = 'sha256:'
            AND substr(digest, 8) NOT GLOB '*[^0-9a-f]*'
        ),
    size_bytes INTEGER NOT NULL CHECK (size_bytes BETWEEN 24 AND 1099511627776),
    gguf_version INTEGER NOT NULL CHECK (gguf_version IN (2, 3)),
    gguf_tensor_count INTEGER NOT NULL CHECK (gguf_tensor_count BETWEEN 1 AND 131072),
    gguf_metadata_kv_count INTEGER NOT NULL CHECK (gguf_metadata_kv_count BETWEEN 0 AND 65536),
    license_id TEXT NOT NULL
        CHECK (length(CAST(license_id AS BLOB)) BETWEEN 1 AND 128),
    license_url TEXT NOT NULL
        CHECK (length(CAST(license_url AS BLOB)) BETWEEN 9 AND 2048),
    license_digest TEXT NOT NULL
        CHECK (
            length(license_digest) = 71
            AND substr(license_digest, 1, 7) = 'sha256:'
            AND substr(license_digest, 8) NOT GLOB '*[^0-9a-f]*'
        ),
    source_kind TEXT NOT NULL CHECK (source_kind IN ('local', 'https')),
    source_identity TEXT
        CHECK (source_identity IS NULL OR length(CAST(source_identity AS BLOB)) BETWEEN 9 AND 4096),
    registered_at_ms INTEGER NOT NULL CHECK (registered_at_ms >= 0),
    CHECK (
        (source_kind = 'local' AND source_identity IS NULL)
        OR (source_kind = 'https' AND source_identity IS NOT NULL)
    ),
    CHECK (model_id = vendor || '/' || name)
) STRICT, WITHOUT ROWID;
