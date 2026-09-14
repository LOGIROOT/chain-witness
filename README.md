# LogiRoot chain witness

This repository is an off-estate witness of the LogiRoot governance receipt chain. On a cadence, the
gate host publishes one record that commits to the chain head at that moment. The records are
append-only: each names the hash of the record before it, and the repository's history is public.

Each record under `records/<chain>/` is a JSON object with exactly these fields:

`schema_version`, `height`, `head_hash`, `utc_time`, `prev_witness_hash`, `key_id`, `signature`

`records/<chain>/latest.json` is a copy of the newest record.

## Verifying a record

The signature algorithm is ML-DSA-65 (FIPS 204). The signing keys are published in the LogiRoot key
directory at https://api.logirootai.com/.well-known/logiroot-signing-keys.json, where `key_id` is
the key's fingerprint. To check a record: verify `signature` (base64) over the ASCII bytes of
`head_hash` with the public key named by `key_id`, recompute the SHA-256 of the previous record file
exactly as published and check it equals `prev_witness_hash`, and check the record's `height` is
greater than the previous record's.

`verify/` holds a small verifier that does this with no credentials, and the repository's own
workflow runs it on every publication, including against a planted-wrong record that must fail.

Copyright (c) 2026 LogiRoot AI Inc. Records and verifier are published for verification.
