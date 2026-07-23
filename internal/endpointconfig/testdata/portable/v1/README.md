# Endpoint configuration identity fixture v1

`identity-v1.json` is the byte-canonical cross-runtime fixture for endpoint
configuration identity. Copy this file byte-for-byte into every producer and
consumer implementation; do not recreate equivalent vectors independently.

The fixture pins the exact JSON preimage and SHA-256 result for each supported
payload-capture mode. Its file digest is pinned by the Go test so whitespace,
ordering, or vector changes require an explicit contract revision.
