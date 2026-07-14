# Portable Cedar fixtures v1

These JSON files are the canonical portable corpus for request-contract v1.

Request-contract v1 interprets JSON numbers using binary64 semantics, matching
`JSON.parse`. Lexically different number tokens that decode to the same
binary64 value are therefore the same policy input; callers that require exact
textual precision must send a string.

`hashing-v1.json` is copied byte-for-byte from the shared contract. Do not
recreate equivalent hashing vectors independently in another runtime.

The hashing corpus pins the semantic seven-term
`kontext:cedar-deployment:v2` identity. It contains no storage revision or
endpoint operational configuration.

`TestPortableFixtureProvenance` pins the contract version and SHA-256 digest of every file. Update the version and digests only when intentionally adopting a reviewed contract revision.
