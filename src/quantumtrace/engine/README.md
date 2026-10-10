# Evidence normalization

`normalize(finding, kb, *, registry=None) -> NormalizedFinding` is an internal
engine interface. Pass `load_kb()` explicitly; normalization has no network,
resource loading, cache, clock, classification or aggregation side effects.
Task 1.5 decomposes composite observations before calling normalization.

The frozen record retains the original `Finding` by reference. Treat that model
as read-only: all scanner metadata, locations, confidence, session IDs and
configured/offered/negotiated evidence remain there. Normalization never alters it.
`identity` is a hashable `CanonicalIdentity` containing algorithm ID, observed
usage, asset type and frozen `Parameters`. Unknown spelling, namespace and
conflicts keep unresolved evidence distinct. No asset ID is assigned here.

Exact KB aliases choose identity before anchored patterns. Patterns belonging to
the same entry may still extract parameters from an exact alias. Ambiguous
patterns/captures stay unresolved. Separator cleanup only affects lookup; raw
names survive, and SHA-512/256 remains distinct from SHA-512 and SHA-256.
Curve synonyms normalize to `secp256r1` etc.; observed signature usage selects
ECDSA while key-exchange usage selects ECDH for neutral curve/key names.
Explicit ECDSA/ECDH names with contrary usage record a conflict.

Parameters retain nominal key size, curve, lowercase schema mode, padding,
parameter set, underlying hash/cipher, variant and separate hash output size.
Scanner fields take precedence over name inference. If observations contradict,
the effective field is None and `conflicts` records both values. `provenance`
records scanner/name/registry origins, including supplied size/mode source markers.
Ambiguous/unresolved scanner sizes and withdrawn provider mode assumptions do
not establish effective parameters. Bare AES supplies neither size nor mode.
PKCS5/PKCS7 padding labels stay distinct; this is no provider implementation audit.

`is_resolved` means the identity lookup has no conflict/unknown reason, not that
all parameters or security facts are known. Generic HMAC, CMAC or GMAC may still
need parameters to classify; known AES with unknown size remains a distinct
identity. Classification must inspect `conflicts` and `unknown_reasons` before
using KB policy. `legacy_name` and `notes` preserve Kyber/Dilithium/SPHINCS/draft
provenance even after registry resolution. A normalized legacy name does not
establish conformance to a final standard. No security bits, OIDs or tiers are
inferred here.

`RegistryResolver.resolve(kind, canonical_hex)` supplies an optional, explicitly
validated owner adapter. Its `RegistryResolution` contains exactly the requested
namespace/codepoint, an IANA name, `verified=True` and a nonempty source reference.
The adapter owns file-schema and primary-source validation. Missing, mismatched
or verify-only rows cannot resolve numeric evidence. Bare decimal values and hex
outside GROUP/CIPHER_SUITE/SIGNATURE_SCHEME remain unknown. Observed
`extra.codepoint` and `extra.iana_name` are cross-checked with raw names and rows;
conflicts retain evidence and prevent a resolved verdict. Unknown hex identity
uses canonical uppercase four-digit spelling within its original namespace.

Owner registry files are currently absent. No guessed TLS/cloud tables or file
schemas are implemented. Task 1.5 must connect the published validated owner
interfaces when available. The synthetic private codepoints in tests exercise
resolver mechanics and make no real-world registry claims. SSH/composite names
retain their KB identity/components for later decomposition; `ssh-rsa` is not
rewritten to a bare RSA key, and fixed DH group/hash metadata remains in the KB.
