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
outside GROUP/CIPHER_SUITE/SIGNATURE_SCHEME/PROTOCOL_VERSION remain unknown. Observed
`extra.codepoint` and `extra.iana_name` are cross-checked with raw names and rows;
conflicts retain evidence and prevent a resolved verdict. Unknown hex identity
uses canonical uppercase four-digit spelling within its original namespace.

Owner registry files are currently absent. No guessed TLS/cloud tables or file
schemas are implemented. Task 1.5 must connect the published validated owner
interfaces when available. The synthetic private codepoints in tests exercise
resolver mechanics and make no real-world registry claims. SSH/composite names
retain their KB identity/components for later decomposition; `ssh-rsa` is not
rewritten to a bare RSA key, and fixed DH group/hash metadata remains in the KB.

# Composite evidence trees

`decompose(finding, kb, *, registry=None, named_registry=None,
cloud_registry=None) -> Decomposition` runs before classification. It retains the
original Finding, optional root, drop reason/issues, resource_id and sorted unique
certificate_arns. Resource associations are raw links; joins and session verdicts
remain later engine/pipeline work. No scanner, shared model or owner file changes.

`EvidenceNode` contains a stable node_id, parent_id, semantic role, kind,
NormalizedFinding, scoreable flag, children, forward_secrecy and notes. `walk()`
returns preorder nodes. Every node's normalized.finding is the original Finding,
not a generated scanner emission. Component parameters are normalized using
private projections and scoped inheritance, with observed/recipe contradictions
retained. Certificate issuer signatures never inherit subject key size or curve.
A KMS key with observed signature metadata produces one signature/key algorithm
atom and its digest, without a duplicate scored key atom. SHA-1 signature and
HMAC-SHA1 MAC remain distinct usages and algorithms.

Dispatch on node.kind before applying atomic KB policy:

- `atom`: classify its normalized identity, checking conflicts/unknown reasons.
- `container`: derive its summary from children; it is never scored. The original
  composite need not match an atomic KB entry, so an unrecognized parent lookup
  alone is not an unknown component. Actual resolution failures return an unknown
  atom with explicit uncertainty, rather than partially pretending to resolve.
- `hybrid`: classify the atomic combiner; its children are trace-only and cannot
  override the combiner verdict. Do not score these halves or combiner hashes.

`scoreable` describes eligibility, not assigned risk. Hygiene-only/library/plaintext/protocol-version observations
and KB-excluded warnings are unscored. Classify trace nodes for explanation if
useful, while retaining their parent relationship and exclusion. Duplicate recipe
nodes with the same semantic ID are collapsed; provenance is retained. Node IDs
hash Finding.id, parent ID, role and canonical identity; timestamps, confidence,
source metadata and recipe traversal order do not enter IDs.

Named IANA TLS suites are parsed structurally with anchored rules. TLS 1.2 static
RSA supplies key transport and authentication mechanisms with unknown certificate
key size; derived mechanisms do not establish an observed certificate. CBC suffix
hashes become HMAC components; AEAD suffix hashes describe the PRF. TLS 1.3 suites
supply only cipher and HKDF, with no guessed group/authentication. `ccm-8` variant
retains truncated-tag construction. PSK compositions remain unknown as combiners;
PSK/anonymous authentication and unspecified forward secrecy remain explicit.
Session authentication observability and the approved UNKNOWN hybrid-session rule
are handled later, not inferred from a cipher-suite tree.

`NamedTLSResolver.resolve_name(kind, raw_name)` returns a verified RegistryResolution
for an OpenSSL alias. No ad hoc OpenSSL-to-IANA table is supplied. Numeric TLS lookup
uses the normalization RegistryResolver, preserving namespace and metadata conflict
checks. PROTOCOL_VERSION uses the versions namespace only, retaining the original
label and partial-session metadata; missing/null evidence is not replaced by
invented negotiation or authentication. GREASE and SCSV are dropped only in relevant namespaces; conflicting
metadata prevents dropping meaningful evidence. Decimal values are never guessed.

`CloudResolver.resolve(Finding)` returns a CloudResolution with matching raw_name,
source_type, nonempty primary-source reference, verified=True and nonempty tuple
of ComponentSpec recipes. The owner adapter validates its schema and conditional
provider/region/source mappings. ComponentSpec carries name, usage, role, kind,
optional size/curve/mode/padding/parameter set/underlying hash/variant, parameter
inheritance and source. KEY parameter scopes cannot silently override observed
sizes. A policy may supply named CIPHER_SUITE components; these receive their own
unscored container and linked children. These interfaces are internal injection
boundaries, not new shared Finding requirements. Supplied signature_algorithm and
key_algorithm metadata are observed evidence, not engine-selected defaults.

The current checkout and integrated main lack TLS/cloud registries. M2 has now published a registry on
its unintegrated owner branch; consumption awaits reviewed integration. Known
key-spec aliases reuse the sourced KB; provider-specific SYMMETRIC_DEFAULT and
unmapped policies retain explicit absent coverage. Verified fake adapters/private
codes in tests exercise mechanics and make no production assignment claims.
Real registry/file adapters await owner publication. Unknown/verify-only inputs
never gain invented rows, key sizes, parameters, OIDs or standard compliance.

# Decomposition fact references

Primary sources checked 2026-10-10; these describe syntax/mechanisms, not repository
risk tiers. The existing dated KB remains the source for algorithm policy/PQC facts.

- [RFC 5246](https://www.rfc-editor.org/rfc/rfc5246.html), sections 6.2.3 and
  7.4: TLS record MAC/AEAD and key exchange/authentication roles.
- [RFC 5288](https://www.rfc-editor.org/rfc/rfc5288.html), section 3: AES-GCM
  suite suffixes identify PRF hashes, not a separate record MAC.
- [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html), sections 4.1.2 and
  7.1: TLS 1.3 suites and the suite-bound HKDF hash; authentication is separate.
- [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html), sections 3 and 4:
  JOSE signature/MAC/curve/AEAD/OAEP names and parameters.
- [RFC 8037](https://www.rfc-editor.org/rfc/rfc8037.html), section 3.1:
  generic EdDSA supports Ed25519 and Ed448; it alone establishes neither variant.
- [Oracle standard algorithm names](https://docs.oracle.com/en/java/javase/25/docs/specs/security/standard-names.html)
  and [OAEPParameterSpec](https://docs.oracle.com/en/java/javase/25/docs/api/java.base/javax/crypto/spec/OAEPParameterSpec.html):
  JCA transformations and separate main/MGF digest parameters. Observed OAEP main
  digest is retained, with MGF1 digest unresolved rather than assumed equal.
- [RFC 5656](https://www.rfc-editor.org/rfc/rfc5656.html), section 6.2:
  SSH named ECDH curves and SHA-256/384/512 exchange hashes. Other SSH fixed
  groups/signature/hybrid facts reuse the sourced KB.
- [RFC 8701](https://www.rfc-editor.org/rfc/rfc8701.html), section 2:
  reserved GREASE structure. SCSV names/values follow RFC 5746 and RFC 7507.

# Central classification

`classify(EvidenceNode, KnowledgeBase, *, scan_started_at: datetime | None = None)
-> ClassifiedNode` interprets one decomposed tree. It neither loads resources nor
reads the clock, aggregates evidence, builds sessions or assigns risk points.
`ClassifiedNode` and `Advice` are frozen; `walk()` retains the tree. Each row holds
its original node/Finding, confidence, exclusions, tier/threat, primitive, flags,
verified optional facts, rationale and ordered deduplicated advice. The original
Finding remains read-only, including all owner metadata and negotiated/source
state. `to_asset()` returns an independent CryptoAsset with stable node links,
copied Location, original finding ID and zero scoring placeholders. Aggregation
in 1.7 must replace per-evidence asset IDs with canonical aggregate IDs and update
relationships; never collapse the private records to Location alone.

Eligibility is `row.scoreable`: derived containers, hybrid trace halves,
hygiene-only/plaintext/library/version observations and KB exclusions are excluded
from quantum scoring and readiness. Unknown crypto stays eligible. Hygiene on a
crypto observation does not exclude its actual cryptographic policy. Do not feed
trace halves into session/composite mechanism summaries or scoring denominators.
Container flags summarize children; e.g. group14 has an unbroken 2048-bit DH
component but its SHA-1 exchange-hash component carries the KB collision-use flag.
The container is unscored, so this never multiplies DH risk twice.

Atomic hybrids follow their combiner policy, irrespective of classical trace
children. `summarize_verdict(components, *, require_authentication=False,
authentication_observable=None) -> VerdictSummary` combines actual mechanisms
with CRITICAL > MEDIUM > UNKNOWN > SAFE. Session assembly must set
`require_authentication=True` and pass observed authentication separately. Unknown
observability or missing authentication adds UNKNOWN, preserving known critical/
medium verdicts. Observability True does not supply a missing key. Cipher-suite
containers apply this authentication guard too. This helper creates no TLSSession
and never interprets encrypted/absent certificates as guessed RSA/ECDSA evidence.

Classify scanner/name conflicts conservatively: parameter-only uncertainty cannot
make any-size RSA/DH/ECC quantum-safe, but no parameter-dependent classical flag
or verified facts are asserted. Identity/namespace/usage conflicts and unknown
resolution prevent an established critical identity; other conflicting records
are UNKNOWN. Unknown AES size is MEDIUM with confidence capped at 0.5 (raw
confidence unchanged); unsupported observed cipher sizes remain UNKNOWN. AES-192
uses the approved configurable KB policy. Modes are lowercase schema values;
GCM/CCM have `ae` primitive; observed ECB gets separate hygiene advice. No provider
default is inferred. HMAC/KDF hash use does not inherit collision-use flags.
Generic CMAC/GMAC requires observed underlying cipher; generic HMAC requires hash.
KDFs follow observed underlying hash/cipher when available, otherwise their KB
quantum-policy default; this does not audit work factor or hand-rolled code.

HNDL applies to Shor-vulnerable key_exchange in PCAP/live/SSH/LB evidence only;
signature/authentication and encryption usage alone do not imply recorded traffic.
Negotiation remains untouched for the later scoring floor. Static RSA key transport
retains false forward secrecy and its recorded-session risk. No forward secrecy
is invented for generic or hybrid mechanisms. Recommendations distinguish signing
from key establishment; KEM replacement for encryption explicitly requires a data
encryption construction. SAFE assets need no migration recommendation; observed
hygiene can still require advice. Explicit truncated hash/XOF outputs without a
packaged verified output policy remain UNKNOWN.

OID/security facts only come from the dated KB, keyed by verified parameter sets
or exact AES-GCM size/mode. Nominal key bits never produce NIST quantum categories.
Legacy Kyber/Dilithium/draft observations retain their flag and notes, while final
OID/category/standard fields are withheld; alias lookup is not final conformity.
Falcon/HQC final facts remain absent. Parameter-category claims are conditional
on conforming implementations, and hybrid recognition never certifies a combiner.

Cloud hygiene derives from retained source_timestamp, then an explicit timezone-
aware scan_started_at fallback. Missing reference/invalid expiry leaves advice
unresolved; no hidden current date. Imported/external/pending-deletion/rotation,
expired ISSUED in-use certificates, <90-day expiry and SHA-1 certificate signatures
are explained in rationale/advice, with HSM and multi-region as context. Raw
Findings are not rewritten and no CryptoAsset.extra field is introduced.

Classification sources checked 2026-10-10: existing dated KB policy/fact sources
remain authoritative. Additional primary checks are
[FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final) for distinct digest
lengths (including SHA-512/256),
[FIPS 202](https://csrc.nist.gov/pubs/fips/202/final) for SHA-3/XOF distinction,
[RFC 6151](https://www.rfc-editor.org/rfc/rfc6151.html) for collision use versus
HMAC-MD5, and the [CycloneDX 1.6 schema](https://cyclonedx.org/schema/bom-1.6.schema.json)
for primitive/mode enums. Tier/default hygiene thresholds are repository policy,
not additional standards or security-level facts. Production registry integration,
real scanner/golden evaluation and full session construction remain later gates.

# Deterministic aggregation

`aggregate(roots: Iterable[ClassifiedNode]) -> Aggregation` consumes classified
roots with their children. It produces sorted independent public `assets`, a
read-only `evidence_index` keyed by aggregate asset ID, and sorted `issues` for
missing explicit cloud certificate references. It does not load resources, read
the clock, assign points, infer usage, or build sessions. Public assets can be
updated by scoring; their Locations/recommendations do not alias raw Findings.
Original Findings held by private records must still be treated as read-only.

Asset IDs hash the complete canonical identity (including padding, underlying
hash/cipher, variant, output size, conflicts, usage and asset type), node kind,
eligibility/exclusions and resource scope. Resolved aliases share identity.
Unknown sizes/usages/conflicts never borrow values from nearby findings. Resource
IDs keep keys, certificates and listener policies distinct; absent material IDs
fall back to physical evidence. Code/config algorithm observations without resource
IDs merge across files, including generation/call observations with the same
observed usage. Containers with flow/session evidence retain session scope;
algorithm components may be shared and have multiple parents. Hybrid trace-only
halves cannot merge into scored classical atoms or override the atomic hybrid.
IDs exclude timestamps, detector, confidence and input order. Links are sorted,
bidirectional and remapped from classified trees to aggregate IDs.

Each `EvidenceOccurrence(occurrence_id, records)` groups one physical site with
all distinct `ClassifiedNode` detector/state/provenance records. Physical sites use
source, file, line, flow, resource, target and session; frame/SNI distinguish packets
without a flow/session/resource/line. Repeated packets in a known flow/session and
multiple detector emissions at the same site count once. Without any locator,
the scanner finding ID is the conservative fallback. Snippet/negotiation/test
state/confidence/extra do not create extra occurrences. Identical records supplied
repeatedly are idempotent. Different records with the same finding ID survive.
All original Locations, frames, snippets, raw aliases and arbitrary extra keys
remain in the private records even when one deterministic representative Location
is selected per public occurrence. `occurrence_id` identifies the site, with the
asset ID supplying its cryptographic context.

Task 1.8 must filter each occurrence's `records` by `scoreable` and source before
counting sites, taking maximum applicable confidence/exposure, or applying the
negotiated HNDL floor. Effective confidence is `record.confidence`; original
scanner confidence stays on `record.node.normalized.finding`. Exclusions, normalized
provenance and all raw cloud/source/usage evidence remain available. Never compute
source summaries or the floor using public union flags: the public HNDL flag and
negotiation flag can originate from different observations. `negotiated` is True
if any record is True, False if all are False, otherwise None. Test-only is True
only with at least one code record and all code records marked test-only; other
source exposure remains independent in the index. Public facts/forward secrecy
require unanimous observed agreement; a final name cannot certify a legacy alias.
Flags/rationale/advice are deterministic unions and tier uses the frozen precedence.

Cloud joins connect LOADBALANCER POLICY roots only through explicit
`extra.certificate_arns` to observed CERTIFICATE root resource IDs, never by an
assumed equal listener/certificate ARN. Certificate components remain under their
own resource identities. Linked certificate tier, classical/HNDL flags and renewal
advice reach the listener summary; containers stay excluded from scoring. Missing
references add issues and UNKNOWN authentication without guessing keys; known
CRITICAL/MEDIUM components dominate UNKNOWN. No material inventory asset is
created or scored: M4 builds that inventory from original KEY findings. Unavailable
policy registry coverage remains unresolved in the retained classification; real
owner adapter review/integration and complete session views remain later gates.
