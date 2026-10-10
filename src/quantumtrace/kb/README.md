# M1 knowledge base

`load_kb()` reads packaged `algorithms.yaml` and `scoring.yaml` independently of the
working directory. Pass a `Path` to load an explicit directory instead. Missing
required resources or invalid policy raise `KnowledgeBaseError` with the resource
name. YAML uses SafeLoader with duplicate-key rejection. No network is accessed.

The returned `KnowledgeBase` exposes immutable `algorithms`, `aliases`, compiled
`patterns`, `scoring`, and `optional_registries` presence flags. `get(id)` returns a
canonical entry or raises KeyError; `by_alias(raw_name)` identifies an exact alias
or returns None. This is data lookup, not evidence normalization or classification.
Patterns operate on `alias_key(raw_name)` and are anchored; task 1.4 resolves
captured parameters and any competing matches using the finding's usage/kind.
Decompose before normalization in task 1.5. A composite alias must retain its
components, rather than discarding hashes or fixed DH parameters.

`load_scoring()` loads scoring alone. `Scoring.as_dict()` returns an independent
JSON-compatible copy for M4's read-only `/api/scoring`. Stable keys are
`tier_weights`, `exposure`, `broken_multiplier`, `occurrence`, `grade_bands`,
`hndl_floor`; `aes_192_tier` permits the specification's explicit policy option
and defaults to MEDIUM. Exposure selects the maximum applicable category; offered,
configured and negotiated evidence must remain distinct. The evaluator/engine
implements the formula later; this loader does not compute scores.

`Algorithm` includes usage/mode primitives, tier/key-size policy, references to
replacement/component entries, optional observed-parameter rules, and sourced facts.
Mappings are read-only, sequences are tuples, and nested records are frozen.
Classical-break conditions distinguish hash/signature use from MAC use. Generic
CMAC/GMAC needs underlying cipher evidence. KDFs retain underlying-hash policy.
Warnings are policy identifiers (`ecb_mode`, `pbkdf2_iterations_below_100000`) for
future engine interpretation, separate from scanner-observed hygiene flags.

SAFE is repository quantum-risk policy. It does not certify an implementation,
provider or parameter choice. Missing fact fields remain None. Nominal symmetric
key sizes do not automatically assert NIST security categories. Legacy
Kyber/Dilithium/SPHINCS aliases preserve pre-standard provenance; recognizing a
name does not prove final FIPS compliance. Falcon/FN-DSA and HQC retain explicit
in-development status. Hybrid components do not override their atomic KEX tier;
authentication/session verdict is separate.

Every entry cites dated repository policy and primary references for claimed
facts. Numeric TLS registries belong to M2; cloud provider mappings belong to M4.
Optional registry presence is reported, without parsing or inventing those tables.
`SYMMETRIC_DEFAULT` remains provider-specific/UNKNOWN here: its spelling alone
cannot establish the algorithm across AWS regions. Task 1.4/1.5 integrates verified
owner registries and retains unresolved or conflicting metadata explicitly.
