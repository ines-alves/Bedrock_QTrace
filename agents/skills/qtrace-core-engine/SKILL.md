---
name: qtrace-core-engine
description: Implement QuantumTrace M1 contracts, knowledge base, core risk engine, pipeline, CLI, native reporting, and accuracy evaluation while preserving scanner evidence and shared interfaces. Excludes other members' scanner and UI implementations.
---

# QuantumTrace core implementation

Read `docs/PLAN.md` sections 3, 5–7, the M1 work package, Appendix D, approved
`docs/DECISIONS.md` updates, and the active plan in `agents/tasks/`.

- Establish section 6 contracts in 1.2 before engine work. Import shared models;
  after the initial freeze, coordinate further contract changes with the team.
- Detection stays in scanners; classification and score rules stay in engine/KB.
  Decompose composites before normalization and preserve raw names and evidence.
- Normalize aliases and parameters without treating bare numbers as untyped TLS
  codepoints. Use the finding's kind hint and the owner's verified registry.
- Canonical aggregation distinguishes usage, parameters, and asset type. Keep
  per-finding confidence, exposure, cloud state, source, and offered/negotiated
  evidence available to scoring; do not reconstruct these from Location alone.
- Apply the approved UNKNOWN authentication rule for unobservable TLS certificates.
  Hybrid KEX is SAFE as a combiner, not the worst tier of its two halves. Keep
  actual component relationships for traceability without overriding this rule.
- HMAC-SHA1 is not a collision-broken SHA-1 signature. Signatures are not HNDL
  exposure. Unknown key sizes, plaintext, and hygiene require distinct handling.
- Use `agents/IMPLEMENTATION.md` scoring exclusions and aggregation defaults.
  Protocol summaries must not score the same components twice. Preserve source
  distinctions when computing source summaries and negotiated HNDL floors.
- Verify standards, codepoints, OIDs, and cloud mappings against primary sources
  during the owning task. Record uncertainty; never label a draft alias as proof
  of final-standard compliance.
- Native reports round-trip through `ScanResult`, including the optional typed
  roadmap established in 1.2. API/UI/CBOM consumers belong to M4; coordinate them.

Test behavior against relevant Appendix D traps plus own local fixtures. Use
hand-computed scores, shuffled-input determinism, unknown inputs, incomplete scans,
SAFE decoys, and JSON round-trips where relevant. Golden metrics must distinguish
missed detection from incorrect classification and print incomplete coverage.
