# Integration — Real starter-kit acceptance checkpoint

Status: planned · Owner: M1 · Priority: P0/P1 gate · Depends on: 1.12 and M2–M4
Branch: `m1/integration-starter-kit`

## Plan before implementation

Confirm integrated owner adapters/registries, M4's CBOM writer/validator, M3's
Markdown integration, and M4 consumption of ScanResult. Run `make check` and the
real starter scan; record runtime and actual metrics. Validate native JSON and
strict CycloneDX 1.6 output using M4's implementation. Do not implement missing
owner modules or call fixture-only plumbing a real starter-kit success.

Check owner-confirmed totals against Appendix D: 97 TLS (54 static RSA, 36 X25519,
7 hybrid), 24 SSH, 10 KMS keys, 7 listeners including 2 plaintext, and 5 ACM certs.
Check all code scenarios/SAFE decoys. Hybrid unobservable auth is UNKNOWN; verify
mixed offered/negotiated and expired-serving anomalies with owners' fixtures.
Fix M1-owned integration issues on this branch, rerun affected/full gates, and log
cross-owner requests. If no code changes are needed, integrate the measured handoff.

## Acceptance checklist

- [ ] Plan/base and real owner implementations confirmed; task branch created.
- [ ] `make check` passes with ≥95% precision/recall and expected tier/flag assertions.
- [ ] Real counts, SAFE decoys, session rules, and output evidence are correct.
- [ ] Native JSON validates; M4 CBOM strict-validates and consumption is verified.
- [ ] Complete scan is under 60 seconds with actual runtime recorded.
- [ ] Starter datasets remain unchanged; known limitations/handoff saved.
- [ ] Correct identity; remote integration verified before optional work.

## Results and contextual handoff

Record commands, actual runtime/metrics/counts, consumer checks, and any blockers.

## Next-session prompt

> I am M1. Start optional task 1.13 only if agents/STATUS.md and the integration
> handoff confirm P0/P1 is green. Read instructions, status, integration handoff,
> 1.13 plan, and task-cycle/core-engine skills. Implement the CI CLI features,
> validate and integrate with my Git profile, save the final handoff, and end.
