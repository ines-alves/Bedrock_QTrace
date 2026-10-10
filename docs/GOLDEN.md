# Golden contribution format, version 1

M1M4-13 supplies the format now; the evaluator is implemented in task 1.12.
`tests/golden/expected.yaml` is a top-level list conforming to
[golden.schema.json](golden.schema.json). Owners contribute their confirmed rows
on tested branches. No generated reports or private keys belong in this file.
M4 owns cloud expectations; M2 owns network confirmations; M3 owns code confirmations.

Every row has `kind` and `source` (repository-relative input file). Optional
`source_type` uses the frozen SourceType value. `resource` matches
Location.resource_id; `resource_alias` matches Finding.extra.alias instead.
`line` is one-based, with a matching tolerance of two lines. `note` records
verification or uncertainty, but unverified rows cannot establish a passing gate.

The evaluator scans with the repository root fixed as the scan root, ensuring
Location.file matches each repository-relative source. A direct-file scan instead
uses the file's parent (network.pcap versus network-capture/network.pcap), which
can change session_id because the hash includes Location.file. Do not use literal
session_id selectors in starter or portable network golden rows; use source plus
observed selectors such as session_sni and transport. The schema still supports
session_id for fixtures with an explicitly fixed root. Ambiguous matches fail;
never choose an arbitrary session or silently match by basename.

Partial captures are separate fixture expectations: ClientHello-only groups may
have offers plus ScanError without extra.session; ServerHello-only groups may
have null offered_* values. HelloRetryRequest alone establishes no negotiated
selection. Keep incomplete coverage/errors explicit; these fixtures do not change
the complete starter-kit counts. M2 behavior was relayed by the user and awaits
tested owner publication/review under M1M2-06.

| Kind | Required fields beyond kind/source | Optional assertions/selectors |
|---|---|---|
| asset | canonical, tier | usage, asset_type, resource/resource_alias, line, classically_broken, hndl_exposed, negotiated |
| finding | kind_hint | raw_name, resource/resource_alias, line, negotiated, extra (recursive subset match) |
| session | tier_session | session_sni, session_id, transport, negotiated_group, tier_kex |
| count | metric, count | source_type, kind_hint, transport, resource/resource_alias |

Asset rows match unique evidence occurrences and then assess canonical name,
classification and flags. Finding rows check raw hygiene/redirect/metadata facts;
they do not enter quantum-risk metrics. Session rows independently verify session
verdict and KEX tier. Count rows count unique resources, unique session IDs, or
unique evidence occurrences after the stated filters; they do not create extra
true positives. Duplicate observations cannot satisfy two expected rows.
Missing/ambiguous matches, wrong tiers/flags, missing scanners and ScanErrors
remain explicit failures. Precision/recall and tier accuracy are reported separately.
Protocol/material inventory does not inflate algorithm accuracy.

```yaml
- kind: asset
  source: cloud-posture/kms_key_inventory.json
  source_type: kms
  resource_alias: alias/release-codesigning
  canonical: RSA-4096
  usage: signature
  tier: CRITICAL
  classically_broken: false
- kind: finding
  source: cloud-posture/load_balancer_listeners.json
  source_type: loadbalancer
  kind_hint: plaintext
  extra:
    lb_name: public-web-alb
    hygiene_only: true
    redirects_to_https: true
    hygiene_flags: [redirect_only_listener]
- kind: count
  source: cloud-posture/kms_key_inventory.json
  source_type: kms
  metric: resources
  count: 10
- kind: session
  source: network-capture/network.pcap
  source_type: pcap
  session_sni: vault01.lab
  negotiated_group: X25519MLKEM768
  tier_kex: SAFE
  tier_session: UNKNOWN
```

M4 cloud section: 10 unique KMS key resources, 7 unique listener resources
(5 TLS/HTTPS and 2 HTTP), 5 unique ACM certificate resources. Include each confirmed
cryptographic occurrence plus raw warning expectations; distinguish the HTTP redirect
from HTTP forwarding while retaining both HTTP findings. Policy classifications
and SYMMETRIC_DEFAULT require M4 primary-source verification before becoming golden.
The source dump timestamp is used for expiry, not the developer's current date.

Derived hygiene advice is asserted in engine behavior tests until an agreed
structured output exists; do not pretend derived flags were observed by scanners.
This format adds no fields to the frozen ScanResult models.
