"""Local aggregation acceptance: identity, evidence multiplicity and graph behavior."""

from dataclasses import replace
from itertools import permutations

import pytest

from quantumtrace.engine.aggregate import aggregate
from quantumtrace.engine.classify import classify
from quantumtrace.engine.decompose import CloudResolution, ComponentSpec, decompose
from quantumtrace.kb.loader import load_kb
from quantumtrace.models import CryptoAsset, Finding, KindHint, Location, SourceType, Tier, Usage


@pytest.fixture(scope="module")
def kb():
    return load_kb()


def finding(name="AES", **updates):
    data = dict(
        id="a",
        raw_name=name,
        kind_hint=KindHint.ALGORITHM,
        usage=Usage.ENCRYPTION,
        key_size=256,
        detector="fixture",
        location=Location(source_type=SourceType.CODE, file="a.py", line=10),
    )
    data.update(updates)
    return Finding(**data)


def classified(kb, raw=None, **updates):
    return classify(decompose(raw or finding(**updates), kb).root, kb)


def payload(result):
    return [asset.model_dump(mode="json") for asset in result.assets]


def evidence(result):
    return {
        key: [
            (site.occurrence_id, [item.model_dump(mode="json") for item in site.findings]) for site in sites
        ]
        for key, sites in result.evidence_index.items()
    }


def test_alias_merge_and_unique_detector_occurrences(kb):
    one = finding("AES256", key_size=None, id="one", detector="regex", confidence=0.7)
    two = finding(
        id="two",
        detector="ast",
        confidence=0.9,
        location=one.location.model_copy(update={"snippet": "AES sink"}),
    )
    third = finding(id="three", location=one.location.model_copy(update={"line": 20}))
    rows = [classified(kb, item) for item in (one, two, third)]
    result = aggregate([*rows, rows[0]])
    assert len(result.assets) == 1
    asset = result.assets[0]
    assert asset.finding_ids == ["one", "three", "two"]
    assert len(asset.occurrences) == 2
    sites = result.evidence_index[asset.asset_id]
    assert sorted(len(site.records) for site in sites) == [1, 2]
    assert {id(raw) for site in sites for raw in site.findings} == {id(one), id(two), id(third)}
    for shuffled in permutations(rows):
        other = aggregate(shuffled)
        assert payload(other) == payload(result)
        assert evidence(other) == evidence(result)


@pytest.mark.parametrize(
    "change",
    [
        {"key_size": None},
        {"key_size": 128},
        {"mode": "CBC"},
        {"usage": Usage.MAC},
        {"raw_name": "ChaCha20"},
        {"extra": {"hygiene_only": True}},
        {"location": Location(source_type=SourceType.KMS, resource_id="key:1")},
    ],
)
def test_different_identity_does_not_merge(kb, change):
    assert len(aggregate([classified(kb), classified(kb, finding(**change))]).assets) == 2


def test_padding_splits_rsa_schemes_but_not_block_cipher_configurations(kb):
    aes = aggregate([classified(kb), classified(kb, finding(padding="PKCS7", line=11))])
    assert len(aes.assets) == 1 and len(aes.assets[0].occurrences) == 1
    rsa = finding("RSA", key_size=2048)
    rows = [classified(kb, rsa), classified(kb, rsa.model_copy(update={"padding": "OAEPPadding"}))]
    assert len(aggregate(rows).assets) == 2


@pytest.mark.parametrize(
    "parameter,value",
    [
        ("underlying_hash", "SHA-1"),
        ("underlying_cipher", "AES"),
        ("variant", "ccm-8"),
        ("output_size", 64),
        ("parameter_set", "test-only"),
    ],
)
def test_private_parameter_identity_retained(kb, parameter, value):
    original = classified(kb)
    node = original.node
    identity = replace(
        node.normalized.identity,
        parameters=replace(node.normalized.identity.parameters, **{parameter: value}),
    )
    changed = replace(original, node=replace(node, normalized=replace(node.normalized, identity=identity)))
    assert len(aggregate([original, changed]).assets) == 2


def test_unknown_never_borrows_size_or_usage_from_same_file(kb):
    rows = [
        classified(kb, finding("RSA", key_size=size, usage=usage, extra={"usage_source": "flow"}))
        for size, usage in [(1024, Usage.SIGNATURE), (None, Usage.SIGNATURE), (1024, Usage.UNKNOWN)]
    ]
    result = aggregate(rows)
    assert len(result.assets) == 3
    assert {(a.key_size, a.usage) for a in result.assets} == {
        (1024, Usage.SIGNATURE),
        (None, Usage.SIGNATURE),
        (1024, Usage.UNKNOWN),
    }
    assert all(
        site.findings[0].extra["usage_source"] == "flow"
        for sites in result.evidence_index.values()
        for site in sites
    )


def test_resources_and_fallback_certificate_locations_stay_distinct(kb):
    rows = [
        classified(
            kb,
            finding(
                "RSA2048",
                kind_hint=KindHint.KEY,
                key_size=None,
                location=Location(source_type=SourceType.KMS, resource_id=arn),
            ),
        )
        for arn in ("key:1", "key:2")
    ]
    assert len(aggregate(rows).assets) == 2
    certs = [
        classified(
            kb,
            finding(
                "RSA2048",
                kind_hint=KindHint.CERTIFICATE,
                key_size=None,
                location=Location(source_type=SourceType.KEYFILE, file=path),
            ),
        )
        for path in ("one.pem", "two.pem")
    ]
    assert len(aggregate(certs).assets) == 4
    assert_graph(aggregate(certs))


def test_mixed_evidence_preserves_source_state_and_confidence(kb):
    code = finding(
        confidence=0.8, in_test_code=True, extra={"usage_source": "flow", "custom": {"a": [1, None]}}
    )
    offered = finding(
        id="offered",
        confidence=0.4,
        negotiated=False,
        location=Location(source_type=SourceType.PCAP, file="capture", flow="flow", frame=1),
        extra={"certificate_state": "encrypted"},
    )
    selected = offered.model_copy(
        update={
            "id": "selected",
            "negotiated": True,
            "confidence": 0.9,
            "location": offered.location.model_copy(update={"frame": 9}),
        }
    )
    result = aggregate(classified(kb, item) for item in (code, offered, selected))
    assert len(result.assets) == 1
    asset = result.assets[0]
    assert asset.negotiated is True and asset.in_test_code_only is True
    assert len(asset.occurrences) == 2
    records = [row for site in result.evidence_index[asset.asset_id] for row in site.records]
    assert sorted(row.confidence for row in records) == [0.4, 0.8, 0.9]
    assert {row.node.normalized.finding.negotiated for row in records} == {None, False, True}
    assert any(row.node.normalized.finding.extra == code.extra for row in records)
    production = code.model_copy(update={"id": "prod", "in_test_code": False})
    assert aggregate([classified(kb, code), classified(kb, production)]).assets[0].in_test_code_only is False
    assert aggregate([classified(kb, offered)]).assets[0].in_test_code_only is False


@pytest.mark.parametrize(
    "states,expected",
    [([False, None], None), ([False, False], False), ([None, None], None), ([True, False], True)],
)
def test_public_negotiation_summary_is_conservative(kb, states, expected):
    result = aggregate(classified(kb, finding(id=str(i), negotiated=state)) for i, state in enumerate(states))
    assert result.assets[0].negotiated is expected


def assert_graph(result):
    by_id = {asset.asset_id: asset for asset in result.assets}
    for asset in result.assets:
        assert asset.components == sorted(set(asset.components))
        assert asset.component_of == sorted(set(asset.component_of))
        assert asset.asset_id not in asset.components
        for child in asset.components:
            assert asset.asset_id in by_id[child].component_of
        for parent in asset.component_of:
            assert asset.asset_id in by_id[parent].components


def test_composites_remap_shared_components_and_shuffle(kb):
    rows = [
        classified(kb, finding(name, id=str(i), key_size=None, usage=Usage.UNKNOWN))
        for i, name in enumerate(["TLS_RSA_WITH_AES_128_CBC_SHA", "TLS_RSA_WITH_AES_256_CBC_SHA", "AES128"])
    ]
    result = aggregate(rows)
    assert_graph(result)
    mac = next(a for a in result.assets if a.canonical_name == "HMAC-SHA1")
    assert len(mac.component_of) == 2
    assert mac.classically_broken is False
    for order in permutations(rows):
        assert payload(aggregate(order)) == payload(result)
    for asset in result.assets:
        assert CryptoAsset.model_validate_json(asset.model_dump_json()) == asset


def test_atomic_hybrid_trace_never_absorbs_scored_classical_key(kb):
    hybrid = classified(kb, finding("X25519MLKEM768", key_size=None, usage=Usage.KEY_EXCHANGE))
    classical = classified(kb, finding("X25519", id="classical", key_size=None, usage=Usage.KEY_EXCHANGE))
    result = aggregate([hybrid, classical])
    assert_graph(result)
    combiner = next(a for a in result.assets if a.canonical_name == "X25519MLKEM768")
    assert combiner.tier == Tier.SAFE and not combiner.hndl_exposed
    xrows = [a for a in result.assets if a.canonical_name == "X25519"]
    assert len(xrows) == 2
    eligibility = {
        any(row.scoreable for site in result.evidence_index[a.asset_id] for row in site.records)
        for a in xrows
    }
    assert eligibility == {False, True}


def test_stable_ids_exclude_timestamp_detector_and_confidence(kb):
    first = classified(kb, finding(extra={"source_timestamp": "2026-01-01T00:00:00Z"}))
    second = classified(
        kb,
        finding(
            id="new", detector="other", confidence=0.3, extra={"source_timestamp": "2026-10-01T00:00:00Z"}
        ),
    )
    left, right = aggregate([first]), aggregate([second])
    assert left.assets[0].asset_id == right.assets[0].asset_id
    assert (
        next(iter(left.evidence_index.values()))[0].occurrence_id
        == next(iter(right.evidence_index.values()))[0].occurrence_id
    )


def test_public_payload_is_independent_and_private_mapping_immutable(kb):
    raw = finding()
    before = raw.model_dump()
    result = aggregate([classified(kb, raw)])
    result.assets[0].occurrences[0].file = "mutated"
    result.assets[0].finding_ids.append("mutated")
    assert raw.model_dump() == before
    with pytest.raises(TypeError):
        result.evidence_index["other"] = ()
    assert aggregate([classified(kb, raw)]).assets[0].finding_ids == ["a"]


def test_unknown_names_and_empty_input(kb):
    result = aggregate(
        [classified(kb, finding("unrecognized-one")), classified(kb, finding("unrecognized-two"))]
    )
    assert len(result.assets) == 2 and all(a.tier == Tier.UNKNOWN for a in result.assets)
    assert aggregate([]).assets == () and not aggregate([]).evidence_index


class CloudFixture:
    def resolve(self, raw):
        return CloudResolution(
            raw.raw_name,
            raw.location.source_type,
            (ComponentSpec("AES256", Usage.ENCRYPTION, "cipher"),),
            True,
            "local-fixture",
        )


def listener(kb, refs, resource="listener:1"):
    raw = finding(
        "fixture-policy",
        key_size=None,
        kind_hint=KindHint.POLICY,
        usage=Usage.UNKNOWN,
        location=Location(source_type=SourceType.LOADBALANCER, resource_id=resource),
        extra={"certificate_arns": refs, "public_exposure": True},
    )
    return classify(decompose(raw, kb, cloud_registry=CloudFixture()).root, kb)


def test_explicit_cloud_certificate_join_propagates_tier_not_scoring(kb):
    policy = listener(kb, ["certificate:1"])
    cert = classified(
        kb,
        finding(
            "RSA2048",
            id="cert",
            key_size=None,
            kind_hint=KindHint.CERTIFICATE,
            location=Location(source_type=SourceType.ACM, resource_id="certificate:1"),
        ),
    )
    unrelated = classified(
        kb,
        finding(
            "Ed25519",
            id="unrelated",
            key_size=None,
            kind_hint=KindHint.CERTIFICATE,
            location=Location(source_type=SourceType.ACM, resource_id="certificate:2"),
        ),
    )
    result = aggregate([policy, cert, unrelated])
    assert_graph(result)
    by_id = {a.asset_id: a for a in result.assets}
    parent = next(a for a in result.assets if a.canonical_name == "fixture-policy")
    assert parent.tier == Tier.CRITICAL
    assert any("cert" in by_id[child].finding_ids for child in parent.components)
    assert all("unrelated" not in by_id[child].finding_ids for child in parent.components)
    assert not any(row.scoreable for site in result.evidence_index[parent.asset_id] for row in site.records)
    assert result.issues == ()
    assert payload(aggregate([unrelated, cert, policy])) == payload(result)


def test_missing_certificate_is_unknown_without_guessed_key(kb):
    result = aggregate([listener(kb, ["missing"])])
    policy = next(a for a in result.assets if a.canonical_name == "fixture-policy")
    assert policy.tier == Tier.UNKNOWN
    assert len(result.issues) == 1
    assert not any(a.usage == Usage.AUTHENTICATION for a in result.assets)


def test_safe_and_unknown_alias_facts_remain_conservative(kb):
    rows = [
        classified(kb, finding(name, id=name, key_size=None, usage=Usage.KEY_EXCHANGE))
        for name in ("ML-KEM-768", "Kyber768")
    ]
    result = aggregate(rows)
    assert len(result.assets) == 1
    asset = result.assets[0]
    assert asset.tier == Tier.SAFE and asset.deprecated_pqc_draft
    assert asset.pqc_standard is None and asset.oid is None and asset.nist_quantum_level is None


def test_same_site_metadata_variants_are_retained_even_with_same_finding_id(kb):
    raw = finding(key_size=None, confidence=0.9, extra={"custom": [1], "key_size_source": "unresolved"})
    other = raw.model_copy(deep=True)
    other.extra["custom"] = [2]
    result = aggregate([classified(kb, raw), classified(kb, other)])
    asset = result.assets[0]
    sites = result.evidence_index[asset.asset_id]
    assert len(sites) == 1 and len(sites[0].records) == 2
    assert all(row.confidence == 0.5 for row in sites[0].records)
    assert all(row.node.normalized.finding.confidence == 0.9 for row in sites[0].records)
    assert asset.key_size is None and asset.tier == Tier.MEDIUM


def test_public_hndl_and_negotiated_union_is_not_floor_evidence(kb):
    # KEX code is negotiated but not observed in transit; the transit observation
    # is only an offer. No single retained row has both required floor flags.
    code = finding("X25519", key_size=None, usage=Usage.KEY_EXCHANGE, negotiated=True)
    offered = finding(
        "X25519",
        id="offered",
        key_size=None,
        usage=Usage.KEY_EXCHANGE,
        negotiated=False,
        location=Location(source_type=SourceType.PCAP, file="capture", flow="one"),
    )
    result = aggregate([classified(kb, code), classified(kb, offered)])
    asset = result.assets[0]
    assert asset.hndl_exposed and asset.negotiated
    assert not any(
        row.hndl_exposed and row.node.normalized.finding.negotiated is True
        for site in result.evidence_index[asset.asset_id]
        for row in site.records
    )


def test_flow_and_unlocated_packet_occurrences(kb):
    rows = [
        classified(
            kb, finding(id=str(i), location=Location(source_type=SourceType.PCAP, file="capture", frame=i))
        )
        for i in (1, 2)
    ]
    assert len(aggregate(rows).assets[0].occurrences) == 2
    flows = [
        classified(
            kb,
            finding(
                id=str(i), location=Location(source_type=SourceType.PCAP, file="capture", flow=flow, frame=i)
            ),
        )
        for i, flow in [(1, "one"), (2, "one"), (3, "two")]
    ]
    assert len(aggregate(flows).assets[0].occurrences) == 2


def test_session_containers_stay_separate_shared_atoms_remain_linked(kb):
    rows = [
        classified(
            kb,
            finding(
                "TLS_AES_256_GCM_SHA384",
                kind_hint=KindHint.CIPHER_SUITE,
                id=flow,
                key_size=None,
                usage=Usage.UNKNOWN,
                session_id=flow,
                location=Location(source_type=SourceType.PCAP, file="capture", flow=flow),
            ),
        )
        for flow in ("one", "two")
    ]
    result = aggregate(rows)
    protocols = [asset for asset in result.assets if asset.asset_type == "protocol"]
    assert len(protocols) == 2 and all(asset.tier == Tier.UNKNOWN for asset in protocols)
    cipher = next(asset for asset in result.assets if asset.canonical_name == "AES")
    assert cipher.tier == Tier.SAFE and len(cipher.component_of) == 2
    assert_graph(result)


def test_absent_explicit_reference_never_joins_by_equal_resource(kb):
    policy = listener(kb, [])
    cert = classified(
        kb,
        finding(
            "RSA2048",
            key_size=None,
            kind_hint=KindHint.CERTIFICATE,
            location=Location(source_type=SourceType.ACM, resource_id="listener:1"),
        ),
    )
    result = aggregate([policy, cert])
    parent = next(asset for asset in result.assets if asset.canonical_name == "fixture-policy")
    assert parent.tier == Tier.SAFE
    assert all(
        next(a for a in result.assets if a.asset_id == child).canonical_name != "RSA"
        for child in parent.components
    )


def test_missing_reference_does_not_override_critical_certificate(kb):
    cert = classified(
        kb,
        finding(
            "RSA2048",
            key_size=None,
            kind_hint=KindHint.CERTIFICATE,
            location=Location(source_type=SourceType.ACM, resource_id="cert"),
            extra={"origin": "IMPORTED"},
        ),
    )
    result = aggregate([listener(kb, ["cert", "missing"]), cert])
    parent = next(asset for asset in result.assets if asset.canonical_name == "fixture-policy")
    assert parent.tier == Tier.CRITICAL and result.issues
    assert "Certificate was imported" in parent.rationale
    assert any("renewal" in item.action for item in parent.recommendations)
    assert "Overall CRITICAL" in parent.rationale


@pytest.mark.parametrize(
    "name,kind,usage,extra",
    [
        ("HTTP", KindHint.PLAINTEXT, Usage.UNKNOWN, {"hygiene_only": True}),
        ("math/rand", KindHint.ALGORITHM, Usage.RNG, {"hygiene_only": True}),
        ("cryptography", KindHint.LIBRARY, Usage.UNKNOWN, {}),
        ("hard-coded symmetric key", KindHint.KEY, Usage.ENCRYPTION, {"hygiene_only": True}),
    ],
)
def test_warning_records_remain_visible_unscored(kb, name, kind, usage, extra):
    result = aggregate(
        [classified(kb, finding(name, kind_hint=kind, usage=usage, extra=extra, key_size=None))]
    )
    assert result.assets
    assert all(
        not row.scoreable and row.exclusions
        for sites in result.evidence_index.values()
        for site in sites
        for row in site.records
    )
