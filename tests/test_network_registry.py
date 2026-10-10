"""TLS registry: committed YAML facts, helpers, and generator behaviour. Never runs openssl."""

from __future__ import annotations

import re

import pytest

from quantumtrace.scanners.network import gen_registry, purepy, registry

TIER_WORDS = {"tier", "threat", "verdict", "pq_status", "verdict_tier", "score", "risk", "safe", "critical"}
TIER_VALUES = {"CRITICAL", "MEDIUM", "SAFE", "UNKNOWN"}


@pytest.fixture(scope="module")
def reg():
    return registry.load_registry()


def walk(node):
    if isinstance(node, dict):
        for key, value in node.items():
            yield key, value
            yield from walk(value)
    elif isinstance(node, list):
        for item in node:
            yield None, item
            yield from walk(item)


# --- structure ---------------------------------------------------------------------------


def test_top_level_keys_and_hex_string_keys(reg):
    assert list(reg) == ["meta", "cipher_suites", "groups", "signature_schemes", "versions"]
    for ns in ("cipher_suites", "groups", "signature_schemes", "versions"):
        assert reg[ns], ns
        for key in reg[ns]:
            assert isinstance(key, str) and re.fullmatch(r"0x[0-9A-F]{4}", key), (ns, key)


def test_entries_have_iana_string_and_openssl_list(reg):
    for ns in ("cipher_suites", "groups"):
        for key, entry in reg[ns].items():
            assert isinstance(entry["openssl"], list), (ns, key)
            assert all(isinstance(name, str) for name in entry["openssl"])
            assert entry["iana"] is None or isinstance(entry["iana"], str)
    for key, entry in reg["signature_schemes"].items():
        assert isinstance(entry["iana"], str), key


def test_no_tier_anywhere(reg):
    for key, value in walk(reg):
        if isinstance(key, str):
            assert key.lower() not in TIER_WORDS, key
        if isinstance(value, str):
            assert value not in TIER_VALUES, (key, value)


def test_meta_records_sources_without_timestamp(reg):
    meta = reg["meta"]
    assert {s["namespace"] for s in meta["iana_sources"]} == {"cipher_suites", "groups", "signature_schemes"}
    for source in meta["iana_sources"]:
        assert source["url"].startswith("https://www.iana.org/assignments/tls-parameters/")
        assert re.fullmatch(r"[0-9a-f]{64}", source["sha256"])
    assert "generated_at" not in meta  # regeneration must be byte-identical
    assert meta["unresolved_openssl_groups"] == []


# --- GREASE and signalling ---------------------------------------------------------------


@pytest.mark.parametrize("value", [(b << 8) | b for b in range(0x0A, 0x100, 0x10)])
def test_all_sixteen_grease_values(value):
    assert registry.is_grease(value)


@pytest.mark.parametrize("value", [0x0000, 0x0A0B, 0x0A1A, 0x1301, 0x11EC, 0xFAFB, 0xFFFF])
def test_non_grease_values(value):
    assert not registry.is_grease(value)


def test_purepy_uses_registry_helpers():
    assert purepy.is_grease is registry.is_grease
    assert purepy.SIGNALLING_SUITES == registry.SIGNALLING_SUITES == {0x00FF, 0x5600}


def test_signalling_suites_flagged_and_nothing_else(reg):
    flagged = {k for k, v in reg["cipher_suites"].items() if v.get("signalling")}
    assert flagged == {"0x00FF", "0x5600"}


def test_grease_codepoints_are_not_registered(reg):
    greases = {registry.format_code((b << 8) | b) for b in range(0x0A, 0x100, 0x10)}
    for ns in ("cipher_suites", "groups", "signature_schemes"):
        assert greases.isdisjoint(reg[ns]), ns


# --- PLAN 7.4 codepoints and the 0x0201 collision ----------------------------------------


def test_plan_group_codepoints(reg):
    expected = {
        "0x0017": "secp256r1",
        "0x0018": "secp384r1",
        "0x0019": "secp521r1",
        "0x001D": "x25519",
        "0x001E": "x448",
        "0x0100": "ffdhe2048",
        "0x0104": "ffdhe8192",
        "0x0200": "MLKEM512",
        "0x0201": "MLKEM768",
        "0x0202": "MLKEM1024",
        "0x11EB": "SecP256r1MLKEM768",
        "0x11EC": "X25519MLKEM768",
        "0x11ED": "SecP384r1MLKEM1024",
        "0x6399": "X25519Kyber768Draft00",
        "0x639A": "SecP256r1Kyber768Draft00",
    }
    for code, name in expected.items():
        assert reg["groups"][code]["iana"] == name, code


def test_plan_signature_scheme_codepoints(reg):
    expected = {
        "0x0201": "rsa_pkcs1_sha1",
        "0x0203": "ecdsa_sha1",
        "0x0401": "rsa_pkcs1_sha256",
        "0x0501": "rsa_pkcs1_sha384",
        "0x0601": "rsa_pkcs1_sha512",
        "0x0403": "ecdsa_secp256r1_sha256",
        "0x0503": "ecdsa_secp384r1_sha384",
        "0x0603": "ecdsa_secp521r1_sha512",
        "0x0804": "rsa_pss_rsae_sha256",
        "0x0809": "rsa_pss_pss_sha256",
        "0x0807": "ed25519",
        "0x0808": "ed448",
        "0x0904": "mldsa44",
        "0x0905": "mldsa65",
        "0x0906": "mldsa87",
    }
    for code, name in expected.items():
        assert reg["signature_schemes"][code]["iana"] == name, code


def test_plan_cipher_suite_codepoints(reg):
    expected = {
        "0x1301": "TLS_AES_128_GCM_SHA256",
        "0x1302": "TLS_AES_256_GCM_SHA384",
        "0x1303": "TLS_CHACHA20_POLY1305_SHA256",
        "0x1304": "TLS_AES_128_CCM_SHA256",
        "0x1305": "TLS_AES_128_CCM_8_SHA256",
        "0xC02F": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "0xC030": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "0xC02B": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "0xC02C": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "0xCCA8": "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        "0xCCA9": "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        "0x009C": "TLS_RSA_WITH_AES_128_GCM_SHA256",
        "0x009D": "TLS_RSA_WITH_AES_256_GCM_SHA384",
        "0x002F": "TLS_RSA_WITH_AES_128_CBC_SHA",
        "0x0035": "TLS_RSA_WITH_AES_256_CBC_SHA",
        "0x000A": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        "0x0005": "TLS_RSA_WITH_RC4_128_SHA",
        "0x009E": "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
        "0x009F": "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    }
    for code, name in expected.items():
        assert reg["cipher_suites"][code]["iana"] == name, code


def test_0x0201_collision_is_resolved_by_namespace(reg):
    assert registry.iana_name("groups", 0x0201) == "MLKEM768"
    assert registry.iana_name("signature_schemes", 0x0201) == "rsa_pkcs1_sha1"
    assert registry.iana_name("cipher_suites", 0x0201) != "MLKEM768"
    assert registry.lookup("groups", "0x0201")["pqc"] is True
    assert "pqc" not in registry.lookup("signature_schemes", "0x0201")


def test_pqc_facts(reg):
    groups = reg["groups"]
    assert groups["0x11EC"]["hybrid"] is True and groups["0x11EC"]["components"] == ["x25519", "MLKEM768"]
    assert groups["0x0201"]["pqc"] is True and groups["0x0201"]["hybrid"] is False
    assert groups["0x6399"]["deprecated_draft"] is True and groups["0x639A"]["deprecated_draft"] is True
    assert "deprecated_draft" not in groups["0x11EC"]
    assert "pqc" not in groups["0x001D"]  # x25519 is classical
    assert reg["signature_schemes"]["0x0904"]["draft"] is True
    for code in ("0x0200", "0x0201", "0x0202"):  # IANA reference is still an IETF draft
        assert groups[code]["draft"] is True, code
    assert "draft" not in groups["0x11EC"]  # final reference
    assert "draft" not in groups["0x6399"]  # deprecated_draft covers it


def test_every_hybrid_component_is_a_registered_group_name(reg):
    names = {entry["iana"] for entry in reg["groups"].values()}
    for code, entry in reg["groups"].items():
        for component in entry.get("components", []):
            assert component in names, (code, component)
    assert "components" not in reg["groups"]["0x6399"]  # not inferred from a draft name


def test_mldsa_codepoints_keep_the_plan_verify_marker(reg):
    for code in ("0x0904", "0x0905", "0x0906"):
        assert reg["signature_schemes"][code]["verify"], code


def test_version_labels(reg):
    assert {k: v["label"] for k, v in reg["versions"].items()} == {
        "0x0300": "SSL 3.0",
        "0x0301": "TLS 1.0",
        "0x0302": "TLS 1.1",
        "0x0303": "TLS 1.2",
        "0x0304": "TLS 1.3",
    }
    assert registry.version_label(0x0304) == "TLS 1.3"
    assert registry.version_label(0x1234) is None


# --- OpenSSL aliases ---------------------------------------------------------------------


def test_cipher_aliases(reg):
    assert reg["cipher_suites"]["0xC02F"]["openssl"] == ["ECDHE-RSA-AES128-GCM-SHA256"]
    assert reg["cipher_suites"]["0x002F"]["openssl"] == ["AES128-SHA"]
    assert reg["cipher_suites"]["0x1301"]["openssl"] == ["TLS_AES_128_GCM_SHA256"]


def test_group_aliases_including_prime256v1(reg):
    p256 = reg["groups"]["0x0017"]
    assert p256["openssl"] == ["secp256r1", "P-256", "prime256v1"]
    assert reg["groups"]["0x0018"]["openssl"] == ["secp384r1", "P-384"]
    assert reg["groups"]["0x0019"]["openssl"] == ["secp521r1", "P-521"]
    assert reg["groups"]["0x11EC"]["openssl"] == ["X25519MLKEM768"]
    assert reg["groups"]["0x001D"]["openssl"] == ["x25519"]


def test_prime256v1_is_marked_verify(reg):
    verify = reg["groups"]["0x0017"]["verify"]
    assert any("prime256v1" in item for item in verify)
    for code, entry in reg["groups"].items():
        if code != "0x0017":
            assert "verify" not in entry, code  # only the ecparam pairing is unconfirmed


def test_openssl_only_suites_carry_verify(reg):
    for code, entry in reg["cipher_suites"].items():
        if entry["iana"] is None:
            assert entry["verify"], code


# --- helpers -----------------------------------------------------------------------------


def test_load_registry_returns_private_copy():
    first = registry.load_registry()
    first["groups"].clear()
    assert registry.load_registry()["groups"]


def test_lookup_variants():
    assert registry.lookup("groups", "0x11ec")["iana"] == "X25519MLKEM768"
    assert registry.lookup("groups", 0x11EC)["iana"] == "X25519MLKEM768"
    assert registry.lookup("groups", 0xBEEF) is None
    assert registry.iana_name("cipher_suites", 0xBEEF) is None
    with pytest.raises(ValueError):
        registry.lookup("versions", 0x0303)


# --- generator ---------------------------------------------------------------------------


def test_regeneration_is_byte_identical_to_committed_yaml():
    texts, digests, openssl = gen_registry.load_inputs()
    text = gen_registry.dump_registry(gen_registry.build_registry(texts, digests, openssl))
    assert text == gen_registry.OUTPUT.read_text(encoding="utf-8")
    assert gen_registry.main(["--check"]) == 0


def test_override_name_disagreement_stops_generation():
    texts, digests, openssl = gen_registry.load_inputs()
    texts = {**texts, "groups": texts["groups"].replace(",X25519MLKEM768,", ",X25519MLKEM768x,")}
    with pytest.raises(gen_registry.RegistryError, match="0x11EC"):
        gen_registry.build_registry(texts, digests, openssl)


def test_empty_csv_stops_generation():
    texts, digests, openssl = gen_registry.load_inputs()
    with pytest.raises(gen_registry.RegistryError):
        gen_registry.build_registry({**texts, "signature_schemes": "Value,Description\n"}, digests, openssl)


def test_parse_iana_cipher_suites_skips_ranges_and_reserved():
    text = (
        "Value,Description,DTLS-OK,Recommended,Reference,Comment\n"
        '"0x13,0x01",TLS_AES_128_GCM_SHA256,Y,Y,[RFC8446],\n'
        '"0x00,0x1C-1D",Reserved to avoid conflicts with SSLv3,,,[RFC5246],\n'
        '"0x0A,0x0A",Reserved,Y,N,[RFC8701],\n'
        '"0x00,0xFF",TLS_EMPTY_RENEGOTIATION_INFO_SCSV,Y,N,[RFC5746],\n'
    )
    parsed = gen_registry.parse_iana_cipher_suites(text)
    assert set(parsed) == {0x1301, 0x00FF}
    assert parsed[0x1301] == {"iana": "TLS_AES_128_GCM_SHA256", "ref": "[RFC8446]"}


def test_parse_iana_groups_marks_obsolete():
    text = (
        "Value,Description,DTLS-OK,Recommended,Reference,Comment\n"
        "0,Reserved,,,[RFC8447],\n"
        "42-255,Unassigned,,,,\n"
        "25497,X25519Kyber768Draft00 (OBSOLETE),N,D,[RFC10024],\n"
    )
    assert gen_registry.parse_iana_groups(text) == {
        0x6399: {"iana": "X25519Kyber768Draft00", "obsolete": True, "ref": "[RFC10024]"}
    }


def test_parse_openssl_inputs():
    ciphers = (
        "          0xC0,0x2F - ECDHE-RSA-AES128-GCM-SHA256    TLSv1.2 Kx=ECDH     Au=RSA\n"
        "          0xC0,0x2F - ECDHE-RSA-AES128-GCM-SHA256    TLSv1.2 duplicate\n"
        "garbage line\n"
    )
    assert gen_registry.parse_openssl_ciphers(ciphers) == {0xC02F: ["ECDHE-RSA-AES128-GCM-SHA256"]}
    assert gen_registry.parse_openssl_groups("secp256r1:P-256:x25519\n") == ["secp256r1", "P-256", "x25519"]
    assert gen_registry.parse_ecparam_oid("ASN1 OID: prime256v1\nNIST CURVE: P-256\n") == "prime256v1"
    assert gen_registry.parse_ecparam_oid("no curve here") is None


def test_ambiguous_curve_alias_stays_unresolved():
    iana = {1: {"iana": "curveA"}, 2: {"iana": "curveB"}}
    curves = {"curveA": "same", "curveB": "same", "Alias": "same", "Other": None}
    aliases, oid_aliases, unresolved = gen_registry._resolve_groups(
        iana, ["curveA", "curveB", "Alias", "Other"], curves
    )
    assert unresolved == ["Alias", "Other"]
    assert aliases == {1: ["curveA"], 2: ["curveB"]}
    assert oid_aliases == {}
