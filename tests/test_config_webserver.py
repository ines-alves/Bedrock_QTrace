"""TLS and SSH settings in server configuration files (config/webserver.py)."""

from __future__ import annotations

from pathlib import Path

import pytest

from quantumtrace import pipeline
from quantumtrace.models import Finding, KindHint, SourceType, Tier, Usage
from quantumtrace.scanners.config.webserver import WebServerConfigScanner

SCANNER = WebServerConfigScanner()


def scan(tmp_path: Path, name: str, text: str) -> list[Finding]:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    assert SCANNER.can_handle(path)
    found = [f for f in SCANNER.scan(path, tmp_path) if isinstance(f, Finding)]
    assert all(f.location.source_type == SourceType.CONFIG for f in found)
    return found


def rows(findings):
    return sorted((f.location.line, f.kind_hint, f.raw_name, f.extra.get("codepoint")) for f in findings)


NGINX = """http {
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;   # legacy kept for old clients
    ssl_ciphers 'ECDHE-RSA-AES256-GCM-SHA384:DES-CBC3-SHA:RC4-SHA:HIGH:!aNULL';
    ssl_ecdh_curve X25519:prime256v1;
    ssl_conf_command Groups X25519MLKEM768;
    proxy_ssl_protocols TLSv1.3;
    server {
        ssl_ciphers
            "EDH-RSA-DES-CBC3-SHA";
    }
}
"""


def test_nginx_versions_suites_groups_and_multiline_statement(tmp_path):
    got = rows(scan(tmp_path, "nginx.conf", NGINX))
    pv, cs, gr, po = KindHint.PROTOCOL_VERSION, KindHint.CIPHER_SUITE, KindHint.GROUP, KindHint.POLICY
    assert got == sorted(
        [
            (2, pv, "TLS 1.0", None),
            (2, pv, "TLS 1.1", None),
            (2, pv, "TLS 1.2", None),
            (3, cs, "ECDHE-RSA-AES256-GCM-SHA384", "0xC030"),
            (3, cs, "DES-CBC3-SHA", "0x000A"),
            (3, cs, "RC4-SHA", "0x0005"),
            (3, po, "ECDHE-RSA-AES256-GCM-SHA384:DES-CBC3-SHA:RC4-SHA:HIGH:!aNULL", None),
            (4, gr, "X25519", "0x001D"),
            (4, gr, "prime256v1", "0x0017"),
            (5, gr, "X25519MLKEM768", "0x11EC"),
            (6, pv, "TLS 1.3", None),
            (8, cs, "EDH-RSA-DES-CBC3-SHA", "0x0016"),
        ]
    )


def test_apache_protocol_set_semantics_and_tls13_suite_list(tmp_path):
    text = (
        "SSLProtocol all -SSLv3\n"
        "SSLProxyProtocol +TLSv1.2\n"
        "SSLCipherSuite TLSv1.3 TLS_AES_256_GCM_SHA384\n"
        "SSLOpenSSLConfCmd Curves secp521r1\n"
        "SSLProtocol all\n"
    )
    found = scan(tmp_path, "ssl.conf", text)
    by_line: dict[int, list[str]] = {}
    for f in found:
        by_line.setdefault(f.location.line, []).append(f.raw_name)
    assert sorted(by_line[1]) == ["TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"]
    assert (
        by_line[2] == ["TLS 1.2"] and by_line[3] == ["TLS_AES_256_GCM_SHA384"] and by_line[4] == ["secp521r1"]
    )
    sslv3 = [f for f in found if f.location.line == 5 and f.raw_name == "SSLv3"]
    assert sslv3 and sslv3[0].extra["build_dependent"] is True  # "all" includes SSLv3 only if OpenSSL has it


def test_haproxy_global_options_and_bind_keywords(tmp_path):
    text = (
        "global\n"
        "    ssl-default-bind-ciphers AES256-SHA\n"
        "    ssl-default-bind-options ssl-min-ver TLSv1.1 no-tls-tickets\n"
        "frontend fe\n"
        "    bind :443 ssl crt /etc/site.pem ciphers ECDHE-ECDSA-AES256-GCM-SHA384 curves P-256 force-tlsv12\n"
    )
    got = [(f.location.line, f.raw_name) for f in scan(tmp_path, "haproxy.cfg", text)]
    assert sorted(got) == [
        (2, "AES256-SHA"),
        (3, "TLS 1.1"),
        (3, "TLS 1.2"),
        (3, "TLS 1.3"),
        (5, "ECDHE-ECDSA-AES256-GCM-SHA384"),
        (5, "P-256"),
        (5, "TLS 1.2"),
    ]


def test_openssl_cnf_min_protocol_keywords_and_openssl_signature_forms(tmp_path):
    text = (
        "MinProtocol = TLSv1.2\n"
        "CipherString = DEFAULT@SECLEVEL=1\n"
        "SignatureAlgorithms = RSA+SHA1:ECDSA+SHA384:rsa_pss_rsae_sha256\n"
    )
    found = scan(tmp_path, "openssl.cnf", text)
    assert [f.raw_name for f in found if f.location.line == 1] == ["TLS 1.2", "TLS 1.3"]
    (policy,) = [f for f in found if f.location.line == 2]
    assert policy.kind_hint == KindHint.POLICY and policy.extra["keywords"] == ["DEFAULT@SECLEVEL=1"]
    sigs = {f.raw_name: f.extra.get("codepoint") for f in found if f.kind_hint == KindHint.SIGNATURE_SCHEME}
    assert sigs == {"RSA+SHA1": "0x0201", "ECDSA+SHA384": "0x0503", "rsa_pss_rsae_sha256": "0x0804"}


def test_java_security_reports_legacy_protocols_that_are_not_disabled(tmp_path):
    text = "jdk.tls.disabledAlgorithms=SSLv3, RC4, DES, \\\n    DH keySize < 1024, TLSv1.1\n"
    found = scan(tmp_path, "java.security", text)
    assert [(f.location.line, f.raw_name, f.extra["not_disabled"]) for f in found] == [(1, "TLS 1.0", True)]


def test_sshd_config_lists_modifiers_and_removals(tmp_path):
    text = (
        "HostKey /etc/ssh/ssh_host_ed25519_key\n"
        "KexAlgorithms sntrup761x25519-sha512@openssh.com,diffie-hellman-group1-sha1\n"
        "Ciphers aes256-gcm@openssh.com,3des-cbc\n"
        "MACs umac-128-etm@openssh.com\n"
        "HostKeyAlgorithms +ssh-dss\n"
        "PubkeyAcceptedAlgorithms -ssh-rsa\n"
    )
    found = scan(tmp_path, "sshd_config", text)
    got = sorted((f.location.line, f.raw_name, f.usage, f.extra.get("modifier")) for f in found)
    assert got == [
        (2, "diffie-hellman-group1-sha1", Usage.KEY_EXCHANGE, None),
        (2, "sntrup761x25519-sha512@openssh.com", Usage.KEY_EXCHANGE, None),
        (3, "3des-cbc", Usage.ENCRYPTION, None),
        (3, "aes256-gcm@openssh.com", Usage.ENCRYPTION, None),
        (4, "umac-128-etm@openssh.com", Usage.MAC, None),
        (5, "ssh-dss", Usage.SIGNATURE, "+"),
    ]
    assert all(f.protocol == "ssh" and f.kind_hint == KindHint.ALGORITHM for f in found)


def test_spring_properties_and_yaml_never_show_other_lines(tmp_path):
    props = scan(
        tmp_path,
        "application.properties",
        "server.ssl.key-store-password=supersecret\nserver.ssl.enabled-protocols=TLSv1.2,TLSv1.3\n"
        "server.ssl.ciphers=TLS_RSA_WITH_AES_128_CBC_SHA\n",
    )
    assert sorted(f.raw_name for f in props) == ["TLS 1.2", "TLS 1.3", "TLS_RSA_WITH_AES_128_CBC_SHA"]
    assert all("supersecret" not in (f.location.snippet or "") for f in props)
    yml = scan(
        tmp_path,
        "app/application.yml",
        "server:\n  ssl:\n    enabled-protocols:\n      - TLSv1.1\n    ciphers: ECDHE-RSA-AES256-GCM-SHA384\n",
    )
    assert sorted((f.location.line, f.raw_name) for f in yml) == [
        (3, "TLS 1.1"),
        (5, "ECDHE-RSA-AES256-GCM-SHA384"),
    ]


def test_tomcat_ssl_host_config(tmp_path):
    text = (
        '<Server><Connector port="8443" SSLEnabled="true">\n'
        '  <SSLHostConfig protocols="TLSv1.2+TLSv1.3" ciphers="TLS_RSA_WITH_3DES_EDE_CBC_SHA"/>\n'
        '</Connector><Connector port="8080"/></Server>\n'
    )
    got = sorted((f.location.line, f.raw_name) for f in scan(tmp_path, "server.xml", text))
    assert got == [(2, "TLS 1.2"), (2, "TLS 1.3"), (2, "TLS_RSA_WITH_3DES_EDE_CBC_SHA")]


@pytest.mark.parametrize(
    "name,text,claimed",
    [
        ("site.conf", "server { ssl_protocols TLSv1.2; }\n", True),
        ("other.conf", "worker_processes 4;\n", False),
        ("server.xml", "<Server><Connector port='80'/></Server>\n", False),
        ("application.properties", "server.port=80\n", False),
    ],
)
def test_generic_names_are_claimed_only_with_tls_settings(tmp_path, name, text, claimed):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    assert SCANNER.can_handle(path) is claimed


def test_engine_classifies_config_findings(tmp_path):
    (tmp_path / "nginx.conf").write_text(NGINX, encoding="utf-8")
    (tmp_path / "sshd_config").write_text("Ciphers 3des-cbc\nMACs umac-64@openssh.com\n", encoding="utf-8")
    result = pipeline.run([tmp_path])
    tiers = {a.canonical_name: a.tier for a in result.assets}
    assert (
        tiers["TLS_RSA_WITH_3DES_EDE_CBC_SHA"] == Tier.CRITICAL
    )  # legacy name resolved through its codepoint
    assert tiers["TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"] == Tier.CRITICAL
    assert tiers["UMAC"] == Tier.MEDIUM and tiers["3DES"] == Tier.MEDIUM
    legacy = [a for a in result.assets if a.canonical_name == "TLS 1.0"]
    assert legacy and legacy[0].classically_broken
    assert not result.errors


@pytest.mark.parametrize(
    "name,usage,expected",
    [
        ("diffie-hellman-group-exchange-sha256", Usage.KEY_EXCHANGE, "DH"),
        ("diffie-hellman-group-exchange-sha1", Usage.KEY_EXCHANGE, "DH"),
        ("diffie-hellman-group14-sha256", Usage.KEY_EXCHANGE, "DH"),
        ("diffie-hellman-group18-sha512", Usage.KEY_EXCHANGE, "DH"),
        ("blowfish-cbc", Usage.ENCRYPTION, "Blowfish"),
        ("arcfour256", Usage.ENCRYPTION, "RC4"),
        ("cast128-cbc", Usage.ENCRYPTION, "CAST5"),
        ("umac-64-etm@openssh.com", Usage.MAC, "UMAC"),
        ("umac-128@openssh.com", Usage.MAC, "UMAC"),
        ("hmac-sha1-etm@openssh.com", Usage.MAC, "HMAC-SHA1"),
        ("hmac-md5-etm@openssh.com", Usage.MAC, "HMAC-MD5"),
        ("hmac-sha1-96", Usage.MAC, "HMAC-SHA1"),
        ("ssh-ed25519-cert-v01@openssh.com", Usage.SIGNATURE, "Ed25519"),
        ("sk-ssh-ed25519@openssh.com", Usage.SIGNATURE, "Ed25519"),
        ("ecdsa-sha2-nistp384", Usage.SIGNATURE, "ECDSA"),
        ("sk-ecdsa-sha2-nistp256@openssh.com", Usage.SIGNATURE, "ECDSA"),
        ("ssh-dss", Usage.SIGNATURE, "DSA"),
        ("ssh-rsa-cert-v01@openssh.com", Usage.SIGNATURE, "RSA"),
        ("rsa-sha2-512-cert-v01@openssh.com", Usage.SIGNATURE, "RSA"),
    ],
)
def test_openssh_algorithm_names_resolve_in_the_kb(tmp_path, name, usage, expected):
    directive = {Usage.KEY_EXCHANGE: "KexAlgorithms", Usage.ENCRYPTION: "Ciphers", Usage.MAC: "MACs"}
    (tmp_path / "sshd_config").write_text(f"{directive.get(usage, 'HostKeyAlgorithms')} {name}\n")
    result = pipeline.run([tmp_path])
    names = {a.canonical_name: a.tier for a in result.assets if a.asset_type != "protocol"}
    assert expected in names and Tier.UNKNOWN not in names.values()
