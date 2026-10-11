"""TLS and SSH settings in server configuration files (PLAN 3.13, M3D-12, M1M3-09, M2M3-03).

Detect-only: each finding is one configured name with its line, never a tier. Dialects:

- nginx: ssl_protocols, ssl_ciphers, ssl_ecdh_curve, ssl_conf_command, and the proxy_/grpc_/uwsgi_
  variants.
- Apache httpd: SSLProtocol and SSLProxyProtocol (set semantics: all, +X, -X), SSLCipherSuite and
  SSLProxyCipherSuite (an optional leading protocol: SSL or TLSv1.3), SSLOpenSSLConfCmd.
- HAProxy: ssl-default-{bind,server}-{ciphers,ciphersuites,curves,options} and bind/server line
  keywords (ciphers, ciphersuites, curves, ssl-min-ver, ssl-max-ver).
- OpenSSL configuration (openssl.cnf): MinProtocol, MaxProtocol, Protocol, CipherString, Ciphersuites,
  Groups, Curves, SignatureAlgorithms.
- java.security: legacy protocols (SSLv3, TLSv1, TLSv1.1) missing from jdk.tls.disabledAlgorithms are
  reported as enabled.
- OpenSSH sshd_config / ssh_config: KexAlgorithms, Ciphers, MACs, HostKeyAlgorithms,
  PubkeyAcceptedAlgorithms (and the older *KeyTypes spellings), HostbasedAcceptedAlgorithms,
  CASignatureAlgorithms. A "-" list removes algorithms and is not reported; "+" and "^" lists are.
- Spring Boot: server.ssl.enabled-protocols and server.ssl.ciphers (properties or YAML).
- Tomcat server.xml: sslEnabledProtocols, protocols and ciphers on SSL connectors and SSLHostConfig.

Finding shapes (source_type config, detector config.webserver, M1M3-09):
- a protocol version: kind protocol_version, raw_name "SSLv2", "SSLv3", "TLS 1.0" ... "TLS 1.3".
- a TLS cipher suite: kind cipher_suite, raw_name as written; extra.codepoint and extra.iana_name come
  from kb/tls_registry.yaml (M2) through its OpenSSL or IANA name. A legacy OpenSSL name the registry
  does not list (DES-CBC3-SHA, RC4-SHA, ...) is mapped to its IANA name by the table below (OpenSSL
  manual), and the codepoint still comes from the registry.
- a TLS cipher string with selection keywords (HIGH:!aNULL, @SECLEVEL=2): one kind policy finding whose
  raw_name is the string as written (M2M3-03); named suites in it are also reported one by one.
- a TLS group: kind group, usage key_exchange, codepoint from the registry.
- a TLS signature scheme: kind signature_scheme, usage signature.
- an SSH algorithm: kind algorithm, protocol "ssh", usage from the directive.
Every finding has extra.setting (the directive) and extra.dialect.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from quantumtrace.models import Finding, KindHint, Location, ScanError, SourceType, Usage
from quantumtrace.scanners.base import finding_id, is_test_path, register
from quantumtrace.scanners.network.registry import load_registry

DETECTOR = "config.webserver"
MAX_FILE_BYTES = 5 * 1024 * 1024
SNIPPET_MAX = 200

NAMES = frozenset(
    {
        "nginx.conf",
        "httpd.conf",
        "apache2.conf",
        "ssl.conf",
        "haproxy.cfg",
        "openssl.cnf",
        "java.security",
        "sshd_config",
        "ssh_config",
    }
)
_SNIFF = re.compile(
    r"\b(?:ssl_protocols|ssl_ciphers|ssl_ecdh_curve|SSLProtocol|SSLCipherSuite|ssl-default-(?:bind|server)"
    r"|ssl-min-ver|MinProtocol|CipherString|Ciphersuites|KexAlgorithms|HostKeyAlgorithms)\b",
    re.IGNORECASE,
)
_CONFIG_DIRS = frozenset(
    {
        "sites-enabled",
        "sites-available",
        "conf.d",
        "vhosts.d",
        "mods-enabled",
        "mods-available",
        "conf-enabled",
    }
)
_SPRING_NAME = re.compile(r"application(?:-[\w.-]+)?\.(?:properties|ya?ml)")
_TOMCAT_SNIFF = re.compile(r"sslEnabledProtocols|SSLHostConfig|SSLEnabled\s*=", re.IGNORECASE)

_VERSIONS = {
    "sslv2": "SSLv2",
    "sslv3": "SSLv3",
    "tlsv1": "TLS 1.0",
    "tlsv1.0": "TLS 1.0",
    "tlsv10": "TLS 1.0",
    "tlsv1.1": "TLS 1.1",
    "tlsv11": "TLS 1.1",
    "tlsv1.2": "TLS 1.2",
    "tlsv12": "TLS 1.2",
    "tlsv1.3": "TLS 1.3",
    "tlsv13": "TLS 1.3",
}
_ORDER = ["SSLv2", "SSLv3", "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"]
# Apache: "all" is +SSLv3 +TLSv1 +TLSv1.1 +TLSv1.2 +TLSv1.3, SSLv3 only when OpenSSL was built with it
# (httpd.apache.org/docs/2.4/mod/mod_ssl.html#sslprotocol, checked 2026-10-11).
_ALL = ["SSLv3", "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"]

# OpenSSL names of legacy suites the registry does not list, mapped to their IANA names. Source: OpenSSL
# 1.1.1 ciphers(1), "CIPHER SUITE NAMES" (docs.openssl.org/1.1.1/man1/ciphers/), checked 2026-10-11.
# The codepoint is looked up from the IANA name in the registry; nothing here invents one.
_LEGACY_OPENSSL = {
    "RC4-MD5": "TLS_RSA_WITH_RC4_128_MD5",
    "RC4-SHA": "TLS_RSA_WITH_RC4_128_SHA",
    "IDEA-CBC-SHA": "TLS_RSA_WITH_IDEA_CBC_SHA",
    "DES-CBC-SHA": "TLS_RSA_WITH_DES_CBC_SHA",
    "DES-CBC3-SHA": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    "DHE-DSS-DES-CBC3-SHA": "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
    "DHE-RSA-DES-CBC3-SHA": "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
    "ECDHE-RSA-DES-CBC3-SHA": "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
    "ECDHE-ECDSA-DES-CBC3-SHA": "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
    "ECDHE-RSA-RC4-SHA": "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
    "ECDHE-ECDSA-RC4-SHA": "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
    "SEED-SHA": "TLS_RSA_WITH_SEED_CBC_SHA",
    "DHE-RSA-SEED-SHA": "TLS_DHE_RSA_WITH_SEED_CBC_SHA",
    "DHE-DSS-SEED-SHA": "TLS_DHE_DSS_WITH_SEED_CBC_SHA",
}

_SSH_USAGE = {
    "kexalgorithms": Usage.KEY_EXCHANGE,
    "ciphers": Usage.ENCRYPTION,
    "macs": Usage.MAC,
    "hostkeyalgorithms": Usage.SIGNATURE,
    "pubkeyacceptedalgorithms": Usage.SIGNATURE,
    "pubkeyacceptedkeytypes": Usage.SIGNATURE,
    "hostbasedacceptedalgorithms": Usage.SIGNATURE,
    "hostbasedkeytypes": Usage.SIGNATURE,
    "hostbasedacceptedkeytypes": Usage.SIGNATURE,
    "casignaturealgorithms": Usage.SIGNATURE,
}
_NGINX_PREFIXES = ("ssl_", "proxy_ssl_", "grpc_ssl_", "uwsgi_ssl_", "zone_sync_ssl_")


@lru_cache(maxsize=1)
def _names() -> dict[str, dict[str, tuple[str, str]]]:
    """Registry lookups: namespace -> upper-cased OpenSSL or IANA name -> (codepoint, IANA name)."""
    registry = load_registry()
    out: dict[str, dict[str, tuple[str, str]]] = {}
    for namespace in ("cipher_suites", "groups", "signature_schemes"):
        table: dict[str, tuple[str, str]] = {}
        for code, row in registry.get(namespace, {}).items():
            iana = row.get("iana")
            if not isinstance(iana, str):
                continue
            table.setdefault(iana.upper(), (code, iana))
            for alias in row.get("openssl") or []:
                table.setdefault(str(alias).upper(), (code, iana))
        out[namespace] = table
    return out


class _Out:
    def __init__(self, file: str) -> None:
        self.file = file
        self.findings: dict[str, Finding] = {}
        self.in_test = is_test_path(file)

    def add(
        self,
        raw: str,
        kind: KindHint,
        usage: Usage,
        line: int,
        snippet: str,
        setting: str,
        dialect: str,
        protocol: str | None = None,
        **extra: Any,
    ) -> None:
        location = Location(
            source_type=SourceType.CONFIG, file=self.file, line=line, snippet=snippet[:SNIPPET_MAX]
        )
        fid = finding_id(DETECTOR, raw, location)
        self.findings.setdefault(
            fid,
            Finding(
                id=fid,
                raw_name=raw,
                kind_hint=kind,
                usage=usage,
                protocol=protocol,
                detector=DETECTOR,
                in_test_code=self.in_test,
                location=location,
                extra={
                    "setting": setting,
                    "dialect": dialect,
                    **{k: v for k, v in extra.items() if v is not None},
                },
            ),
        )

    # ---- TLS value lists

    def versions(
        self, names: list[str], line: int, snippet: str, setting: str, dialect: str, **extra: Any
    ) -> None:
        for name in sorted(set(names), key=_ORDER.index):
            self.add(name, KindHint.PROTOCOL_VERSION, Usage.UNKNOWN, line, snippet, setting, dialect, **extra)

    def ciphers(self, value: str, line: int, snippet: str, setting: str, dialect: str) -> None:
        table = _names()["cipher_suites"]
        keywords: list[str] = []
        for token in re.split(r"[:,\s]+", value.strip().strip("'\"")):
            if not token:
                continue
            if token[0] in "!-+@" or "+" in token:
                keywords.append(token)
                continue
            key = token.upper()
            if key.startswith("EDH-"):
                key = "DHE-" + key[4:]
            hit = table.get(key) or table.get(_LEGACY_OPENSSL.get(key, "").upper())
            if hit:
                self.add(
                    token,
                    KindHint.CIPHER_SUITE,
                    Usage.UNKNOWN,
                    line,
                    snippet,
                    setting,
                    dialect,
                    codepoint=hit[0],
                    iana_name=hit[1],
                )
            elif "-" in token or key.startswith("TLS_") or key.startswith("SSL_"):
                self.add(token, KindHint.CIPHER_SUITE, Usage.UNKNOWN, line, snippet, setting, dialect)
            else:
                keywords.append(token)
        if keywords:
            self.add(
                value.strip().strip("'\""),
                KindHint.POLICY,
                Usage.UNKNOWN,
                line,
                snippet,
                setting,
                dialect,
                keywords=keywords,
            )

    def groups(self, value: str, line: int, snippet: str, setting: str, dialect: str) -> None:
        table = _names()["groups"]
        for token in re.split(r"[:,\s]+", value.strip().strip("'\"")):
            if not token or token.lower() == "auto" or token.startswith(("?", "*", "/", "-")):
                continue
            hit = table.get(token.upper())
            self.add(
                token,
                KindHint.GROUP,
                Usage.KEY_EXCHANGE,
                line,
                snippet,
                setting,
                dialect,
                codepoint=hit[0] if hit else None,
                iana_name=hit[1] if hit else None,
            )

    def sigalgs(self, value: str, line: int, snippet: str, setting: str, dialect: str) -> None:
        table = _names()["signature_schemes"]
        for token in re.split(r"[:,\s]+", value.strip().strip("'\"")):
            if not token:
                continue
            hit = table.get(token.upper()) or table.get(_openssl_sigalg(token).upper())
            self.add(
                token,
                KindHint.SIGNATURE_SCHEME,
                Usage.SIGNATURE,
                line,
                snippet,
                setting,
                dialect,
                codepoint=hit[0] if hit else None,
                iana_name=hit[1] if hit else None,
            )

    def openssl_command(
        self, name: str, value: str, line: int, snippet: str, setting: str, dialect: str
    ) -> None:
        """An OpenSSL SSL_CONF command (openssl.cnf, nginx ssl_conf_command, Apache SSLOpenSSLConfCmd)."""
        command = name.lower()
        if command in {"ciphersuites", "cipherstring"}:
            self.ciphers(value, line, snippet, setting, dialect)
        elif command in {"groups", "curves"}:
            self.groups(value, line, snippet, setting, dialect)
        elif command in {"signaturealgorithms", "clientsignaturealgorithms"}:
            self.sigalgs(value, line, snippet, setting, dialect)
        elif command == "minprotocol":
            self.versions(_range(value, None), line, snippet, setting, dialect, bound="minimum")
        elif command == "maxprotocol":
            pass  # a ceiling enables nothing by itself
        elif command == "protocol":
            self.versions(_set(re.split(r"[,\s]+", value)), line, snippet, setting, dialect)


def _openssl_sigalg(token: str) -> str:
    """IANA scheme name of an OpenSSL "algorithm+hash" signature algorithm (SSL_CONF_cmd
    SignatureAlgorithms), "" when the form is not one of these. ECDSA+SHA256 has the codepoint of
    ecdsa_secp256r1_sha256 (TLS 1.2 does not bind the curve; the codepoint is the same)."""
    match = re.fullmatch(r"(RSA|RSA-PSS|PSS|ECDSA)\+SHA(1|224|256|384|512)", token, re.I)
    if not match:
        return ""
    algorithm, bits = match[1].upper(), match[2]
    if algorithm == "RSA":
        return f"rsa_pkcs1_sha{bits}"
    if algorithm in {"RSA-PSS", "PSS"}:
        return f"rsa_pss_rsae_sha{bits}"
    curves = {"256": "secp256r1", "384": "secp384r1", "512": "secp521r1"}
    return f"ecdsa_{curves[bits]}_sha{bits}" if bits in curves else ("ecdsa_sha1" if bits == "1" else "")


def _version(token: str) -> str | None:
    return _VERSIONS.get(token.strip().strip("+-").lower())


def _range(low: str, high: str | None) -> list[str]:
    start = _version(low)
    stop = _version(high) if high else "TLS 1.3"
    if start is None or stop is None:
        return []
    return _ORDER[_ORDER.index(start) : _ORDER.index(stop) + 1]


def _set(tokens: list[str]) -> list[str]:
    enabled: list[str] = []
    for token in tokens:
        token = token.strip()
        if not token:
            continue
        if token.lower().lstrip("+-") == "all":
            names = _ALL
        else:
            name = _version(token)
            names = [name] if name else []
        if token.startswith("-"):
            enabled = [n for n in enabled if n not in names]
        else:
            enabled += [n for n in names if n not in enabled]
    return enabled


def _logical_lines(text: str) -> Iterator[tuple[int, str]]:
    """(first line number, statement) with backslash continuations and multi-line nginx statements joined."""
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        start = i + 1
        line = (
            re.sub(r"(?:^|\s)[#;].*$", "", lines[i]) if not lines[i].lstrip().startswith(("#", ";")) else ""
        )
        while line.rstrip().endswith("\\") and i + 1 < len(lines):
            i += 1
            line = line.rstrip()[:-1] + " " + lines[i].strip()
        if line.strip().lower().startswith(_NGINX_PREFIXES) and ";" not in line:
            while ";" not in line and i + 1 < len(lines):
                i += 1
                line += " " + re.sub(r"(?:^|\s)#.*$", "", lines[i]).strip()
        i += 1
        if line.strip():
            yield start, line.strip()


def _scan_text(out: _Out, text: str, name: str) -> None:
    ssh = name in {"sshd_config", "ssh_config"}
    for line, statement in _logical_lines(text):
        snippet = statement
        if ssh:
            match = re.match(r"(\w+)[\s=]+(\S+)", statement)
            if match and match[1].lower() in _SSH_USAGE:
                value = match[2]
                if value.startswith("-"):
                    continue  # removes algorithms from the defaults
                for algorithm in value.lstrip("+^").split(","):
                    if algorithm:
                        out.add(
                            algorithm,
                            KindHint.ALGORITHM,
                            _SSH_USAGE[match[1].lower()],
                            line,
                            snippet,
                            match[1],
                            "openssh",
                            protocol="ssh",
                            modifier=value[0] if value[0] in "+^" else None,
                        )
            continue
        # nginx
        match = re.match(r"((?:proxy_|grpc_|uwsgi_|zone_sync_)?ssl_(\w+))\s+(.*?);?$", statement)
        if match:
            directive, kind, value = match[1], match[2].lower(), match[3].rstrip(";").strip()
            if kind == "protocols":
                out.versions(
                    [v for t in value.split() if (v := _version(t))], line, snippet, directive, "nginx"
                )
            elif kind == "ciphers":
                out.ciphers(value, line, snippet, directive, "nginx")
            elif kind == "ecdh_curve":
                out.groups(value, line, snippet, directive, "nginx")
            elif kind == "conf_command":
                parts = value.split(None, 1)
                if len(parts) == 2:
                    out.openssl_command(parts[0], parts[1], line, snippet, directive, "nginx")
            continue
        # Apache httpd
        match = re.match(
            r"(SSL(?:Proxy)?Protocol|SSL(?:Proxy)?CipherSuite|SSLOpenSSLConfCmd)\s+(.*)$", statement, re.I
        )
        if match:
            directive, value = match[1], match[2].strip()
            if directive.lower().endswith("protocol"):
                versions = _set(value.split())
                build = "SSLv3" in versions and "all" in value.lower() and "+sslv3" not in value.lower()
                for version in versions:
                    out.versions(
                        [version],
                        line,
                        snippet,
                        directive,
                        "apache",
                        build_dependent=True if build and version == "SSLv3" else None,
                    )
            elif directive.lower().endswith("ciphersuite"):
                parts = value.split(None, 1)
                if len(parts) == 2 and parts[0].upper() in {"SSL", "TLSV1.3"}:
                    value = parts[1]
                out.ciphers(value, line, snippet, directive, "apache")
            else:
                parts = value.split(None, 1)
                if len(parts) == 2:
                    out.openssl_command(parts[0], parts[1], line, snippet, directive, "apache")
            continue
        # HAProxy global settings and bind/server keywords
        match = re.match(
            r"(ssl-default-(?:bind|server)-(ciphers|ciphersuites|curves|options))\s+(.*)$", statement
        )
        if match:
            directive, kind, value = match[1], match[2], match[3]
            if kind in {"ciphers", "ciphersuites"}:
                out.ciphers(value, line, snippet, directive, "haproxy")
            elif kind == "curves":
                out.groups(value, line, snippet, directive, "haproxy")
            else:
                _haproxy_options(out, value.split(), line, snippet, directive)
            continue
        if re.match(r"(?:bind|server|default-server)\s", statement):
            tokens = statement.split()
            for index, token in enumerate(tokens[:-1]):
                if token in {"ciphers", "ciphersuites"}:
                    out.ciphers(tokens[index + 1], line, snippet, f"{tokens[0]} {token}", "haproxy")
                elif token == "curves":
                    out.groups(tokens[index + 1], line, snippet, f"{tokens[0]} {token}", "haproxy")
            _haproxy_options(out, tokens, line, snippet, tokens[0])
            continue
        # OpenSSL configuration
        match = re.match(
            r"(MinProtocol|MaxProtocol|Protocol|CipherString|Ciphersuites|Groups|Curves|SignatureAlgorithms"
            r"|ClientSignatureAlgorithms)\s*=\s*(.+)$",
            statement,
            re.I,
        )
        if match:
            out.openssl_command(match[1], match[2], line, snippet, match[1], "openssl")
            continue
        # java.security
        match = re.match(r"jdk\.tls\.disabledAlgorithms\s*=\s*(.*)$", statement)
        if match:
            disabled = {t.strip().split()[0].lower() for t in match[1].split(",") if t.strip()}
            legacy = [
                n
                for t, n in (("sslv3", "SSLv3"), ("tlsv1", "TLS 1.0"), ("tlsv1.1", "TLS 1.1"))
                if t not in disabled
            ]
            out.versions(legacy, line, snippet, "jdk.tls.disabledAlgorithms", "java", not_disabled=True)
            continue
        # Spring Boot properties
        match = re.match(r"server\.ssl\.(enabled-protocols|ciphers)\s*[=:]\s*(.+)$", statement)
        if match:
            _spring(out, match[1], match[2], line, snippet)


def _haproxy_options(out: _Out, tokens: list[str], line: int, snippet: str, directive: str) -> None:
    low, high = None, None
    for index, token in enumerate(tokens[:-1]):
        if token == "ssl-min-ver":
            low = tokens[index + 1]
        elif token == "ssl-max-ver":
            high = tokens[index + 1]
    forced = [t for t in tokens if t.startswith("force-")]
    if forced:
        out.versions(
            [v for t in forced if (v := _version(t.removeprefix("force-")))],
            line,
            snippet,
            directive,
            "haproxy",
            bound="forced",
        )
    elif low:
        out.versions(_range(low, high), line, snippet, directive, "haproxy", bound="minimum")


def _spring(out: _Out, key: str, value: Any, line: int, snippet: str) -> None:
    items = value if isinstance(value, list) else re.split(r"[,\s]+", str(value).strip().strip("'\"[]"))
    items = [str(i).strip() for i in items if str(i).strip()]
    setting = f"server.ssl.{key}"
    if key == "enabled-protocols":
        out.versions([v for i in items if (v := _version(i))], line, snippet, setting, "spring")
    else:
        out.ciphers(",".join(items), line, snippet, setting, "spring")


def _spring_yaml(out: _Out, text: str) -> None:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError:
        return
    ssl = ((data or {}).get("server") or {}).get("ssl") if isinstance(data, dict) else None
    if not isinstance(ssl, dict):
        return
    lines = text.splitlines()
    for key in ("enabled-protocols", "ciphers"):
        if key in ssl:
            line = next((n for n, row in enumerate(lines, 1) if row.strip().startswith(f"{key}:")), 1)
            _spring(out, key, ssl[key], line, lines[line - 1].strip() if lines else key)


def _tomcat(out: _Out, text: str) -> None:
    for tag in re.finditer(r"<(Connector|SSLHostConfig)\b[^>]*>", text, re.S):
        body, line = tag[0], text.count("\n", 0, tag.start()) + 1
        if tag[1] == "Connector" and not re.search(r'SSLEnabled\s*=\s*"true"', body, re.I):
            continue
        snippet = re.sub(r"\s+", " ", body)
        for attribute in ("sslEnabledProtocols", "protocols"):
            found = re.search(rf'\b{attribute}\s*=\s*"([^"]*)"', body)
            if found:
                out.versions(
                    _set(re.split(r"[,+\s]+|(?=[+-])", found[1])), line, snippet, attribute, "tomcat"
                )
        found = re.search(r'\bciphers\s*=\s*"([^"]*)"', body)
        if found:
            out.ciphers(found[1], line, snippet, "ciphers", "tomcat")


def _read_head(path: Path) -> str:
    try:
        with path.open("rb") as handle:
            return handle.read(256 * 1024).decode("utf-8", "replace")
    except OSError:
        return ""


@register
class WebServerConfigScanner:
    name = "config.webserver"
    source_type = SourceType.CONFIG

    def can_handle(self, path: Path) -> bool:
        name = path.name.lower()
        if name in NAMES:
            return True
        if path.suffix.lower() in {".conf", ".cfg", ".cnf"}:
            return bool(_SNIFF.search(_read_head(path)))
        # Virtual hosts in server config directories often have no or other extensions
        # (sites-enabled/example.com): claim them only when they hold TLS settings.
        if path.parent.name.lower() in _CONFIG_DIRS:
            return bool(_SNIFF.search(_read_head(path)))
        if _SPRING_NAME.fullmatch(name):
            return "server" in _read_head(path) and "ssl" in _read_head(path)
        if name == "server.xml":
            return bool(_TOMCAT_SNIFF.search(_read_head(path)))
        return False

    def scan(self, path: Path, root: Path) -> Iterator[Finding | ScanError]:
        path = Path(path)
        try:
            rel = path.relative_to(root).as_posix()
        except ValueError:
            rel = path.as_posix()
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                yield ScanError(detector=DETECTOR, path=str(path), message="file larger than 5 MB, skipped")
                return
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            yield ScanError(detector=DETECTOR, path=str(path), message=f"cannot read: {exc.strerror or exc}")
            return
        out = _Out(rel)
        name = path.name.lower()
        if name == "server.xml":
            _tomcat(out, text)
        elif name.endswith((".yml", ".yaml")):
            _spring_yaml(out, text)
        else:
            _scan_text(out, text, name)
        yield from out.findings.values()
