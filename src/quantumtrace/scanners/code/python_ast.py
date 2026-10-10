"""Python import-alias resolution for the regex rule engine.

The Python rules match canonical spellings (hashlib.md5(, rsa.generate_private_key(, hashes.SHA1(),
AESGCM(). Code that imports under another name (import hashlib as h, from hashlib import md5,
from ...asymmetric import rsa as R) would not match. resolve_aliases rewrites those references, in
the comment-masked text, to the canonical spelling before the rules run. Rules, flow and usage
inference are unchanged and see canonical text.

Properties:
  - Newlines are never touched, so line numbers hold. Snippets come from the original text.
  - A file without a rewritable alias returns the masked text object unchanged.
  - A file that does not parse (Python 2, partial files) returns the masked text unchanged.
  - A name is rewritten only when every binding of it in the file is the same import. Any
    assignment, parameter, loop or with target, comprehension target, def or class of the same
    name, a conflicting import, or a conflicting binding of the replacement's root skips it.
  - Strings are never rewritten: only ast.Name nodes and plain-import dotted attribute chains.
  - The one insertion: PBKDF2HMAC(hashes.SHA1(), ...) gets `algorithm=` before its positional hash
    class (any line layout), so the keyword rule and the plain-hash dedupe see one canonical form.

Canonical form:
  import hashlib as h                     h        -> hashlib
  from hashlib import md5 [as m]          md5, m   -> hashlib.md5
  from ...asymmetric import rsa as R      R        -> rsa
  from ...rsa import generate_private_key g        -> rsa.generate_private_key
  from ...aead import AESGCM as G         G        -> AESGCM
  import cryptography...asymmetric.rsa    cryptography...asymmetric.rsa.f( -> rsa.f(

QUALIFIERS is the set of module tokens the rules write in front of a member. A test keeps it in
step with rules/python.yaml.
"""

from __future__ import annotations

import ast

QUALIFIERS = frozenset(
    {
        "AES",
        "ARC4",
        "BLAKE2b",
        "BLAKE2s",
        "DES",
        "DES3",
        "DSA",
        "ECC",
        "HMAC",
        "MD2",
        "MD5",
        "PKCS1_OAEP",
        "PKCS1_v1_5",
        "RIPEMD160",
        "RSA",
        "SHA1",
        "SHA224",
        "SHA256",
        "SHA384",
        "SHA3_224",
        "SHA3_256",
        "SHA3_384",
        "SHA3_512",
        "SHA512",
        "TLSVersion",
        "algorithms",
        "dh",
        "dsa",
        "ec",
        "ed25519",
        "hashes",
        "hashlib",
        "hmac",
        "modes",
        "os",
        "padding",
        "pkcs1_15",
        "pss",
        "random",
        "rsa",
        "ssl",
        "x25519",
        "x448",
    }
)

# Members the rules write without a module prefix even when their module is a qualifier.
BARE_MEMBERS = frozenset(
    {
        "Ed25519PrivateKey",
        "X25519PrivateKey",
        "X25519PublicKey",
        "X448PrivateKey",
        "X448PublicKey",
    }
)

# A binding of a name: ("as", dotted path), ("plain", root), ("from", module, object) or ("other",).
_Binding = tuple[str, ...]


def _bindings(tree: ast.AST) -> dict[str, list[_Binding]]:
    names: dict[str, list[_Binding]] = {}

    def add(name: str, binding: _Binding = ("other",)) -> None:
        names.setdefault(name, []).append(binding)

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                if item.asname:
                    add(item.asname, ("as", item.name))
                else:
                    root = item.name.split(".")[0]
                    add(root, ("plain", root))
        elif isinstance(node, ast.ImportFrom):
            for item in node.names:
                if item.name == "*":
                    continue
                bound = item.asname or item.name
                if node.level or not node.module:
                    add(bound)
                else:
                    add(bound, ("from", node.module, item.name))
        elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            add(node.id)
        elif isinstance(node, ast.arg):
            add(node.arg)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            add(node.name)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            add(node.name)
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            add(node.name)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            add(node.rest)
    return names


def _replacement(name: str, binding: _Binding) -> str | None:
    kind = binding[0]
    if kind == "as":
        last = binding[1].rsplit(".", 1)[-1]
        return last if last in QUALIFIERS else None
    if kind == "from":
        module, obj = binding[1], binding[2]
        module_last = module.rsplit(".", 1)[-1]
        if obj in BARE_MEMBERS:
            return obj
        if module_last in QUALIFIERS:
            return f"{module_last}.{obj}"
        return obj
    return None


def _name_map(names: dict[str, list[_Binding]]) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for name, bound in names.items():
        if len(set(bound)) != 1:
            continue
        replacement = _replacement(name, bound[0])
        if replacement is None or replacement == name:
            continue
        root = replacement.split(".")[0]
        if any(b == ("other",) for b in names.get(root, [])):
            continue
        mapping[name] = replacement
    return mapping


def _dotted_imports(tree: ast.AST, names: dict[str, list[_Binding]]) -> dict[str, str]:
    """Plain `import a.b.c` paths whose last segment is a qualifier, mapped to that segment."""
    found: dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Import):
            continue
        for item in node.names:
            if item.asname or "." not in item.name:
                continue
            last = item.name.rsplit(".", 1)[-1]
            root = item.name.split(".")[0]
            if last in QUALIFIERS and all(b[0] == "plain" for b in names.get(root, [])):
                found[item.name] = last
    return found


def _dotted(node: ast.AST) -> str | None:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    parts.append(node.id)
    return ".".join(reversed(parts))


def _positional_algorithm(
    call: ast.Call, mapping: dict[str, str], dotted: dict[str, str], names: dict[str, list[_Binding]]
) -> tuple[int, int] | None:
    """Position of the first argument of PBKDF2HMAC(hashes.X(), ...) when it is a positional hash class."""
    func = call.func
    callee = func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else ""
    if mapping.get(callee, callee) != "PBKDF2HMAC":
        return None
    if isinstance(func, ast.Name) and ("other",) in names.get(func.id, []):
        return None
    if not call.args or any(k.arg in (None, "algorithm") for k in call.keywords):
        return None
    first = call.args[0]
    if not isinstance(first, ast.Call) or first.args or first.keywords:
        return None
    path = _dotted(first.func)
    if path is None:
        return None
    module, _, member = path.rpartition(".")
    if module in dotted:
        canonical = f"{dotted[module]}.{member}"
    else:
        root, _, rest = path.partition(".")
        canonical = mapping.get(root, root) + (f".{rest}" if rest else "")
    if not canonical.startswith("hashes.") or canonical.count(".") != 1:
        return None
    return first.lineno, first.col_offset


def resolve_aliases(text: str, masked: str) -> str:
    """Return `masked` with aliased names and dotted import paths rewritten to canonical spelling.

    `text` is the original source (parsed), `masked` the same text with comments blanked. Both have
    the same characters outside comments, so positions from `text` apply to `masked`.
    """
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return masked
    names = _bindings(tree)
    mapping = _name_map(names)
    dotted = _dotted_imports(tree, names)

    edits: list[tuple[int, int, int, str, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            at = _positional_algorithm(node, mapping, dotted, names)
            if at is not None:
                edits.append((at[0], at[1], at[1], "", "algorithm="))
            continue
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id in mapping:
            old, new = node.id, mapping[node.id]
        elif isinstance(node, ast.Attribute) and dotted:
            old = _dotted(node) or ""
            if old not in dotted:
                continue
            new = dotted[old]
        else:
            continue
        if node.end_lineno != node.lineno or node.end_col_offset is None:
            continue
        edits.append((node.lineno, node.col_offset, node.end_col_offset, old, new))
    if not edits:
        return masked

    source_lines = text.split("\n")
    lines = masked.split("\n")
    for number, start, end, old, new in sorted(edits, reverse=True):
        if number > len(lines):
            continue
        # ast offsets count UTF-8 bytes
        raw = source_lines[number - 1].encode("utf-8")
        a = len(raw[:start].decode("utf-8", errors="ignore"))
        b = len(raw[:end].decode("utf-8", errors="ignore"))
        row = lines[number - 1]
        if row[a:b] != old:
            continue
        lines[number - 1] = row[:a] + new + row[b:]
    result = "\n".join(lines)
    return masked if result == masked else result
