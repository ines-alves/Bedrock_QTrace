"""Regex rule engine for source code scanning.

Scanners only detect: this module yields raw Finding objects and never assigns a tier,
threat or score. Rules live in rules/<language>.yaml.

Rule fields (YAML list of mappings):
  id, language, pattern, raw_name, kind_hint, usage          required (raw_name optional if emit: false)
  confidence                                                 default 1.0
  key_size (int), key_size_unit (bits|bytes), key_size_from_length (bool)
  curve, mode, padding, library                              templates, "{group}" substitution
  refine: {from: <group>, pattern: <regex>}                  split a resolved group into more groups
  lookahead_pattern, lookahead_lines                         fallback key size search after the match
  provides_key_size: <family>                                key size source: a sized generation site
  inherit_key_size: <family>                                 key size sink: size only through a flow link
  key_arg_pattern, key_arg_lines                             where to find the sink's key (group key_arg)
  mode_cases: [{mode, mode_source, requires, forbids}]       first case whose regexes hold in the enclosing
                                                             function sets mode and extra["mode_source"]
  requires, forbids: [regex]                                 the rule fires only if every requires regex
  scope: file | function                                     matches and no forbids regex matches, in the
                                                             whole file (default) or the enclosing function
  extra: {key: json value}                                   static extra (hygiene_only, hand_rolled, ...);
                                                             a string value may hold "{group}" (the
                                                             source constant of a TLS version rule)
  redact: true                                               redact every string literal in the snippet
  literal_key: <family>                                      hard-coded key rule: see below
  values_must_match: {group: regex}                          drop the hit unless each named group's value,
                                                             after constant resolution, fully matches
                                                             (an identifier that did not resolve is
                                                             always dropped, whatever its spelling)
  absorbed_by: [RULE_ID, ...]                                drop the hit when its match starts inside the
                                                             match of a hit of one of these rules
  iterations: {arg, keyword, callee, loop_param, default}     where the PBKDF2 iteration count is: see below
  parameter_source: library_default                          the emitted parameter (hash in raw_name) is the
                                                             documented library default: see below
  emit: false                                                record only, produce no finding

Pattern groups: a group named X holds a literal; a group named X_ref holds an identifier that is
resolved through file-scope constants and Python parameter defaults. key_size and key_size_ref are
the size groups. A group named key_arg holds the identifier of the key a sink consumes. A group named
key_literal holds an inline string or bytes literal passed as the key (Go []byte("...") included): with
key_size_from_length the size is its decoded length in bits, key_size_source "literal". It never stays
readable in a snippet.

Key size flow (inherit_key_size): a sink takes a size only when its key argument traces, inside the
file, to a source of the same family: the sized generation is in a function that returns it (the
producer), the producer's result is bound to a variable once, and that variable reaches the sink
directly or as an argument of the function that contains the sink. Reassigned or conflicting bindings,
imported keys and unused allocations never link: the size stays None with key_size_source
"unresolved" (or "ambiguous" for conflicting sizes). A linked size has key_size_source "flow".

Iterations (PBKDF2): a rule with `iterations` reports extra["iterations"] (an int) when the count is an
int literal, a file-scope constant or Python parameter default, or the argument of the single call site
(or of several call sites that agree) of the enclosing function when the count is one of its parameters
(one hop). Anything else (an expression, a second hop, disagreeing call sites, no call site) emits no
key; it is never 0. `arg` is the 0-based index among the positional arguments and `keyword` the keyword
name, of the call at the match: the pattern holds an empty group `call` right after the opening
parenthesis. `callee` (a regex naming the constructor, PBEKeySpec in Java) reads the call from the enclosing function
instead, and must be unique there. `loop_param: true` (hand-rolled KDFs) takes the bound of a counting
loop of the enclosing function when exactly one such bound is a parameter of that function. The
confidence of the finding is not changed.

Usage inference (RSA only): a generation hit (provides_key_size RSA) whose rule usage is unknown becomes
usage signature, with extra["usage_source"] "flow" and confidence at most 0.8, only when every RSA sink
(inherit_key_size RSA) of the file traces to exactly one generation, at least one sink traces to this
generation, and every sink linked to it signs or verifies. One RSA sink with an unresolved, ambiguous or
multi-source flow blocks the whole file, because it might consume the generated key through an alias.

Hard-coded key (literal_key): the rule pattern matches a key sink and holds either a group `key_arg` (the
identifier of the key) or a group `literal` (an inline string literal). The hit is kept only if the key is
a string or bytes literal: inline, a file-scope constant, a Python parameter default, or a constant
reached through call-site arguments of the enclosing function (same flow as inherit_key_size, at most
FLOW_DEPTH hops). The finding moves to the line of the literal. Keys that come from a generation, an
import, a call or an unresolvable call site never qualify. A literal reached through a
call-site hop has confidence at most 0.8. The size of the literal is never reported.

Library defaults (parameter_source): a rule with `parameter_source: library_default` reports a parameter
the call did not state, taken from the library's documented default (the hash in raw_name). The finding
carries extra["parameter_source"] "library_default" and confidence at most 0.8. `iterations.default: N`
does the same for the count: when the call names no count (no keyword, no positional at that index, no
star argument) iterations is N and parameter_source is set. The documentation URL and library version go
in the rule comment, never in extra. A library without a documented default has no such rule.

Local key assignment (M1M3-12): a string or bytes literal assigned to a local of the function that holds
the sink (`key = b"..."`, `key := []byte("...")`, `byte[] key = "...".getBytes(...)`) also qualifies,
when that name has exactly one assignment in the function and is never extended with an augmented
assignment. The finding moves to the literal's line with confidence at most 0.8, and the AES finding
takes the literal's length as its size (key_size_source flow, resolved_from_line the assignment). A name
that is reassigned, bound to a call, or a literal that is only plaintext never qualifies.

Snippets: every string literal of the matched line is replaced by <redacted> unless its text equals a
value one of the rule's literal groups captured (an algorithm, transform or name). A key literal that
no group captured never reaches a snippet. `redact: true` keeps no literal at all.

Python import aliases (import hashlib as h, from hashlib import md5) are rewritten to the canonical
spelling in the masked text before any rule runs: see python_ast.py.
"""

from __future__ import annotations

import ast
import json
import re
from collections.abc import Iterator
from dataclasses import dataclass, field, replace
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from quantumtrace.models import Finding, KindHint, Location, ScanError, SourceType, Usage
from quantumtrace.scanners.base import finding_id, is_test_path, register
from quantumtrace.scanners.code.python_ast import resolve_aliases

LANGUAGE_BY_SUFFIX = {".py": "python", ".java": "java", ".go": "go"}
RULES_DIR = Path(__file__).parent / "rules"
MAX_FILE_BYTES = 5 * 1024 * 1024
SNIPPET_MAX = 200
HEURISTIC_CONFIDENCE_CAP = 0.8
UNRESOLVED_CONFIDENCE_CAP = 0.5
ALIAS_DEPTH = 5

_RULE_KEYS = {
    "id",
    "language",
    "pattern",
    "raw_name",
    "kind_hint",
    "usage",
    "confidence",
    "key_size",
    "key_size_unit",
    "key_size_from_length",
    "curve",
    "mode",
    "padding",
    "library",
    "refine",
    "lookahead_pattern",
    "lookahead_lines",
    "provides_key_size",
    "inherit_key_size",
    "emit",
    "key_arg_pattern",
    "key_arg_lines",
    "mode_cases",
    "extra",
    "redact",
    "requires",
    "forbids",
    "scope",
    "literal_key",
    "values_must_match",
    "absorbed_by",
    "iterations",
    "parameter_source",
}
_ITERATIONS_KEYS = {"arg", "keyword", "callee", "loop_param", "default"}
_CASE_KEYS = {"mode", "mode_source", "requires", "forbids"}
_RESERVED_EXTRA = {
    "rule",
    "key_size_source",
    "unresolved",
    "resolved_from_line",
    "mode_source",
    "usage_source",
    "iterations",
    "parameter_source",
}
FLOW_DEPTH = 3

Value = int | str | bytes


# ---------------------------------------------------------------- rules


@dataclass(frozen=True)
class ModeCase:
    mode: str
    mode_source: str | None
    requires: tuple[re.Pattern[str], ...]
    forbids: tuple[re.Pattern[str], ...]


@dataclass(frozen=True)
class IterationsSpec:
    arg: int | None
    keyword: str | None
    callee: re.Pattern[str] | None
    loop_param: bool
    default: int | None = None


@dataclass(frozen=True)
class Rule:
    id: str
    language: str
    pattern: re.Pattern[str]
    raw_name: str
    kind_hint: KindHint
    usage: Usage
    confidence: float = 1.0
    key_size: int | None = None
    key_size_unit: str = "bits"
    key_size_from_length: bool = False
    curve: str | None = None
    mode: str | None = None
    padding: str | None = None
    library: str | None = None
    refine: tuple[str, re.Pattern[str]] | None = None
    lookahead_pattern: re.Pattern[str] | None = None
    lookahead_lines: int = 5
    provides_key_size: str | None = None
    inherit_key_size: str | None = None
    emit: bool = True
    key_arg_pattern: re.Pattern[str] | None = None
    key_arg_lines: int = 5
    mode_cases: tuple[ModeCase, ...] = ()
    extra: dict[str, Any] = field(default_factory=dict)
    redact: bool = False
    requires: tuple[re.Pattern[str], ...] = ()
    forbids: tuple[re.Pattern[str], ...] = ()
    scope: str = "file"
    literal_key: str | None = None
    values_must_match: tuple[tuple[str, re.Pattern[str]], ...] = ()
    absorbed_by: tuple[str, ...] = ()
    iterations: IterationsSpec | None = None
    parameter_source: str | None = None

    @property
    def expects_key_size(self) -> bool:
        groups = self.pattern.groupindex
        return (
            "key_size" in groups
            or "key_size_ref" in groups
            or self.inherit_key_size is not None
            or self.lookahead_pattern is not None
        )


def _compile(src: str, where: str) -> re.Pattern[str]:
    try:
        return re.compile(src, re.MULTILINE)
    except re.error as exc:
        raise ValueError(f"{where}: invalid regex: {exc}") from exc


def _parse_rule(raw: dict[str, Any], source: str) -> Rule:
    rid = raw.get("id", "?")
    where = f"{source}: rule {rid}"
    unknown = set(raw) - _RULE_KEYS
    if unknown:
        raise ValueError(f"{where}: unknown keys {sorted(unknown)}")
    for key in ("id", "language", "pattern", "kind_hint", "usage"):
        if key not in raw:
            raise ValueError(f"{where}: missing '{key}'")
    emit = raw.get("emit", True)
    if emit and not raw.get("raw_name"):
        raise ValueError(f"{where}: missing 'raw_name'")
    try:
        kind_hint = KindHint(raw["kind_hint"])
        usage = Usage(raw["usage"])
    except ValueError as exc:
        raise ValueError(f"{where}: {exc}") from exc
    unit = raw.get("key_size_unit", "bits")
    if unit not in ("bits", "bytes"):
        raise ValueError(f"{where}: key_size_unit must be bits or bytes")
    refine = None
    if "refine" in raw:
        spec = raw["refine"]
        refine = (spec["from"], _compile(spec["pattern"], where))
    look = raw.get("lookahead_pattern")
    key_arg = raw.get("key_arg_pattern")
    extra = raw.get("extra") or {}
    if not isinstance(extra, dict) or set(extra) & _RESERVED_EXTRA:
        raise ValueError(f"{where}: extra must be a mapping without {sorted(_RESERVED_EXTRA)}")
    try:
        json.dumps(extra)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{where}: extra must be JSON compatible: {exc}") from exc
    scope = raw.get("scope", "file")
    if scope not in ("file", "function"):
        raise ValueError(f"{where}: scope must be file or function")
    conditions = {}
    for key in ("requires", "forbids"):
        patterns = raw.get(key) or []
        if not isinstance(patterns, list) or not all(isinstance(p, str) for p in patterns):
            raise ValueError(f"{where}: {key} must be a list of regex strings")
        conditions[key] = tuple(_compile(p, where) for p in patterns)
    literal_key = raw.get("literal_key")
    if literal_key is not None:
        groups = _compile(raw["pattern"], where).groupindex
        if not isinstance(literal_key, str) or not ({"key_arg", "literal"} & set(groups)):
            raise ValueError(f"{where}: literal_key needs a family name and a key_arg or literal group")
    must_match = raw.get("values_must_match") or {}
    if not isinstance(must_match, dict) or not all(isinstance(v, str) for v in must_match.values()):
        raise ValueError(f"{where}: values_must_match must map group names to regex strings")
    absorbed_by = raw.get("absorbed_by") or []
    if not isinstance(absorbed_by, list) or not all(isinstance(v, str) for v in absorbed_by):
        raise ValueError(f"{where}: absorbed_by must be a list of rule ids")
    iterations = None
    spec = raw.get("iterations")
    if spec is not None:
        if not isinstance(spec, dict) or set(spec) - _ITERATIONS_KEYS:
            raise ValueError(f"{where}: iterations takes only {sorted(_ITERATIONS_KEYS)}")
        arg, keyword, callee = spec.get("arg"), spec.get("keyword"), spec.get("callee")
        loop_param = bool(spec.get("loop_param", False))
        if loop_param == (arg is not None or keyword is not None):
            raise ValueError(f"{where}: iterations needs arg and/or keyword, or loop_param")
        if arg is not None and (not isinstance(arg, int) or isinstance(arg, bool) or arg < 0):
            raise ValueError(f"{where}: iterations.arg must be a non-negative integer")
        if keyword is not None and not isinstance(keyword, str):
            raise ValueError(f"{where}: iterations.keyword must be a string")
        if callee is None and not loop_param and "call" not in _compile(raw["pattern"], where).groupindex:
            raise ValueError(f"{where}: iterations needs a `call` group in the pattern or a callee")
        default = spec.get("default")
        if default is not None:
            if not isinstance(default, int) or isinstance(default, bool) or default < 1:
                raise ValueError(f"{where}: iterations.default must be a positive integer")
            if loop_param or callee is not None:
                raise ValueError(
                    f"{where}: iterations.default needs the call group, not callee or loop_param"
                )
        iterations = IterationsSpec(
            arg=arg,
            keyword=keyword,
            callee=_compile(callee, where) if callee else None,
            loop_param=loop_param,
            default=default,
        )
    parameter_source = raw.get("parameter_source")
    if parameter_source is not None and parameter_source != "library_default":
        raise ValueError(f"{where}: parameter_source can only be library_default")
    cases = []
    for case in raw.get("mode_cases") or []:
        bad = set(case) - _CASE_KEYS
        if bad or "mode" not in case:
            raise ValueError(f"{where}: mode_cases need 'mode' and only {sorted(_CASE_KEYS)}")
        cases.append(
            ModeCase(
                mode=str(case["mode"]),
                mode_source=case.get("mode_source"),
                requires=tuple(_compile(r, where) for r in case.get("requires") or []),
                forbids=tuple(_compile(r, where) for r in case.get("forbids") or []),
            )
        )
    return Rule(
        id=str(raw["id"]),
        language=raw["language"],
        pattern=_compile(raw["pattern"], where),
        raw_name=raw.get("raw_name", ""),
        kind_hint=kind_hint,
        usage=usage,
        confidence=float(raw.get("confidence", 1.0)),
        key_size=raw.get("key_size"),
        key_size_unit=unit,
        key_size_from_length=bool(raw.get("key_size_from_length", False)),
        curve=raw.get("curve"),
        mode=raw.get("mode"),
        padding=raw.get("padding"),
        library=raw.get("library"),
        refine=refine,
        lookahead_pattern=_compile(look, where) if look else None,
        lookahead_lines=int(raw.get("lookahead_lines", 5)),
        provides_key_size=raw.get("provides_key_size"),
        inherit_key_size=raw.get("inherit_key_size"),
        emit=bool(emit),
        key_arg_pattern=_compile(key_arg, where) if key_arg else None,
        key_arg_lines=int(raw.get("key_arg_lines", 5)),
        mode_cases=tuple(cases),
        extra=dict(extra),
        redact=bool(raw.get("redact", False)),
        requires=conditions["requires"],
        forbids=conditions["forbids"],
        scope=scope,
        literal_key=literal_key,
        values_must_match=tuple((group, _compile(p, where)) for group, p in must_match.items()),
        absorbed_by=tuple(absorbed_by),
        iterations=iterations,
        parameter_source=parameter_source,
    )


@lru_cache(maxsize=None)
def load_rules(language: str, rules_dir: Path = RULES_DIR) -> tuple[Rule, ...]:
    """Load and validate rules/<language>.yaml. Raises ValueError on a malformed rule file."""
    path = rules_dir / f"{language}.yaml"
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    if not isinstance(data, list):
        raise ValueError(f"{path}: expected a list of rules")
    rules = []
    seen: set[str] = set()
    for raw in data:
        rule = _parse_rule(raw, str(path))
        if rule.language != language:
            raise ValueError(f"{path}: rule {rule.id} has language {rule.language}")
        if rule.id in seen:
            raise ValueError(f"{path}: duplicate rule id {rule.id}")
        seen.add(rule.id)
        rules.append(rule)
    for rule in rules:
        unknown = set(rule.absorbed_by) - seen
        if unknown:
            raise ValueError(f"{path}: rule {rule.id} is absorbed_by unknown rule {sorted(unknown)}")
    return tuple(rules)


# ---------------------------------------------------------------- comment masking


def _skip_string(text: str, i: int, quote: str) -> int:
    """Return the index just after the string literal opening at text[i]."""
    n = len(text)
    j = i + 1
    while j < n:
        ch = text[j]
        if ch == "\\":
            j += 2
            continue
        if ch == quote:
            return j + 1
        if ch == "\n":
            return j
        j += 1
    return n


def _skip_until(text: str, i: int, closing: str) -> int:
    """Return the index just after `closing`, searching from i, or the end of text."""
    j = text.find(closing, i)
    return len(text) if j == -1 else j + len(closing)


def _starts_statement(text: str, i: int) -> bool:
    line_start = text.rfind("\n", 0, i) + 1
    return text[line_start:i].strip() == ""


def mask_comments(text: str, language: str) -> str:
    """Blank out comments (and Python docstrings) while keeping line and column positions."""
    out = list(text)
    n = len(text)
    i = 0

    def blank(a: int, b: int) -> None:
        for k in range(a, b):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        ch = text[i]
        if language == "python":
            if ch == "#":
                j = text.find("\n", i)
                j = n if j == -1 else j
                blank(i, j)
                i = j
            elif ch in "\"'":
                triple = text[i : i + 3]
                if triple in ('"""', "'''"):
                    j = _skip_until(text, i + 3, triple)
                    if _starts_statement(text, i):
                        blank(i, j)
                    i = j
                else:
                    i = _skip_string(text, i, ch)
            else:
                i += 1
            continue
        if text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j == -1 else j
            blank(i, j)
            i = j
        elif text.startswith("/*", i):
            j = _skip_until(text, i + 2, "*/")
            blank(i, j)
            i = j
        elif ch == '"':
            if language == "java" and text.startswith('"""', i):
                i = _skip_until(text, i + 3, '"""')
            else:
                i = _skip_string(text, i, '"')
        elif ch == "'":
            i = _skip_string(text, i, "'")
        elif ch == "`" and language == "go":
            i = _skip_until(text, i + 1, "`")
        else:
            i += 1
    return "".join(out)


# ---------------------------------------------------------------- constants


@dataclass(frozen=True)
class _Alias:
    name: str


_Entry = Value | _Alias | None

_IDENT = re.compile(r"[A-Za-z_]\w*")
_INT = re.compile(r"(?:0[xX][0-9a-fA-F_]+|\d[\d_]*)[lL]?")
_STR = r'(?:[bBrRuU]{0,2}"(?:[^"\\]|\\.)*"|[bBrRuU]{0,2}\'(?:[^\'\\]|\\.)*\')'

_PY_ASSIGN = re.compile(r"^(?P<name>[A-Za-z_]\w*)\s*(?::\s*[^=]+?)?\s*=(?!=)\s*(?P<val>.+?)\s*$")
_JAVA_FINAL = re.compile(
    r"\b(?:static\s+final|final\s+static)\b[^=;()]*?\b(?P<name>[A-Za-z_]\w*)\s*=\s*(?P<val>[^;]+);"
)
_GO_DECL = re.compile(r"^(?:const|var)\s+(?P<name>[A-Za-z_]\w*)(?:\s+[\w.\[\]*]+)?\s*=\s*(?P<val>.+?)\s*$")
_GO_BLOCK_START = re.compile(r"^\s*(?:const|var)\s*\(\s*$")
_GO_BLOCK_END = re.compile(r"^\s*\)\s*$")
_GO_ENTRY = re.compile(r"^\s*(?P<name>[A-Za-z_]\w*)(?:\s+[\w.\[\]*]+)?\s*=\s*(?P<val>.+?)\s*$")
_PY_DEF = re.compile(r"^(?P<indent>[ \t]*)(?:async\s+)?def\s+(?P<name>\w+)\s*\(", re.MULTILINE)


def _parse_int(token: str) -> int:
    token = token.replace("_", "").rstrip("lL")
    return int(token, 16) if token[:2].lower() == "0x" else int(token, 10)


def _string_value(token: str) -> str | bytes | None:
    try:
        value = ast.literal_eval(token)
    except (ValueError, SyntaxError):
        return None
    return value if isinstance(value, (str, bytes)) else None


def _parse_value(expr: str, language: str) -> _Entry:
    expr = expr.strip().rstrip(";")
    if _INT.fullmatch(expr):
        return _parse_int(expr)
    if language == "go":
        wrapped = re.fullmatch(r"\[\]byte\(\s*(.+?)\s*\)", expr)
        if wrapped:
            expr = wrapped.group(1)
        if len(expr) >= 2 and expr[0] == "`" and expr[-1] == "`":
            return expr[1:-1]
    if language == "java":
        getter = re.fullmatch(r"(?P<lit>\"(?:[^\"\\]|\\.)*\")\s*\.getBytes\(.*\)", expr)
        if getter:
            expr = getter.group("lit")
    if re.fullmatch(_STR, expr):
        return _string_value(expr)
    if _IDENT.fullmatch(expr):
        return _Alias(expr)
    return None


def _split_top_level(text: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    current: list[str] = []
    for ch in text:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
    parts.append("".join(current))
    return [p.strip() for p in parts if p.strip()]


@dataclass(frozen=True)
class _PyScope:
    first: int
    last: int
    name: str
    params: tuple[str, ...]
    defaults: dict[str, _Entry]
    default_lines: dict[str, int]


def _python_scopes(masked: str) -> list[_PyScope]:
    """Function extents with their parameters and parameter defaults."""
    lines = masked.split("\n")
    scopes = []
    for m in _PY_DEF.finditer(masked):
        depth, j = 1, m.end()
        while j < len(masked) and depth:
            depth += {"(": 1, ")": -1}.get(masked[j], 0)
            j += 1
        params_src = masked[m.end() : j - 1]
        defaults: dict[str, _Entry] = {}
        default_lines: dict[str, int] = {}
        cursor = 0
        for param in _split_top_level(params_src):
            at = params_src.find(param, cursor)
            cursor = at + len(param)
            pm = re.match(r"^\*{0,2}(?P<n>[A-Za-z_]\w*)\s*(?::[^=]+)?(?:=\s*(?P<d>.+))?$", param, re.S)
            if pm:
                default = pm.group("d")
                defaults[pm.group("n")] = _parse_value(default, "python") if default else None
                default_lines[pm.group("n")] = masked.count("\n", 0, m.end() + at) + 1
        first = masked.count("\n", 0, m.start()) + 1
        indent = len(m.group("indent").expandtabs(4))
        last = first
        for k in range(first, len(lines)):
            row = lines[k]
            if row.strip() and len(row) - len(row.lstrip()) <= indent:
                break
            last = k + 1
        names = tuple(n for n in defaults if n not in ("self", "cls"))
        scopes.append(_PyScope(first, last, m.group("name"), names, defaults, default_lines))
    return scopes


class Constants:
    """File-scope constants plus Python function parameter defaults."""

    def __init__(self, masked: str, language: str) -> None:
        self._globals: dict[str, _Entry] = {}
        self._global_lines: dict[str, int] = {}
        self._scopes: list[_PyScope] = []
        if language == "python":
            for number, row in enumerate(masked.split("\n"), 1):
                m = _PY_ASSIGN.match(row)
                if m:
                    self._globals[m.group("name")] = _parse_value(m.group("val"), language)
                    self._global_lines[m.group("name")] = number
            self._scopes = sorted(_python_scopes(masked), key=lambda sc: sc.first, reverse=True)
        elif language == "java":
            for m in _JAVA_FINAL.finditer(masked):
                self._globals[m.group("name")] = _parse_value(m.group("val"), language)
                self._global_lines[m.group("name")] = masked.count("\n", 0, m.start("val")) + 1
        else:
            in_block = False
            for number, row in enumerate(masked.split("\n"), 1):
                if in_block and _GO_BLOCK_END.match(row):
                    in_block = False
                elif _GO_BLOCK_START.match(row):
                    in_block = True
                else:
                    m = (_GO_ENTRY if in_block else _GO_DECL).match(row)
                    if m:
                        self._globals[m.group("name")] = _parse_value(m.group("val"), language)
                        self._global_lines[m.group("name")] = number

    def resolve_full(self, name: str, line: int) -> tuple[Value, str, int | None] | None:
        """Resolve an identifier used at `line`. Returns (value, source, definition line) or None."""
        entry: _Entry = None
        source = "constant"
        found = False
        at: int | None = None
        for scope in self._scopes:
            if scope.first <= line <= scope.last and name in scope.defaults:
                entry, source, found = scope.defaults[name], "param_default", True
                at = scope.default_lines.get(name)
                break
        if not found:
            entry = self._globals.get(name)
            at = self._global_lines.get(name)
        for _ in range(ALIAS_DEPTH):
            if not isinstance(entry, _Alias):
                break
            at = self._global_lines.get(entry.name)
            entry = self._globals.get(entry.name)
        if isinstance(entry, (int, str, bytes)):
            return entry, source, at
        return None

    def resolve(self, name: str, line: int) -> tuple[Value, str] | None:
        """Resolve an identifier used at `line`. Returns (value, source) or None."""
        full = self.resolve_full(name, line)
        return None if full is None else (full[0], full[1])


# ---------------------------------------------------------------- matching


@dataclass
class _Hit:
    rule: Rule
    usage: Usage
    line: int
    raw_name: str
    key_size: int | None
    key_size_source: str | None
    curve: str | None
    mode: str | None
    padding: str | None
    confidence: float
    unresolved: list[str]
    key_arg: str | None = None
    resolved_from_line: int | None = None
    mode_source: str | None = None
    usage_source: str | None = None
    sink_generations: frozenset[int] | None = None
    literal_inline: bool = False
    visible: frozenset[str] = frozenset()
    span: tuple[int, int] = (0, 0)
    call_paren: int | None = None
    iterations: int | None = None
    parameter_source: str | None = None
    extra: dict[str, Any] | None = None


def _literal_length(value: str | bytes) -> int:
    return len(value.encode("utf-8")) if isinstance(value, str) else len(value)


def _size_from(
    rule: Rule, groups: dict[str, str | None], consts: Constants, line: int
) -> tuple[int | None, str | None, int | None]:
    """Returns (size, source, line of the constant or default the size came from)."""
    if rule.key_size is not None:
        return rule.key_size, "literal", None
    literal = groups.get("key_size")
    if literal:
        size = _parse_int(literal)
        return (size * 8 if rule.key_size_unit == "bytes" else size), "literal", None
    key_literal = groups.get("key_literal")
    if key_literal and rule.key_size_from_length:
        inline = _parse_value(key_literal, rule.language)
        if isinstance(inline, (str, bytes)):
            return _literal_length(inline) * 8, "literal", None
        return None, None, None
    ref = groups.get("key_size_ref")
    if not ref:
        return None, None, None
    resolved = consts.resolve_full(ref, line)
    if resolved is None:
        return None, None, None
    value, source, at = resolved
    if isinstance(value, int):
        return (value * 8 if rule.key_size_unit == "bytes" else value), source, at
    if rule.key_size_from_length:
        return _literal_length(value) * 8, source, at
    return None, None, None


class _Template(dict):
    def __missing__(self, key: str) -> str:
        return ""


def _render(template: str | None, values: dict[str, str]) -> str | None:
    if template is None:
        return None
    return template.format_map(_Template(values)).strip() or None


def _render_extra(extra: dict[str, Any], values: dict[str, str]) -> dict[str, Any]:
    """Static extra with "{group}" filled in the string values that name a group."""
    return {
        key: _render(value, values) if isinstance(value, str) and "{" in value else value
        for key, value in extra.items()
    }


def _match_hits(rule: Rule, masked: str, lines: list[str], consts: Constants) -> Iterator[_Hit]:
    for m in rule.pattern.finditer(masked):
        line = masked.count("\n", 0, m.start()) + 1
        groups: dict[str, str | None] = dict(m.groupdict())
        size, size_source, from_line = _size_from(rule, groups, consts, line)
        visible = _visible_literals(groups)

        if size is None and rule.lookahead_pattern is not None:
            window = "\n".join(lines[line - 1 : line + rule.lookahead_lines])
            look = rule.lookahead_pattern.search(window)
            if look:
                visible |= _visible_literals(look.groupdict())
                look_line = line + window.count("\n", 0, look.start())
                size, _, from_line = _size_from(rule, dict(look.groupdict()), consts, look_line)
                size_source = "lookahead" if size is not None else None

        key_arg = groups.get("key_arg")
        if not key_arg and rule.key_size_from_length:
            key_arg = groups.get("key_size_ref")
        if not key_arg and rule.key_arg_pattern is not None:
            window = "\n".join(lines[line - 1 : line + rule.key_arg_lines])
            found = rule.key_arg_pattern.search(window)
            if found:
                key_arg = found.groupdict().get("key_arg")

        values: dict[str, str] = {}
        unresolved: list[str] = []
        for name, value in groups.items():
            if value is None or name == "key_size_ref":
                continue
            if name.endswith("_ref"):
                base = name[: -len("_ref")]
                if groups.get(base):
                    continue
                resolved = consts.resolve_full(value, line)
                if resolved is not None and from_line is None:
                    from_line = resolved[2]
                if resolved is not None and not isinstance(resolved[0], int):
                    text = resolved[0]
                    values[base] = text.decode("utf-8", "replace") if isinstance(text, bytes) else text
                elif resolved is not None:
                    values[base] = str(resolved[0])
                else:
                    values[base] = value
                    unresolved.append(base)
            else:
                values[name] = value

        if any(
            group in unresolved or not (value := values.get(group)) or not pattern.fullmatch(value)
            for group, pattern in rule.values_must_match
        ):
            continue

        if rule.refine is not None:
            source_group, pattern = rule.refine
            refined = pattern.search(values.get(source_group, ""))
            if refined:
                for name, value in refined.groupdict().items():
                    if value is not None:
                        values.setdefault(name, value)

        confidence = rule.confidence
        if unresolved:
            confidence = min(confidence, UNRESOLVED_CONFIDENCE_CAP)
        if size_source == "lookahead" or rule.parameter_source:
            confidence = min(confidence, HEURISTIC_CONFIDENCE_CAP)

        yield _Hit(
            rule=rule,
            usage=rule.usage,
            line=line,
            raw_name=_render(rule.raw_name, values) or "",
            key_size=size,
            key_size_source=size_source,
            curve=_render(rule.curve, values),
            mode=_render(rule.mode, values),
            padding=_render(rule.padding, values),
            confidence=confidence,
            unresolved=unresolved,
            key_arg=key_arg,
            resolved_from_line=from_line,
            literal_inline=bool(groups.get("literal")),
            visible=frozenset() if rule.redact else frozenset(visible),
            span=m.span(),
            call_paren=m.start("call") - 1 if "call" in groups else None,
            parameter_source=rule.parameter_source,
            extra=_render_extra(rule.extra, values),
        )


# ---------------------------------------------------------------- key flow


@dataclass(frozen=True)
class _Func:
    name: str
    first: int
    last: int
    params: tuple[str, ...]


@dataclass(frozen=True)
class _Assign:
    line: int
    scope: int | None
    names: tuple[str, ...]
    callee: str | None
    rhs: str = ""


_JAVA_METHOD = re.compile(
    r"^[ \t]*(?:(?:public|private|protected|static|final|synchronized|abstract|native)[ \t]+)*"
    r"(?:<[^>\n]+>[ \t]+)?(?P<type>[\w.<>\[\],? \t]+?)[ \t]+(?P<name>[A-Za-z_]\w*)[ \t]*"
    r"\((?P<params>[^)]*)\)[ \t]*(?:throws[ \t]+[\w.,\t ]+?)?[ \t\n]*\{",
    re.MULTILINE,
)
_GO_FUNC = re.compile(
    r"^[ \t]*func[ \t]*(?:\([^)]*\)[ \t]*)?(?P<name>[A-Za-z_]\w*)[ \t]*\((?P<params>[^)]*)\)[^{\n]*\{",
    re.MULTILINE,
)
_NOT_METHODS = {"if", "for", "while", "switch", "catch", "return", "new", "else", "synchronized"}
_ASSIGN = re.compile(r"^\s*(?P<lhs>[^=()]+?)\s*:?=(?!=)\s*(?P<rhs>.*)$")
_CALLEE = re.compile(r"\s*(?:await\s+)?(?:[A-Za-z_]\w*\s*\.\s*)*(?P<fn>[A-Za-z_]\w*)\s*\(")
_LOOP_BOUND = re.compile(r"\bfor\b[^;{}\n]*;\s*[A-Za-z_]\w*\s*<=?\s*(?P<bound>[A-Za-z_]\w*)\s*;")
_RETURN = re.compile(r"^\s*return\b(?P<expr>.*)$")
_RECEIVER = re.compile(r"\b([A-Za-z_]\w*)\s*\.\s*\w+\s*\(")
_IDENTS = re.compile(r"[A-Za-z_]\w*")
_Source = tuple[int, int | None, int | None]
_BASE_IDENT = re.compile(r"[&*]?\s*(?P<id>[A-Za-z_]\w*)\b(?:[.\[(].*)?", re.S)
_STRING_LITERAL = re.compile(r"[bBrRuUfF]{0,2}(?:\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*'|`[^`]*`)")


def _match_close(text: str, i: int, opening: str, closing: str) -> int:
    """Index of the bracket closing the one at text[i], skipping string literals."""
    depth, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch in "\"'`":
            i = _skip_string(text, i + 1, ch)
            continue
        if ch == opening:
            depth += 1
        elif ch == closing:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return n - 1


def _param_names(params: str, language: str) -> tuple[str, ...]:
    names = []
    for seg in _split_top_level(params):
        idents = _IDENTS.findall(seg.split("=")[0])
        if not idents:
            continue
        names.append(idents[0] if language == "go" else idents[-1])
    return tuple(names)


def _functions(masked: str, language: str) -> list[_Func]:
    if language == "python":
        return [_Func(sc.name, sc.first, sc.last, sc.params) for sc in _python_scopes(masked)]
    pattern = _JAVA_METHOD if language == "java" else _GO_FUNC
    funcs = []
    for m in pattern.finditer(masked):
        if m.group("name") in _NOT_METHODS:
            continue
        if language == "java" and re.search(r"\b(?:new|return|else)\b", m.group("type")):
            continue
        opening = masked.index("{", m.end("params"))
        closing = _match_close(masked, opening, "{", "}")
        funcs.append(
            _Func(
                m.group("name"),
                masked.count("\n", 0, m.start()) + 1,
                masked.count("\n", 0, closing) + 1,
                _param_names(m.group("params"), language),
            )
        )
    return funcs


def _target_names(lhs: str) -> tuple[str, ...]:
    names = []
    for seg in lhs.split(","):
        tokens = seg.split(":")[0].split()
        if tokens and re.fullmatch(r"[A-Za-z_]\w*", tokens[-1]) and tokens[-1] != "_":
            names.append(tokens[-1])
    return tuple(names)


_KEYWORD_ARG = re.compile(r"^([A-Za-z_]\w*)\s*=(?!=)\s*(.+)$", re.S)


def _argument_for(args: list[str], name: str, position: int) -> str | None:
    """The argument bound to parameter `name` (keyword, else the positional at `position`)."""
    arg = None
    for k, raw in enumerate(args):
        keyword = _KEYWORD_ARG.match(raw)
        if keyword and keyword.group(1) == name:
            return keyword.group(2)
        if not keyword and k == position:
            arg = raw
    return arg


def _call_args(masked: str, open_paren: int) -> list[str]:
    close = _match_close(masked, open_paren, "(", ")")
    return _split_top_level(masked[open_paren + 1 : close])


class _Flow:
    """Same-file flow of a sized key from its generation to the key argument of a sink."""

    def __init__(self, masked: str, language: str, hits: list[_Hit], consts: Constants) -> None:
        self.masked = masked
        self.consts = consts
        self.language = language
        self.lines = masked.split("\n")
        self.hits = hits
        self.funcs = _functions(masked, language)
        self.declared = {f.first for f in self.funcs}
        self.by_name: dict[str, list[int]] = {}
        for index, func in enumerate(self.funcs):
            self.by_name.setdefault(func.name, []).append(index)
        self.assigns: list[_Assign] = []
        for number, row in enumerate(self.lines, 1):
            m = _ASSIGN.match(row)
            if not m or m.group("lhs").rstrip().endswith(("<", ">", "!")):
                continue
            names = _target_names(m.group("lhs"))
            if names:
                callee = _CALLEE.match(m.group("rhs"))
                self.assigns.append(
                    _Assign(
                        number,
                        self.scope_of(number),
                        names,
                        callee.group("fn") if callee else None,
                        m.group("rhs"),
                    )
                )

    def scope_of(self, line: int) -> int | None:
        best = None
        for index, func in enumerate(self.funcs):
            if func.first <= line <= func.last and (best is None or func.first > self.funcs[best].first):
                best = index
        return best

    def context(self, line: int) -> str:
        scope = self.scope_of(line)
        if scope is None:
            return self.masked
        func = self.funcs[scope]
        return "\n".join(self.lines[func.first - 1 : func.last])

    def _local_literal(self, assign: _Assign, name: str) -> set[_Source] | None:
        """The single assignment of `name` in its function when it binds a string or bytes literal that
        is never extended (`name += ...`): the source is the literal's length and line."""
        if len(assign.names) != 1:
            return None
        value = _parse_value(assign.rhs, self.language)
        if not isinstance(value, (str, bytes)):
            return None
        first, last = (1, len(self.lines)) if assign.scope is None else self._span(assign.scope)
        extended = re.compile(rf"\b{re.escape(name)}\s*(?:<<|>>|[-+*/%&|^])=")
        if any(extended.search(self.lines[n - 1]) for n in range(first, last + 1)):
            return None
        return {(_literal_length(value) * 8, assign.line, None)}

    def _span(self, index: int) -> tuple[int, int]:
        return self.funcs[index].first, self.funcs[index].last

    def _bound(self, line: int) -> set[str]:
        for assign in self.assigns:
            if assign.line == line:
                return set(assign.names)
        return set(_RECEIVER.findall(self.lines[line - 1]))

    def _producer(self, index: int, family: str) -> set[_Source] | None:
        func = self.funcs[index]
        returns = []
        for number in range(func.first, func.last + 1):
            m = _RETURN.match(self.lines[number - 1])
            if m:
                returns.append((number, set(_IDENTS.findall(m.group("expr")))))
        found: set[_Source] = set()
        for size, from_line, line in self._sources(family):
            if self.scope_of(line) != index:
                continue
            bound = self._bound(line)
            if any(number == line or bound & idents for number, idents in returns):
                found.add((size, from_line, line))
        return found or None

    def _sources(self, family: str) -> list[tuple[int, int | None, int]]:
        """(size, line the size came from, generation line) of every sized hit of the family."""
        return [
            (h.key_size, h.resolved_from_line, h.line)
            for h in self.hits
            if h.rule.provides_key_size == family and h.key_size is not None
        ]

    def _call_sites(self, func: _Func, index: int) -> list[tuple[int, list[str]]]:
        sites = []
        for m in re.finditer(rf"(?<![\w.]){re.escape(func.name)}\s*\(", self.masked):
            line = self.masked.count("\n", 0, m.start()) + 1
            if line in self.declared or self.scope_of(line) == index:
                continue
            sites.append((line, _call_args(self.masked, m.end() - 1)))
        return sites

    def trace(
        self, name: str, scope: int | None, family: str, depth: int, literal: bool
    ) -> set[_Source] | None:
        """Sources (size, line the size came from, generation line) of the key `name`, or None."""
        if depth > FLOW_DEPTH:
            return None
        assigns = [a for a in self.assigns if a.scope == scope and name in a.names]
        if len(assigns) > 1:
            return None
        if len(assigns) == 1:
            assign = assigns[0]
            direct: set[_Source] = {s for s in self._sources(family) if s[2] == assign.line}
            if direct:
                return direct
            if literal:
                local = self._local_literal(assign, name)
                if local is not None:
                    return local
            targets = self.by_name.get(assign.callee or "", [])
            if len(targets) == 1:
                return self._producer(targets[0], family)
            return None
        if scope is None or name not in self.funcs[scope].params:
            constant = self.consts.resolve_full(name, 0) if literal else None
            if constant is not None and isinstance(constant[0], (str, bytes)):
                return {(_literal_length(constant[0]) * 8, constant[2], None)}
            return None
        func = self.funcs[scope]
        position = func.params.index(name)
        sites = self._call_sites(func, scope)
        if not sites:
            return None
        found: set[_Source] = set()
        for line, args in sites:
            arg = _argument_for(args, name, position)
            base = _BASE_IDENT.fullmatch(arg.strip()) if arg else None
            if not base:
                return None
            traced = self.trace(base.group("id"), self.scope_of(line), family, depth + 1, literal)
            if traced is None:
                return None
            found |= traced
        return found

    def _apply_providers(self) -> None:
        """Size a key source (provides_key_size, key_size_from_length) whose key identifier is a local
        literal or reaches a literal through call sites, so consumers can inherit the size."""
        for hit in self.hits:
            family = hit.rule.provides_key_size
            if not family or hit.key_size is not None or not hit.rule.key_size_from_length or not hit.key_arg:
                continue
            traced = self.trace(hit.key_arg, self.scope_of(hit.line), family, 0, True) or set()
            sizes = {size for size, _, _ in traced}
            if len(sizes) == 1:
                hit.key_size = next(iter(sizes))
                hit.key_size_source = "flow"
                lines = [at for _, at, _ in traced if at is not None]
                hit.resolved_from_line = min(lines) if lines else hit.resolved_from_line
                hit.confidence = min(hit.confidence, HEURISTIC_CONFIDENCE_CAP)

    def apply(self) -> None:
        self._apply_providers()
        for hit in self.hits:
            family = hit.rule.inherit_key_size
            if not family or hit.key_size is not None:
                continue
            traced: set[_Source] = set()
            if hit.key_arg:
                traced = (
                    self.trace(hit.key_arg, self.scope_of(hit.line), family, 0, hit.rule.key_size_from_length)
                    or set()
                )
            sizes = {size for size, _, _ in traced}
            generations = {gen for _, _, gen in traced if gen is not None}
            if traced and len(generations) == len({gen for _, _, gen in traced}):
                hit.sink_generations = frozenset(generations)
            if len(sizes) == 1:
                hit.key_size = next(iter(sizes))
                hit.key_size_source = "flow"
                lines = [at for _, at, _ in traced if at is not None]
                hit.resolved_from_line = min(lines) if lines else hit.resolved_from_line
                hit.confidence = min(hit.confidence, HEURISTIC_CONFIDENCE_CAP)
            else:
                hit.key_size_source = "ambiguous" if sizes else "unresolved"
                hit.confidence = min(hit.confidence, UNRESOLVED_CONFIDENCE_CAP)

    def apply_usage(self) -> None:
        """Set usage signature on RSA generations whose every linked sink signs or verifies."""
        linked: dict[int, list[_Hit]] = {}
        for sink in self.hits:
            if sink.rule.inherit_key_size != "RSA":
                continue
            generations = sink.sink_generations
            if generations is None or len(generations) != 1:
                return
            linked.setdefault(next(iter(generations)), []).append(sink)
        for hit in self.hits:
            if hit.rule.provides_key_size != "RSA" or hit.usage != Usage.UNKNOWN:
                continue
            sinks = linked.get(hit.line)
            if sinks and all(s.usage == Usage.SIGNATURE for s in sinks):
                hit.usage = Usage.SIGNATURE
                hit.usage_source = "flow"
                hit.confidence = min(hit.confidence, HEURISTIC_CONFIDENCE_CAP)

    def _literal_lines(self, hit: _Hit, language: str) -> tuple[set[int], bool]:
        """Lines of the string or bytes literals that reach the key argument of `hit`, and whether a
        call-site hop was needed."""
        name = hit.key_arg
        if not name:
            return set(), False
        scope = self.scope_of(hit.line)
        traced = self.trace(name, scope, hit.rule.literal_key or "", 0, True)
        if traced:
            lines = {at for _, at, gen in traced if gen is None and at is not None}
            hopped = (scope is not None and name in self.funcs[scope].params) or any(
                a.scope == scope and name in a.names for a in self.assigns
            )
            return lines, hopped
        assigned = any(a.scope == scope and name in a.names for a in self.assigns)
        if language == "python" and not assigned:
            resolved = self.consts.resolve_full(name, hit.line)
            if resolved and resolved[1] == "param_default" and isinstance(resolved[0], (str, bytes)):
                return ({resolved[2]} if resolved[2] is not None else set()), False
        return set(), False

    def apply_literal_keys(self, language: str) -> list[_Hit]:
        """Keep hard-coded key hits whose key is a literal, moved to the line of that literal."""
        kept: list[_Hit] = []
        for hit in self.hits:
            if not hit.rule.literal_key:
                kept.append(hit)
            elif hit.literal_inline:
                kept.append(hit)
            else:
                lines, hopped = self._literal_lines(hit, language)
                for line in sorted(lines):
                    confidence = min(hit.confidence, HEURISTIC_CONFIDENCE_CAP) if hopped else hit.confidence
                    kept.append(replace(hit, line=line, confidence=confidence))
        return kept

    def _int_of(self, expr: str, line: int) -> int | None:
        """An int literal, or an identifier that resolves to an int constant or parameter default."""
        expr = expr.strip()
        if _INT.fullmatch(expr):
            return _parse_int(expr)
        if _IDENT.fullmatch(expr):
            resolved = self.consts.resolve_full(expr, line)
            if resolved is not None and isinstance(resolved[0], int):
                return resolved[0]
        return None

    def _count_expression(self, hit: _Hit, spec: IterationsSpec, scope: int | None) -> str | None:
        """The source text of the iteration count argument, or None."""
        if spec.loop_param:
            if scope is None:
                return None
            func = self.funcs[scope]
            body = "\n".join(self.lines[func.first - 1 : func.last])
            bounds = {m.group("bound") for m in _LOOP_BOUND.finditer(body) if m.group("bound") in func.params}
            return next(iter(bounds)) if len(bounds) == 1 else None
        if spec.callee is None:
            if hit.call_paren is None:
                return None
            sites = [_call_args(self.masked, hit.call_paren)]
        else:
            sites = []
            for m in re.finditer(rf"(?:{spec.callee.pattern})\s*\(", self.masked):
                line = self.masked.count("\n", 0, m.start()) + 1
                if scope is None or self.funcs[scope].first <= line <= self.funcs[scope].last:
                    sites.append(_call_args(self.masked, m.end() - 1))
        counts = set()
        for args in sites:
            found = None
            if spec.keyword is not None:
                for raw in args:
                    keyword = _KEYWORD_ARG.match(raw)
                    if keyword and keyword.group(1) == spec.keyword:
                        found = keyword.group(2)
            if found is None and spec.arg is not None:
                positional = [a for a in args if not _KEYWORD_ARG.match(a)]
                if spec.arg < len(positional):
                    found = positional[spec.arg]
            if found is None:
                return None
            counts.add(found.strip())
        return counts.pop() if len(counts) == 1 else None

    def _count_absent(self, hit: _Hit, spec: IterationsSpec) -> bool:
        """The call names no iteration count at all (and passes no star arguments that could carry it)."""
        if hit.call_paren is None:
            return False
        args = _call_args(self.masked, hit.call_paren)
        if any(a.strip().startswith("*") for a in args):
            return False
        if spec.keyword is not None:
            for raw in args:
                keyword = _KEYWORD_ARG.match(raw)
                if keyword and keyword.group(1) == spec.keyword:
                    return False
        positional = [a for a in args if not _KEYWORD_ARG.match(a)]
        return spec.arg is None or len(positional) <= spec.arg

    def apply_iterations(self) -> None:
        """Set the iteration count on PBKDF2 hits: literal, constant, or one call-site hop."""
        for hit in self.hits:
            spec = hit.rule.iterations
            if spec is None:
                continue
            scope = self.scope_of(hit.line)
            expr = self._count_expression(hit, spec, scope)
            if expr is None:
                if spec.default is not None and self._count_absent(hit, spec):
                    hit.iterations = spec.default
                    hit.parameter_source = "library_default"
                    hit.confidence = min(hit.confidence, HEURISTIC_CONFIDENCE_CAP)
                continue
            value = self._int_of(expr, hit.line)
            if value is None and scope is not None and expr in self.funcs[scope].params:
                func = self.funcs[scope]
                position = func.params.index(expr)
                values: set[int | None] = set()
                for line, args in self._call_sites(func, scope):
                    arg = _argument_for(args, expr, position)
                    values.add(self._int_of(arg, line) if arg is not None else None)
                if len(values) == 1:
                    value = values.pop()
            hit.iterations = value

    def apply_modes(self) -> None:
        for hit in self.hits:
            if not hit.rule.mode_cases:
                continue
            text = self.context(hit.line)
            for case in hit.rule.mode_cases:
                if all(r.search(text) for r in case.requires) and not any(
                    r.search(text) for r in case.forbids
                ):
                    hit.mode = case.mode
                    hit.mode_source = case.mode_source
                    hit.confidence = min(hit.confidence, HEURISTIC_CONFIDENCE_CAP)
                    break


def _conditions_hold(hits: list[_Hit], masked: str, language: str) -> list[_Hit]:
    """Drop hits whose rule `requires` or `forbids` regexes fail in the file or enclosing function."""
    if not any(h.rule.requires or h.rule.forbids for h in hits):
        return hits
    lines = masked.split("\n")
    funcs = _functions(masked, language) if any(h.rule.scope == "function" for h in hits) else []
    kept = []
    for hit in hits:
        text = masked
        if hit.rule.scope == "function":
            around = [f for f in funcs if f.first <= hit.line <= f.last]
            if around:
                inner = max(around, key=lambda f: f.first)
                text = "\n".join(lines[inner.first - 1 : inner.last])
        if all(r.search(text) for r in hit.rule.requires) and not any(
            r.search(text) for r in hit.rule.forbids
        ):
            kept.append(hit)
    return kept


_NEVER_VISIBLE = frozenset({"key_arg", "literal", "key_literal"})


def _visible_literals(groups: dict[str, str | None]) -> set[str]:
    """Literal group values that may stay readable in a snippet (never a key group)."""
    return {
        value
        for name, value in groups.items()
        if value and name not in _NEVER_VISIBLE and not name.endswith("_ref")
    }


def _drop_absorbed(hits: list[_Hit]) -> list[_Hit]:
    """Drop a hit whose match starts inside the match of a hit of a rule named in its `absorbed_by`."""
    if not any(h.rule.absorbed_by for h in hits):
        return hits
    return [
        hit
        for hit in hits
        if not any(
            other.rule.id in hit.rule.absorbed_by and other.span[0] <= hit.span[0] < other.span[1]
            for other in hits
        )
    ]


def _redact(snippet: str, visible: frozenset[str]) -> str:
    """Replace every string literal except one whose text equals a captured value."""

    def replace(match: re.Match[str]) -> str:
        token = match.group(0)
        inner = token.lstrip("bBrRuUfF")[1:-1]
        return token if inner in visible else "<redacted>"

    return _STRING_LITERAL.sub(replace, snippet)


def scan_source(text: str, file: str, language: str, rules: tuple[Rule, ...] | list[Rule]) -> list[Finding]:
    """Scan one file's text. `file` is the path relative to the scan root, in posix form."""
    masked = mask_comments(text, language)
    if language == "python":
        masked = resolve_aliases(text, masked)
    consts = Constants(masked, language)
    lines = masked.split("\n")
    original = text.split("\n")
    in_test = is_test_path(file)

    hits: list[_Hit] = []
    for rule in rules:
        hits.extend(_match_hits(rule, masked, lines, consts))
    hits = _drop_absorbed(_conditions_hold(hits, masked, language))
    if any(
        h.rule.mode_cases
        or h.rule.literal_key
        or h.rule.iterations
        or (h.rule.inherit_key_size and h.key_size is None)
        for h in hits
    ):
        flow = _Flow(masked, language, hits, consts)
        flow.apply()
        flow.apply_usage()
        flow.apply_modes()
        flow.apply_iterations()
        hits = flow.apply_literal_keys(language)

    for hit in hits:
        if hit.rule.expects_key_size and hit.key_size is None and hit.key_size_source is None:
            hit.key_size_source = "unresolved"
            hit.confidence = min(hit.confidence, UNRESOLVED_CONFIDENCE_CAP)

    findings: dict[str, Finding] = {}
    for hit in sorted(hits, key=lambda h: (h.line, h.rule.id, h.raw_name)):
        if not hit.rule.emit or not hit.raw_name:
            continue
        detector = f"code.{language}.regex:{hit.rule.id}"
        snippet = original[hit.line - 1].strip()
        snippet = _redact(snippet, hit.visible)[:SNIPPET_MAX]
        location = Location(
            source_type=SourceType.CODE,
            file=file,
            line=hit.line,
            snippet=snippet,
        )
        extra: dict[str, Any] = dict(hit.extra if hit.extra is not None else hit.rule.extra)
        extra["rule"] = hit.rule.id
        if hit.mode_source:
            extra["mode_source"] = hit.mode_source
        if hit.usage_source:
            extra["usage_source"] = hit.usage_source
        if hit.resolved_from_line is not None:
            extra["resolved_from_line"] = hit.resolved_from_line
        if hit.iterations is not None:
            extra["iterations"] = hit.iterations
        if hit.parameter_source:
            extra["parameter_source"] = hit.parameter_source
        if hit.key_size_source:
            extra["key_size_source"] = hit.key_size_source
        if hit.unresolved:
            extra["unresolved"] = sorted(hit.unresolved)
        fid = finding_id(detector, hit.raw_name, location)
        findings.setdefault(
            fid,
            Finding(
                id=fid,
                raw_name=hit.raw_name,
                kind_hint=hit.rule.kind_hint,
                usage=hit.usage,
                key_size=hit.key_size,
                curve=hit.curve,
                mode=hit.mode,
                padding=hit.padding,
                library=hit.rule.library,
                language=language,
                in_test_code=in_test,
                detector=detector,
                confidence=hit.confidence,
                location=location,
                extra=extra,
            ),
        )
    return list(findings.values())


# ---------------------------------------------------------------- scanner


@register
class CodeScanner:
    name = "code.regex"
    source_type = SourceType.CODE

    def __init__(self, rules_dir: Path | None = None) -> None:
        self._rules_dir = rules_dir or RULES_DIR

    def can_handle(self, path: Path) -> bool:
        return path.suffix.lower() in LANGUAGE_BY_SUFFIX

    def scan(self, path: Path, root: Path) -> Iterator[Finding | ScanError]:
        language = LANGUAGE_BY_SUFFIX[path.suffix.lower()]
        detector = f"code.{language}.regex"
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                yield ScanError(detector=detector, path=str(path), message="file larger than 5 MB, skipped")
                return
            text = path.read_text(encoding="utf-8", errors="replace")
            rules = load_rules(language, self._rules_dir)
        except (OSError, ValueError, yaml.YAMLError) as exc:
            yield ScanError(detector=detector, path=str(path), message=str(exc))
            return
        try:
            rel = path.relative_to(root).as_posix()
        except ValueError:
            rel = path.name
        yield from scan_source(text, rel, language, rules)
