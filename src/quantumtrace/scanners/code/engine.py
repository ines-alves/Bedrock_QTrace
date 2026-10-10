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
  provides_key_size: <family>                                record this rule's key size for the file
  inherit_key_size: <family>                                 take the file's single key size for <family>
  emit: false                                                record only, produce no finding

Pattern groups: a group named X holds a literal; a group named X_ref holds an identifier that is
resolved through file-scope constants and Python parameter defaults. key_size and key_size_ref are
the size groups.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from quantumtrace.models import Finding, KindHint, Location, ScanError, SourceType, Usage
from quantumtrace.scanners.base import finding_id, is_test_path, register

LANGUAGE_BY_SUFFIX = {".py": "python", ".java": "java", ".go": "go"}
RULES_DIR = Path(__file__).parent / "rules"
MAX_FILE_BYTES = 5 * 1024 * 1024
SNIPPET_MAX = 200
HEURISTIC_CONFIDENCE_CAP = 0.8
UNRESOLVED_CONFIDENCE_CAP = 0.5
ALIAS_DEPTH = 5

_RULE_KEYS = {
    "id", "language", "pattern", "raw_name", "kind_hint", "usage", "confidence",
    "key_size", "key_size_unit", "key_size_from_length", "curve", "mode", "padding", "library",
    "refine", "lookahead_pattern", "lookahead_lines", "provides_key_size", "inherit_key_size", "emit",
}

Value = int | str | bytes


# ---------------------------------------------------------------- rules


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
_GO_DECL = re.compile(
    r"^\s*(?:const|var)\s+(?P<name>[A-Za-z_]\w*)(?:\s+[\w.\[\]*]+)?\s*=\s*(?P<val>.+?)\s*$"
)
_GO_BLOCK_START = re.compile(r"^\s*(?:const|var)\s*\(\s*$")
_GO_BLOCK_END = re.compile(r"^\s*\)\s*$")
_GO_ENTRY = re.compile(r"^\s*(?P<name>[A-Za-z_]\w*)(?:\s+[\w.\[\]*]+)?\s*=\s*(?P<val>.+?)\s*$")
_PY_DEF = re.compile(r"^(?P<indent>[ \t]*)(?:async\s+)?def\s+\w+\s*\(", re.MULTILINE)


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
    parts, depth, current = [], 0, []
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


def _python_scopes(masked: str) -> list[tuple[int, int, dict[str, _Entry]]]:
    """Function extents with their parameter defaults: (first_line, last_line, {param: default})."""
    lines = masked.split("\n")
    scopes = []
    for m in _PY_DEF.finditer(masked):
        depth, j = 1, m.end()
        while j < len(masked) and depth:
            depth += {"(": 1, ")": -1}.get(masked[j], 0)
            j += 1
        params_src = masked[m.end() : j - 1]
        defaults: dict[str, _Entry] = {}
        for param in _split_top_level(params_src):
            pm = re.match(r"^\*{0,2}(?P<n>[A-Za-z_]\w*)\s*(?::[^=]+)?(?:=\s*(?P<d>.+))?$", param, re.S)
            if pm:
                default = pm.group("d")
                defaults[pm.group("n")] = _parse_value(default, "python") if default else None
        first = masked.count("\n", 0, m.start()) + 1
        indent = len(m.group("indent").expandtabs(4))
        last = first
        for k in range(first, len(lines)):
            row = lines[k]
            if row.strip() and len(row) - len(row.lstrip()) <= indent:
                break
            last = k + 1
        scopes.append((first, last, defaults))
    return scopes


class Constants:
    """File-scope constants plus Python function parameter defaults."""

    def __init__(self, masked: str, language: str) -> None:
        self._globals: dict[str, _Entry] = {}
        self._scopes: list[tuple[int, int, dict[str, _Entry]]] = []
        if language == "python":
            for row in masked.split("\n"):
                m = _PY_ASSIGN.match(row)
                if m:
                    self._globals[m.group("name")] = _parse_value(m.group("val"), language)
            self._scopes = sorted(_python_scopes(masked), key=lambda s: s[0], reverse=True)
        elif language == "java":
            for m in _JAVA_FINAL.finditer(masked):
                self._globals[m.group("name")] = _parse_value(m.group("val"), language)
        else:
            in_block = False
            for row in masked.split("\n"):
                if in_block and _GO_BLOCK_END.match(row):
                    in_block = False
                elif _GO_BLOCK_START.match(row):
                    in_block = True
                else:
                    m = (_GO_ENTRY if in_block else _GO_DECL).match(row)
                    if m:
                        self._globals[m.group("name")] = _parse_value(m.group("val"), language)

    def resolve(self, name: str, line: int) -> tuple[Value, str] | None:
        """Resolve an identifier used at `line`. Returns (value, source) or None."""
        entry: _Entry = None
        source = "constant"
        found = False
        for first, last, defaults in self._scopes:
            if first <= line <= last and name in defaults:
                entry, source, found = defaults[name], "param_default", True
                break
        if not found:
            entry = self._globals.get(name)
        for _ in range(ALIAS_DEPTH):
            if not isinstance(entry, _Alias):
                break
            entry = self._globals.get(entry.name)
        if isinstance(entry, (int, str, bytes)):
            return entry, source
        return None


# ---------------------------------------------------------------- matching


@dataclass
class _Hit:
    rule: Rule
    line: int
    raw_name: str
    key_size: int | None
    key_size_source: str | None
    curve: str | None
    mode: str | None
    padding: str | None
    confidence: float
    unresolved: list[str]


def _literal_length(value: Value) -> int:
    return len(value.encode("utf-8")) if isinstance(value, str) else len(value)


def _size_from(
    rule: Rule, groups: dict[str, str | None], consts: Constants, line: int
) -> tuple[int | None, str | None]:
    if rule.key_size is not None:
        return rule.key_size, "literal"
    literal = groups.get("key_size")
    if literal:
        return _parse_int(literal), "literal"
    ref = groups.get("key_size_ref")
    if not ref:
        return None, None
    resolved = consts.resolve(ref, line)
    if resolved is None:
        return None, None
    value, source = resolved
    if isinstance(value, int):
        return (value * 8 if rule.key_size_unit == "bytes" else value), source
    if rule.key_size_from_length:
        return _literal_length(value) * 8, source
    return None, None


class _Template(dict):
    def __missing__(self, key: str) -> str:
        return ""


def _render(template: str | None, values: dict[str, str]) -> str | None:
    if template is None:
        return None
    return template.format_map(_Template(values)).strip() or None


def _match_hits(rule: Rule, masked: str, lines: list[str], consts: Constants) -> Iterator[_Hit]:
    for m in rule.pattern.finditer(masked):
        line = masked.count("\n", 0, m.start()) + 1
        groups: dict[str, str | None] = dict(m.groupdict())
        size, size_source = _size_from(rule, groups, consts, line)

        if size is None and rule.lookahead_pattern is not None:
            window = "\n".join(lines[line - 1 : line + rule.lookahead_lines])
            look = rule.lookahead_pattern.search(window)
            if look:
                look_line = line + window.count("\n", 0, look.start())
                size, _ = _size_from(rule, dict(look.groupdict()), consts, look_line)
                size_source = "lookahead" if size is not None else None

        values: dict[str, str] = {}
        unresolved: list[str] = []
        for name, value in groups.items():
            if value is None or name == "key_size_ref":
                continue
            if name.endswith("_ref"):
                base = name[: -len("_ref")]
                if groups.get(base):
                    continue
                resolved = consts.resolve(value, line)
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
        if size_source == "lookahead":
            confidence = min(confidence, HEURISTIC_CONFIDENCE_CAP)

        yield _Hit(
            rule=rule,
            line=line,
            raw_name=_render(rule.raw_name, values) or "",
            key_size=size,
            key_size_source=size_source,
            curve=_render(rule.curve, values),
            mode=_render(rule.mode, values),
            padding=_render(rule.padding, values),
            confidence=confidence,
            unresolved=unresolved,
        )


def _apply_inheritance(hits: list[_Hit]) -> None:
    """Fill missing key sizes from the file's key-size sources, per family."""
    sources: dict[str, set[int]] = {}
    for hit in hits:
        family = hit.rule.provides_key_size
        if family and hit.key_size is not None:
            sources.setdefault(family, set()).add(hit.key_size)
    for hit in hits:
        family = hit.rule.inherit_key_size
        if not family or hit.key_size is not None:
            continue
        sizes = sources.get(family, set())
        if len(sizes) == 1:
            hit.key_size = next(iter(sizes))
            hit.key_size_source = "file_scope"
            hit.confidence = min(hit.confidence, HEURISTIC_CONFIDENCE_CAP)
        else:
            hit.key_size_source = "ambiguous" if sizes else "unresolved"
            hit.confidence = min(hit.confidence, UNRESOLVED_CONFIDENCE_CAP)


def scan_source(text: str, file: str, language: str, rules: tuple[Rule, ...] | list[Rule]) -> list[Finding]:
    """Scan one file's text. `file` is the path relative to the scan root, in posix form."""
    masked = mask_comments(text, language)
    consts = Constants(masked, language)
    lines = masked.split("\n")
    original = text.split("\n")
    in_test = is_test_path(file)

    hits: list[_Hit] = []
    for rule in rules:
        hits.extend(_match_hits(rule, masked, lines, consts))
    _apply_inheritance(hits)

    for hit in hits:
        if hit.rule.expects_key_size and hit.key_size is None and hit.key_size_source is None:
            hit.key_size_source = "unresolved"
            hit.confidence = min(hit.confidence, UNRESOLVED_CONFIDENCE_CAP)

    findings: dict[str, Finding] = {}
    for hit in sorted(hits, key=lambda h: (h.line, h.rule.id, h.raw_name)):
        if not hit.rule.emit or not hit.raw_name:
            continue
        detector = f"code.{language}.regex:{hit.rule.id}"
        location = Location(
            source_type=SourceType.CODE,
            file=file,
            line=hit.line,
            snippet=original[hit.line - 1].strip()[:SNIPPET_MAX],
        )
        extra: dict[str, Any] = {"rule": hit.rule.id}
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
                usage=hit.rule.usage,
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
