"""Dependency manifest scanner: library findings from requirements*.txt, pom.xml and go.mod (M3D-07).

A library finding states that a cryptographic library is declared in a direct dependency list. It does not
state that the library is used or vulnerable, and it carries no tier. Only identities in
rules/libraries.yaml are reported. Nothing is resolved: no transitive dependencies, no network.

Finding shape (M3M4-05): kind_hint library, usage unknown, raw_name `name==version` for an exact pin and
`name` alone otherwise (a version is never invented), library the package identity as written, language
python, java or go, detector `code.<language>.manifest`, confidence 1.0, snippet the declaration as
written, so a range or a property stays visible. Maven names are `groupId:artifactId`, Go names are
module paths and `// indirect` is kept in the snippet.

Constructs that hide a dependency from this scanner (requirements includes, editable and URL
requirements, Maven coordinates built from unresolved properties, Go replace directives that touch an
allowlisted module) are yielded as ScanError so the coverage is never reported as complete. Their
messages carry the line number and the kind of construct, never the text of the line.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from xml.parsers import expat

import yaml

from quantumtrace.models import Finding, KindHint, Location, ScanError, SourceType, Usage
from quantumtrace.scanners.base import finding_id, is_test_path, register
from quantumtrace.scanners.code.engine import MAX_FILE_BYTES, RULES_DIR, SNIPPET_MAX

LIBRARIES_FILE = "libraries.yaml"
ECOSYSTEMS = ("python", "java", "go")
RULE_IDS = {"python": "PY_LIBRARY", "java": "JAVA_LIBRARY", "go": "GO_LIBRARY"}
PROPERTY_DEPTH = 5

_REQUIREMENTS_NAME = re.compile(r"^(?:.*[-_])?requirements(?:[-_].+)?\.txt$")
_PY_REQUIREMENT = re.compile(
    r"^(?P<name>[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(?:\[[^\]]*\])?\s*(?P<rest>.*)$"
)
_PY_PIN = re.compile(r"^==\s*(?P<version>[^\s,;*=!<>~]+)$")
_PY_URL = re.compile(r"^(?:[A-Za-z][A-Za-z0-9+.-]*://|\.{1,2}/|/|file:)")
_GO_DIRECTIVE = re.compile(r"^(?P<word>require|replace|exclude|retract)\s*(?P<open>\()?\s*(?P<rest>.*)$")
_PROPERTY = re.compile(r"\$\{([^}]+)\}")

_POM_DEPENDENCY_PATHS = {
    ("project", "dependencies", "dependency"),
    ("project", "profiles", "profile", "dependencies", "dependency"),
}
_POM_FIELDS = {"groupId", "artifactId", "version"}


# ---------------------------------------------------------------- allowlist


def _normalize_python(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


@lru_cache(maxsize=None)
def load_libraries(rules_dir: Path = RULES_DIR) -> dict[str, frozenset[str]]:
    """Load rules/libraries.yaml: ecosystem -> exact identities. Raises ValueError when malformed."""
    path = rules_dir / LIBRARIES_FILE
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict) or set(data) - set(ECOSYSTEMS):
        raise ValueError(f"{path}: expected a mapping with keys {list(ECOSYSTEMS)}")
    libraries: dict[str, frozenset[str]] = {}
    for ecosystem in ECOSYSTEMS:
        names = data.get(ecosystem) or []
        if not isinstance(names, list) or not all(isinstance(n, str) and n for n in names):
            raise ValueError(f"{path}: {ecosystem} must be a list of names")
        if ecosystem == "python":
            names = [_normalize_python(n) for n in names]
        libraries[ecosystem] = frozenset(names)
    return libraries


# ---------------------------------------------------------------- parsed declarations


@dataclass(frozen=True)
class _Declaration:
    line: int
    name: str
    version: str | None
    snippet: str


@dataclass(frozen=True)
class _Unsupported:
    line: int
    message: str


def _snippet(text: str) -> str:
    return text.strip()[:SNIPPET_MAX]


def _parse_requirements(text: str, allowed: frozenset[str]) -> tuple[list[_Declaration], list[_Unsupported]]:
    declarations: list[_Declaration] = []
    problems: list[_Unsupported] = []
    lines = text.split("\n")
    i = 0
    while i < len(lines):
        start = i + 1
        first = lines[i].rstrip("\r")
        logical = first
        while logical.rstrip().endswith("\\") and i + 1 < len(lines):
            i += 1
            logical = logical.rstrip()[:-1] + " " + lines[i].rstrip("\r")
        i += 1
        stripped = re.sub(r"(?:^|\s)#.*$", "", logical).strip().rstrip("\\").strip()
        if not stripped:
            continue
        if stripped.startswith("-"):
            option = stripped.split(None, 1)[0].split("=", 1)[0]
            if option in ("-r", "--requirement", "-c", "--constraint"):
                problems.append(_Unsupported(start, "included requirements file not followed"))
            elif option in ("-e", "--editable"):
                problems.append(_Unsupported(start, "editable requirement not scanned"))
            continue
        if _PY_URL.match(stripped):
            problems.append(_Unsupported(start, "URL or path requirement not scanned"))
            continue
        match = _PY_REQUIREMENT.match(stripped)
        if match is None:
            problems.append(_Unsupported(start, "requirement line not understood"))
            continue
        name = match.group("name")
        rest = re.split(r"\s+--", match.group("rest"))[0].split(";")[0].strip()
        if rest.startswith("@"):
            if _normalize_python(name) in allowed:
                problems.append(_Unsupported(start, f"direct reference requirement not scanned: {name}"))
            continue
        pin = _PY_PIN.match(rest)
        declarations.append(
            _Declaration(start, name, pin.group("version") if pin else None, _snippet(first.rstrip("\\")))
        )
    return declarations, problems


def _parse_go_mod(text: str, allowed: frozenset[str]) -> tuple[list[_Declaration], list[_Unsupported]]:
    declarations: list[_Declaration] = []
    problems: list[_Unsupported] = []
    block: str | None = None

    def handle(word: str, body: str, lineno: int, raw: str) -> None:
        parts = body.split()
        if not parts:
            return
        if word == "require" and len(parts) >= 2:
            declarations.append(_Declaration(lineno, parts[0].strip('"`'), parts[1], _snippet(raw)))
        elif word == "replace" and (module := parts[0].strip('"`')) in allowed:
            problems.append(_Unsupported(lineno, f"replace directive not applied: {module}"))

    for lineno, raw in enumerate(text.split("\n"), start=1):
        body = raw.split("//", 1)[0].strip()
        if block is not None:
            if body == ")":
                block = None
            elif body:
                handle(block, body, lineno, raw)
            continue
        match = _GO_DIRECTIVE.match(body)
        if match is None:
            continue
        if match.group("open"):
            block = match.group("word")
            if match.group("rest"):
                handle(block, match.group("rest"), lineno, raw)
        else:
            handle(match.group("word"), match.group("rest"), lineno, raw)
    return declarations, problems


def _substitute(value: str, props: dict[str, str]) -> str:
    for _ in range(PROPERTY_DEPTH):
        new = _PROPERTY.sub(lambda m: props.get(m.group(1), m.group(0)), value)
        if new == value:
            break
        value = new
    return value


def _parse_pom(text: str) -> tuple[list[_Declaration], list[_Unsupported]]:
    """Direct dependencies of project and profiles. dependencyManagement and plugin dependencies are not."""
    parser = expat.ParserCreate()
    stack: list[str] = []
    lines: list[int] = []
    buffer: list[str] = []
    props: dict[str, str] = {}
    raw_deps: list[dict[str, tuple[int, str]]] = []
    current: dict[str, tuple[int, str]] | None = None
    dep_depth = 0

    def start(name: str, attrs: dict[str, str]) -> None:
        nonlocal current, dep_depth
        stack.append(name)
        lines.append(parser.CurrentLineNumber)
        buffer.clear()
        if tuple(stack) in _POM_DEPENDENCY_PATHS:
            current = {}
            dep_depth = len(stack)

    def end(name: str) -> None:
        nonlocal current
        path = tuple(stack)
        value = "".join(buffer).strip()
        if current is not None and len(path) == dep_depth + 1 and name in _POM_FIELDS:
            current[name] = (lines[-1], value)
        elif path in _POM_DEPENDENCY_PATHS and current is not None:
            raw_deps.append(current)
            current = None
        elif len(path) == 3 and path[:2] == ("project", "properties"):
            props[name] = value
        elif path == ("project", "version"):
            props["project.version"] = value
        stack.pop()
        lines.pop()
        buffer.clear()

    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.CharacterDataHandler = buffer.append
    parser.Parse(text, True)

    declarations: list[_Declaration] = []
    problems: list[_Unsupported] = []
    for dep in raw_deps:
        if "groupId" not in dep or "artifactId" not in dep:
            continue
        group = dep["groupId"][1]
        line, artifact = dep["artifactId"]
        declared = dep.get("version", (line, ""))[1]
        group_r, artifact_r = _substitute(group, props), _substitute(artifact, props)
        if "${" in group_r or "${" in artifact_r:
            problems.append(_Unsupported(line, "dependency coordinates use an unresolved property"))
            continue
        version = _substitute(declared, props) if declared else ""
        pinned = bool(version) and "${" not in version and not re.match(r"^[\[(]|,", version)
        snippet = f"{group}:{artifact}" + (f":{declared}" if declared else "")
        declarations.append(
            _Declaration(line, f"{group_r}:{artifact_r}", version if pinned else None, _snippet(snippet))
        )
    return declarations, problems


# ---------------------------------------------------------------- scanner


@register
class ManifestScanner:
    name = "code.manifest"
    source_type = SourceType.CODE

    def __init__(self, rules_dir: Path | None = None) -> None:
        self._rules_dir = rules_dir or RULES_DIR

    def can_handle(self, path: Path) -> bool:
        name = path.name.lower()
        return name in ("pom.xml", "go.mod") or _REQUIREMENTS_NAME.match(name) is not None

    def scan(self, path: Path, root: Path) -> Iterator[Finding | ScanError]:
        name = path.name.lower()
        language = "go" if name == "go.mod" else "java" if name == "pom.xml" else "python"
        detector = f"code.{language}.manifest"
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                yield ScanError(detector=detector, path=str(path), message="file larger than 5 MB, skipped")
                return
            text = path.read_text(encoding="utf-8", errors="replace")
            allowed = load_libraries(self._rules_dir)[language]
        except (OSError, ValueError, yaml.YAMLError) as exc:
            yield ScanError(detector=detector, path=str(path), message=str(exc))
            return
        try:
            declarations, problems = self._parse(language, text, allowed)
        except expat.ExpatError as exc:
            yield ScanError(detector=detector, path=str(path), message=f"not well-formed XML: {exc}")
            return
        try:
            rel = path.relative_to(root).as_posix()
        except ValueError:
            rel = path.name

        in_test = is_test_path(rel)
        findings: dict[str, Finding] = {}
        for decl in declarations:
            identity = _normalize_python(decl.name) if language == "python" else decl.name
            if identity not in allowed:
                continue
            raw_name = f"{decl.name}=={decl.version}" if decl.version else decl.name
            location = Location(source_type=SourceType.CODE, file=rel, line=decl.line, snippet=decl.snippet)
            fid = finding_id(detector, raw_name, location)
            findings.setdefault(
                fid,
                Finding(
                    id=fid,
                    raw_name=raw_name,
                    kind_hint=KindHint.LIBRARY,
                    usage=Usage.UNKNOWN,
                    library=decl.name,
                    language=language,
                    in_test_code=in_test,
                    detector=detector,
                    location=location,
                    extra={"rule": RULE_IDS[language]},
                ),
            )
        yield from sorted(findings.values(), key=lambda f: (f.location.line or 0, f.raw_name))
        for problem in sorted(problems, key=lambda p: (p.line, p.message)):
            yield ScanError(
                detector=detector, path=str(path), message=f"line {problem.line}: {problem.message}"
            )

    @staticmethod
    def _parse(
        language: str, text: str, allowed: frozenset[str]
    ) -> tuple[list[_Declaration], list[_Unsupported]]:
        if language == "go":
            return _parse_go_mod(text, allowed)
        if language == "java":
            return _parse_pom(text)
        return _parse_requirements(text, allowed)
