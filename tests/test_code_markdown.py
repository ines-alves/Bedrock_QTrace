"""Markdown executive summary (M3D-08).

ScanResult objects are built by hand; expected text is written from the agreed rendering rules, not from
the renderer's output. Asserts are structural (rows and lines), not whole-document snapshots.
"""

import random

from quantumtrace.models import (
    CryptoAsset,
    Finding,
    KindHint,
    Location,
    Recommendation,
    RiskSummary,
    RoadmapItem,
    ScanError,
    ScanResult,
    SourceType,
    Threat,
    Tier,
    TLSSession,
    Usage,
)
from quantumtrace.output.markdown import render_markdown_summary, write_markdown_summary


def loc(file="src/app.py", line=1, **kw) -> Location:
    return Location(source_type=kw.pop("source_type", SourceType.CODE), file=file, line=line, **kw)


def asset(asset_id, tier=Tier.CRITICAL, occurrences=None, **kw) -> CryptoAsset:
    return CryptoAsset(
        asset_id=asset_id,
        canonical_name=kw.pop("canonical_name", asset_id.upper()),
        family="F",
        asset_type="algorithm",
        primitive="signature",
        usage=kw.pop("usage", Usage.SIGNATURE),
        tier=tier,
        threat=kw.pop("threat", Threat.SHOR),
        rationale="r",
        occurrences=occurrences if occurrences is not None else [loc()],
        **kw,
    )


def finding(fid, raw_name="x", kind=KindHint.ALGORITHM, **kw) -> Finding:
    extra = kw.pop("extra", {})
    location = kw.pop("location", None) or loc()
    return Finding(
        id=fid,
        raw_name=raw_name,
        kind_hint=kind,
        detector="code.python.regex:T",
        location=location,
        extra=extra,
        **kw,
    )


def summary(top_risks=(), **kw) -> RiskSummary:
    base = dict(
        score=42,
        grade="D",
        readiness_pct=12.345,
        counts_by_tier={"CRITICAL": 2, "MEDIUM": 1, "SAFE": 3, "UNKNOWN": 0},
        counts_by_source={"code": {"CRITICAL": 2, "MEDIUM": 1, "SAFE": 3, "UNKNOWN": 0}},
        score_by_source={"code": 42},
        hndl_exposed_count=1,
        top_risks=list(top_risks),
    )
    base.update(kw)
    return RiskSummary(**base)


def result(**kw) -> ScanResult:
    base = dict(
        tool_version="0.1.0",
        scan_id="scan-1",
        started_at="2026-01-01T00:00:00Z",
        finished_at="2026-01-01T00:01:00Z",
        inputs=["sample-repos"],
        findings=[],
        assets=[],
        summary=summary(),
    )
    base.update(kw)
    return ScanResult(**base)


def section(text: str, heading: str) -> list[str]:
    """Lines of one ## section, without the heading."""
    lines = text.split("\n")
    start = lines.index(f"## {heading}") + 1
    end = next((i for i in range(start, len(lines)) if lines[i].startswith("## ")), len(lines))
    return lines[start:end]


def blocks(lines: list[str]) -> list[list[str]]:
    """Blank-line separated blocks of a section."""
    out: list[list[str]] = [[]]
    for line in lines:
        if line:
            out[-1].append(line)
        elif out[-1]:
            out.append([])
    return [b for b in out if b]


def table_rows(lines: list[str]) -> list[str]:
    return [line for line in lines if line.startswith("| ")][2:]


def session(sid, flow="a:1->b:2", tier=Tier.CRITICAL, **kw) -> TLSSession:
    return TLSSession(
        session_id=sid,
        flow=flow,
        sni=None,
        version="TLSv1.2",
        pq_status=kw.pop("pq_status", "classical"),
        verdict_tier=tier,
        source="pcap",
        **kw,
    )


def full_result() -> ScanResult:
    assets = [
        asset(
            "rsa-1024-signature",
            occurrences=[loc("b.py", 9), loc("a.py", 3), loc("a.py", 1), loc("c.go", 7), loc("c.go", 2)],
            canonical_name="RSA-1024",
            hndl_exposed=True,
            classically_broken=True,
            recommendations=[
                Recommendation(action="Z later", target_algorithm=None, standard=None, priority=2),
                Recommendation(
                    action="Use ML-DSA", target_algorithm="ML-DSA-65", standard="FIPS 204", priority=1
                ),
            ],
        ),
        asset(
            "md5",
            tier=Tier.MEDIUM,
            usage=Usage.HASH,
            in_test_code_only=True,
            occurrences=[loc("t/test_a.py", 4)],
        ),
        asset(
            "tls-policy",
            occurrences=[
                Location(
                    source_type=SourceType.LOADBALANCER,
                    resource_id="arn:aws:elasticloadbalancing:x",
                    target="public-alb",
                ),
                Location(
                    source_type=SourceType.PCAP, flow="10.0.0.1:1->10.0.0.2:443", frame=17, sni="a.example"
                ),
            ],
        ),
        asset("aes-256-gcm", tier=Tier.SAFE, occurrences=[loc("s.py", 5)]),
    ]
    findings = [
        finding("w1", "random.getrandbits", extra={"hygiene_only": True, "hygiene_flags": ["insecure_rng"]}),
        finding(
            "w2",
            "random.getrandbits",
            location=loc("other.py", 8),
            extra={"hygiene_only": True, "hygiene_flags": ["insecure_rng"]},
            in_test_code=True,
        ),
        finding(
            "w3",
            "HTTP:80",
            kind=KindHint.PLAINTEXT,
            location=Location(source_type=SourceType.LOADBALANCER, resource_id="arn:lb/web"),
            extra={"hygiene_only": True, "hygiene_flags": ["redirect_only_listener"]},
        ),
        finding(
            "l1",
            "cryptography==46.0.5",
            kind=KindHint.LIBRARY,
            library="cryptography",
            language="python",
            location=loc("python/requirements.txt", 1),
        ),
        finding("c1", "RSA"),
    ]
    return result(
        assets=assets,
        findings=findings,
        sessions=[session("s2", "z:1->y:2", Tier.SAFE, transport="tls"), session("s1")],
        summary=summary(["rsa-1024-signature", "tls-policy", "md5", "aes-256-gcm"]),
        errors=[ScanError(detector="code.manifest", path="req/requirements.txt", message="line 3: x")],
        roadmap=[
            RoadmapItem(phase=1, action="Enable hybrid", asset_ids=["tls-policy"], occurrence_count=2),
            RoadmapItem(
                phase=0, action="Replace broken", asset_ids=["md5", "rsa-1024-signature"], occurrence_count=6
            ),
        ],
    )


def shuffled(r: ScanResult, seed: int) -> ScanResult:
    rng = random.Random(seed)
    data = r.model_copy(deep=True)
    for lst in (data.assets, data.findings, data.sessions, data.errors, data.inputs, data.roadmap or []):
        rng.shuffle(lst)
    for a in data.assets:
        rng.shuffle(a.occurrences)
        rng.shuffle(a.recommendations)
    for item in data.roadmap or []:
        rng.shuffle(item.asset_ids)
    return data


# ---------------------------------------------------------------- determinism


def test_shuffled_unordered_inputs_give_identical_text():
    base = full_result()
    base.inputs = ["z-dir", "a-dir"]
    expected = render_markdown_summary(base)
    for seed in range(5):
        assert render_markdown_summary(shuffled(base, seed)) == expected


def test_same_result_twice_and_trailing_newline():
    r = full_result()
    text = render_markdown_summary(r)
    assert text == render_markdown_summary(r)
    assert text.endswith("\n") and not text.endswith("\n\n")


def test_timestamps_omitted_scan_id_kept():
    text = render_markdown_summary(full_result())
    assert "2026-01-01" not in text
    assert "scan-1" in text
    assert render_markdown_summary(result(scan_id="scan-2")) != render_markdown_summary(result())


# ---------------------------------------------------------------- score and counts


def test_score_counts_and_sources():
    text = render_markdown_summary(full_result())
    score = "\n".join(section(text, "Score"))
    assert "42/100" in score and "Grade: D" in score and "12.3%" in score
    assert "harvest now, decrypt later: 1" in score
    tiers = table_rows(section(text, "Counts by tier"))
    assert tiers == ["| CRITICAL | 2 |", "| MEDIUM | 1 |", "| UNKNOWN | 0 |", "| SAFE | 3 |"]
    assert table_rows(section(text, "Counts by source")) == ["| code | 2 | 1 | 0 | 3 | 42 |"]


# ---------------------------------------------------------------- empty and optional parts


def test_empty_result():
    text = render_markdown_summary(result())
    assert "No ranked risks in this result." in text
    assert "No warnings." in text
    assert "No library findings." in text
    assert "No TLS or SSH sessions in this result." in text
    assert "No scan errors were reported." in text
    assert blocks(section(text, "Report diagnostics")) == [["None."]]
    assert "## Roadmap" not in text


def test_roadmap_none_omitted_and_empty_list_rendered():
    assert "## Roadmap" not in render_markdown_summary(result(roadmap=None))
    lines = section(render_markdown_summary(result(roadmap=[])), "Roadmap")
    assert "No roadmap items." in lines


def test_empty_errors_make_no_coverage_claim():
    lines = "\n".join(section(render_markdown_summary(result()), "Errors and coverage"))
    assert "No scan errors were reported." in lines
    assert "not a statement that every file type was scanned" in lines
    assert "scanned successfully" not in lines


def test_errors_listed_sorted_and_say_incomplete():
    r = result(
        errors=[
            ScanError(detector="z.det", path="b", message="m2"),
            ScanError(detector="a.det", path="a", message="m1"),
        ]
    )
    lines = section(render_markdown_summary(r), "Errors and coverage")
    assert any("2 scan error(s). Coverage is incomplete" in line for line in lines)
    assert table_rows(lines) == ["| a.det | a | m1 |", "| z.det | b | m2 |"]


# ---------------------------------------------------------------- top risks


def test_top_risks_follow_given_order_and_evidence():
    text = render_markdown_summary(full_result())
    rows = table_rows(section(text, "Top risks"))
    assert [r.split(" | ")[1] for r in rows] == [
        "RSA-1024 (rsa-1024-signature)",
        "TLS-POLICY (tls-policy)",
        "MD5 (md5)",
        "AES-256-GCM (aes-256-gcm)",
    ]
    first = rows[0]
    assert "HNDL, classically broken" in first
    assert "code: a.py:1; code: a.py:3; code: b.py:9; +2 more" in first
    assert "Use ML-DSA (target: ML-DSA-65; standard: FIPS 204)" in first
    assert "Z later" not in first


def test_non_file_evidence_is_rendered():
    rows = table_rows(section(render_markdown_summary(full_result()), "Top risks"))
    policy = rows[1]
    assert "loadbalancer: resource arn:aws:elasticloadbalancing:x target public-alb" in policy
    assert "pcap: flow 10.0.0.1:1->10.0.0.2:443 frame 17 sni a.example" in policy


def test_label_adds_parameters_the_name_lacks():
    assets = [
        asset("a1", canonical_name="RSA", key_size=1024),
        asset("a2", canonical_name="RSA-1024", key_size=1024),
        asset("a3", canonical_name="AES", key_size=128, mode="ecb"),
        asset("a4", canonical_name="ECDSA", curve="secp256r1"),
    ]
    r = result(assets=assets, summary=summary(["a1", "a2", "a3", "a4"]))
    rows = table_rows(section(render_markdown_summary(r), "Top risks"))
    assert [row.split(" | ")[1] for row in rows] == [
        "RSA 1024-bit (a1)",
        "RSA-1024 (a2)",
        "AES 128-bit ecb (a3)",
        "ECDSA secp256r1 (a4)",
    ]


def test_warning_shown_when_engine_also_made_it_an_asset():
    """The real engine keeps hygiene findings as UNKNOWN assets; the Warnings section reads findings."""
    f = finding("w", "random.getrandbits", extra={"hygiene_only": True, "hygiene_flags": ["insecure_rng"]})
    a = asset("rng", tier=Tier.UNKNOWN, usage=Usage.RNG, finding_ids=["w"])
    text = render_markdown_summary(result(findings=[f], assets=[a], summary=summary([])))
    assert len(table_rows(section(text, "Warnings"))) == 1
    assert "No ranked risks in this result." in text


def test_test_code_only_asset_is_marked():
    rows = table_rows(section(render_markdown_summary(full_result()), "Top risks"))
    assert "test code only" in rows[2]
    assert "test code only" not in rows[0]


def test_top_risk_missing_from_assets_is_listed_not_replaced():
    r = result(
        assets=[asset("md5"), asset("sha-1")],
        summary=summary(["ghost", "md5", "ghost", "also-missing", "sha-1"]),
    )
    text = render_markdown_summary(r)
    rows = table_rows(section(text, "Top risks"))
    assert [row.split(" | ")[1] for row in rows] == ["MD5 (md5)", "SHA-1 (sha-1)"]
    diag = "\n".join(section(text, "Report diagnostics"))
    assert "ghost, also-missing" in diag
    assert diag.count("ghost") == 1


def test_only_ten_valid_assets_after_resolving():
    ids = [f"a{i:02d}" for i in range(12)]
    r = result(assets=[asset(i) for i in ids], summary=summary(["missing", *ids]))
    text = render_markdown_summary(r)
    rows = table_rows(section(text, "Top risks"))
    assert len(rows) == 10
    assert [row.split(" | ")[1] for row in rows][0] == "A00 (a00)"
    assert "Showing 10 of 12 ranked assets" in text


def test_no_own_ranking_when_top_risks_empty():
    r = result(assets=[asset("md5"), asset("sha-1")], summary=summary([]))
    assert "No ranked risks in this result." in render_markdown_summary(r)


def test_recommendation_tiebreak_treats_missing_as_empty():
    recs = [
        Recommendation(action="Same", target_algorithm="B", standard=None, priority=1),
        Recommendation(action="Same", target_algorithm=None, standard="S", priority=1),
    ]
    r = result(assets=[asset("x", recommendations=recs)], summary=summary(["x"]))
    row = table_rows(section(render_markdown_summary(r), "Top risks"))[0]
    assert "Same (standard: S)" in row


# ---------------------------------------------------------------- warnings and libraries


def test_warnings_cover_all_sources_and_stay_out_of_assets():
    text = render_markdown_summary(full_result())
    rows = table_rows(section(text, "Warnings"))
    assert len(rows) == 2
    rng = next(r for r in rows if r.startswith("| random.getrandbits"))
    assert "| insecure_rng | code | 2 | partly |" in rng
    assert "code: other.py:8; code: src/app.py:1" in rng
    plaintext = next(r for r in rows if r.startswith("| HTTP:80"))
    assert "| redirect_only_listener | loadbalancer | 1 | no |" in plaintext
    assert "random.getrandbits" not in "\n".join(section(text, "Top risks"))


def test_hygiene_flag_false_is_not_a_warning():
    f = finding("w", "x", extra={"hygiene_only": False, "hygiene_flags": ["insecure_rng"]})
    assert "No warnings." in render_markdown_summary(result(findings=[f]))


def test_all_test_code_warning_says_yes():
    f = finding("w", "random.randbytes", in_test_code=True, extra={"hygiene_only": True, "hygiene_flags": []})
    row = table_rows(section(render_markdown_summary(result(findings=[f])), "Warnings"))[0]
    assert "| 1 | yes |" in row


def test_library_inventory():
    rows = table_rows(section(render_markdown_summary(full_result()), "Library inventory"))
    assert rows == ["| cryptography | cryptography==46.0.5 | python | code: python/requirements.txt:1 | no |"]


def test_libraries_sorted_by_name():
    libs = [
        finding("b", "zlib==1", kind=KindHint.LIBRARY, library="zlib", language="python"),
        finding("a", "attrs", kind=KindHint.LIBRARY, library="attrs", language="python"),
    ]
    rows = table_rows(section(render_markdown_summary(result(findings=libs)), "Library inventory"))
    assert [r.split(" | ")[0] for r in rows] == ["| attrs", "| zlib"]


# ---------------------------------------------------------------- sessions


def test_sessions_counts_and_detail_order():
    counts, detail = blocks(section(render_markdown_summary(full_result()), "TLS and SSH sessions"))
    assert table_rows(counts) == ["| tls | classical | CRITICAL | 1 |", "| tls | classical | SAFE | 1 |"]
    assert [r.split(" | ")[0] for r in table_rows(detail)] == ["| CRITICAL", "| SAFE"]
    assert not any(line.startswith("Showing") for line in detail)


def test_sessions_truncated_and_stated():
    sessions = [session(f"s{i:02d}", flow=f"f{i:02d}") for i in range(13)]
    text = render_markdown_summary(result(sessions=sessions))
    lines = section(text, "TLS and SSH sessions")
    assert "Showing 10 of 13 sessions" in "\n".join(lines)
    assert "| tls | classical | CRITICAL | 13 |" in lines


# ---------------------------------------------------------------- roadmap


def test_roadmap_phases_labels_and_assets():
    text = render_markdown_summary(full_result())
    lines = section(text, "Roadmap")
    assert "Phases are project planning targets, not regulatory deadlines." in lines
    headings = [line for line in lines if line.startswith("### ")]
    assert headings == ["### Phase 0: this week", "### Phase 1: now"]
    bullets = [line for line in lines if line.startswith("- ")]
    assert bullets[0] == (
        "- Replace broken: 6 occurrence(s); assets: MD5 (md5), RSA-1024 (rsa-1024-signature)"
    )
    assert "TLS-POLICY (tls-policy)" in bullets[1]


def test_roadmap_unknown_asset_id_is_flagged():
    r = result(roadmap=[RoadmapItem(phase=2, action="A", asset_ids=["gone"], occurrence_count=1)])
    text = render_markdown_summary(r)
    assert "gone (not in assets)" in text
    assert "Roadmap asset ids with no matching asset: gone" in text


# ---------------------------------------------------------------- escaping and writing


def test_pipes_newlines_and_html_are_escaped_in_cells():
    r = result(
        assets=[asset("x", canonical_name="a|b\nc<script>", occurrences=[loc("dir/f|g.py", 1)])],
        summary=summary(["x"]),
        errors=[ScanError(detector="d", path="p|q", message="one\ntwo | three")],
    )
    text = render_markdown_summary(r)
    row = table_rows(section(text, "Top risks"))[0]
    assert "a\\|b c&lt;script> (x)" in row
    assert "dir/f\\|g.py:1" in row
    err = table_rows(section(text, "Errors and coverage"))[0]
    assert err == "| d | p\\|q | one two \\| three |"
    table = [line for line in section(text, "Top risks") if line.startswith("| ")]
    assert len({line.replace("\\|", "").count("|") for line in table}) == 1


def test_snippets_never_printed():
    f = finding("w", "k", location=loc(snippet="SECRET-SNIPPET"), extra={"hygiene_only": True})
    a = asset("x", occurrences=[loc(snippet="SECRET-SNIPPET")])
    text = render_markdown_summary(result(findings=[f], assets=[a], summary=summary(["x"])))
    assert "SECRET-SNIPPET" not in text


def test_write_creates_parents_and_matches_render(tmp_path):
    r = full_result()
    target = tmp_path / "out" / "nested" / "summary.md"
    write_markdown_summary(r, target)
    raw = target.read_bytes()
    assert raw.decode("utf-8") == render_markdown_summary(r)
    assert b"\r" not in raw and raw.endswith(b"\n")


def test_write_accepts_string_path(tmp_path):
    write_markdown_summary(result(), str(tmp_path / "s.md"))
    assert (tmp_path / "s.md").read_text(encoding="utf-8").startswith("# QuantumTrace summary")
