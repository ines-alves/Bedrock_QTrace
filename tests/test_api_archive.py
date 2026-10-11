"""Scanning a repository from a zip or a GitHub link: safe unpacking, strict links and no server paths in results."""

import io
import sys
import types
import urllib.error
import zipfile
from pathlib import Path

import pytest
from fastapi import HTTPException, UploadFile

import api.main as main
from api import archive
from quantumtrace.models import ScanError, ScanResult


def _zip(path: Path, files: dict[str, str], *, symlink: str | None = None) -> Path:
    with zipfile.ZipFile(path, "w") as bundle:
        for name, text in files.items():
            bundle.writestr(name, text)
        if symlink:
            link = zipfile.ZipInfo(symlink)
            link.external_attr = 0o120777 << 16
            bundle.writestr(link, "target")
    return path


def _rejected(path: Path, tmp_path: Path) -> str:
    with pytest.raises(HTTPException) as error:
        archive.extract(path, tmp_path / "out")
    assert error.value.status_code in (400, 413)
    return error.value.detail


def test_unsafe_paths_are_refused(tmp_path: Path):
    assert "unsafe path" in _rejected(_zip(tmp_path / "a.zip", {"../evil.txt": "x"}), tmp_path)
    assert "unsafe path" in _rejected(_zip(tmp_path / "b.zip", {"/etc/evil.txt": "x"}), tmp_path)
    assert not (tmp_path / "evil.txt").exists()


def test_symbolic_links_are_skipped_not_unpacked(tmp_path: Path):
    bundle = _zip(tmp_path / "c.zip", {"ok.py": "x"}, symlink="link")
    target = archive.extract(bundle, tmp_path / "out")
    assert sorted(p.name for p in target.iterdir()) == ["ok.py"]


def test_size_and_file_limits(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    many = _zip(tmp_path / "many.zip", {f"f{i}.py": "x" for i in range(3)})
    monkeypatch.setattr(archive, "MAX_FILES", 2)
    assert "more than 2 files" in _rejected(many, tmp_path)
    monkeypatch.setattr(archive, "MAX_FILES", 100)
    monkeypatch.setattr(archive, "MAX_UNPACKED_BYTES", 5)
    assert "400 MB" in _rejected(_zip(tmp_path / "big.zip", {"a.py": "0123456789"}), tmp_path)


def test_not_a_zip(tmp_path: Path):
    (tmp_path / "x.zip").write_text("plain text")
    assert "not a valid zip" in _rejected(tmp_path / "x.zip", tmp_path)


def test_single_top_folder_becomes_the_scan_target(tmp_path: Path):
    nested = _zip(tmp_path / "n.zip", {"repo-main/a.py": "x", "repo-main/b/c.py": "y", "__MACOSX/._a": "z"})
    assert archive.extract(nested, tmp_path / "one") == (tmp_path / "one" / "repo-main").resolve()
    flat = _zip(tmp_path / "f.zip", {"a.py": "x", "b.py": "y"})
    assert archive.extract(flat, tmp_path / "two") == (tmp_path / "two").resolve()


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/octocat/Hello-World",
        "https://github.com/octocat/Hello-World/",
        "https://github.com/octocat/Hello-World.git",
        " https://github.com/octocat/Hello-World ",
    ],
)
def test_github_links_become_one_download_url(url: str):
    assert archive.github_zip_url(url) == (
        "https://github.com/octocat/Hello-World/archive/HEAD.zip",
        "octocat/Hello-World (GitHub)",
    )


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/octocat/Hello-World",
        "https://gitlab.com/octocat/Hello-World",
        "https://github.com.evil.example/octocat/Hello-World",
        "https://user@github.com/octocat/Hello-World",
        "https://github.com/octocat",
        "https://github.com/octocat/Hello-World/tree/main",
        "https://github.com/../Hello-World",
        "file:///etc/passwd",
        "",
    ],
)
def test_other_links_are_refused(url: str):
    with pytest.raises(HTTPException) as error:
        archive.github_zip_url(url)
    assert error.value.status_code == 400


def test_redirects_leave_only_to_github_hosts():
    handler = archive._GithubRedirects()
    with pytest.raises(urllib.error.URLError):
        handler.redirect_request(None, None, 302, "Found", {}, "https://169.254.169.254/latest")
    with pytest.raises(urllib.error.URLError):
        handler.redirect_request(None, None, 302, "Found", {}, "http://codeload.github.com/x")


def _stub_pipeline(monkeypatch: pytest.MonkeyPatch, sample: ScanResult) -> list[Path]:
    scanned: list[Path] = []
    module = types.ModuleType("quantumtrace.pipeline")

    def run(inputs: list[Path]) -> ScanResult:
        scanned.append(inputs[0])
        assert inputs[0].is_dir() and (inputs[0] / "app.py").exists()
        error = ScanError(detector="pipeline", path=f"{inputs[0].as_posix()}/bad.json", message="x")
        return sample.model_copy(update={"inputs": [inputs[0].as_posix()], "errors": [error]})

    module.run = run  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "quantumtrace.pipeline", module)
    return scanned


@pytest.fixture
def sample(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> ScanResult:
    monkeypatch.setattr(main, "REPORT", tmp_path / "out" / "report.json")
    monkeypatch.setattr(main, "UPLOADS", tmp_path / "uploads")
    return ScanResult.model_validate_json(main.SAMPLE.read_text())


def test_upload_is_scanned_cleaned_up_and_free_of_server_paths(
    sample: ScanResult, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    scanned = _stub_pipeline(monkeypatch, sample)
    data = tmp_path / "r.zip"
    _zip(data, {"repo-main/app.py": "import hashlib"})
    result = main.scan_upload(UploadFile(file=io.BytesIO(data.read_bytes()), filename="../../repo.zip"))
    assert result.inputs == ["repo.zip (uploaded)"]
    assert [error.path for error in result.errors] == ["bad.json"]
    assert str(tmp_path) not in result.model_dump_json()
    assert not scanned[0].exists() and not any((tmp_path / "uploads").iterdir())
    assert main.source() == {"source": "scan"}


def test_github_link_downloads_then_scans(
    sample: ScanResult, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    _stub_pipeline(monkeypatch, sample)
    seen: list[str] = []

    def fake_download(url: str, destination: Path) -> None:
        seen.append(url)
        _zip(destination, {"Hello-World-abc/app.py": "x"})

    monkeypatch.setattr(archive, "download", fake_download)
    result = main.scan_github(main.GithubRequest(url="https://github.com/octocat/Hello-World"))
    assert seen == ["https://github.com/octocat/Hello-World/archive/HEAD.zip"]
    assert result.inputs == ["octocat/Hello-World (GitHub)"]


def test_oversized_upload_is_refused(sample: ScanResult, monkeypatch: pytest.MonkeyPatch):
    _stub_pipeline(monkeypatch, sample)
    monkeypatch.setattr(archive, "MAX_ARCHIVE_BYTES", 10)
    with pytest.raises(HTTPException) as error:
        main.scan_upload(UploadFile(file=io.BytesIO(b"x" * 100), filename="big.zip"))
    assert error.value.status_code == 413


def test_clear_scan_forgets_the_report_and_leaves_the_dashboard_empty(
    sample: ScanResult, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    uploads = tmp_path / "out" / "uploads"
    uploads.mkdir(parents=True)
    (uploads / "leftover").write_text("x")
    monkeypatch.setattr(main, "UPLOADS", uploads)
    main.REPORT.parent.mkdir(exist_ok=True)
    main.REPORT.write_text(sample.model_copy(update={"scan_id": "live"}).model_dump_json())
    assert main.source() == {"source": "scan"}
    assert main.clear_scan() == {"source": "none"}
    assert main.source() == {"source": "none"}
    assert not main.REPORT.exists() and not uploads.exists()
    with pytest.raises(HTTPException) as error:
        main.result()
    assert error.value.status_code == 404
    assert main.clear_scan() == {"source": "none"}  # clearing twice is harmless


def test_upload_takes_the_same_types(sample: ScanResult, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    seen: list[object] = []
    module = types.ModuleType("quantumtrace.pipeline")

    def run(inputs, probes=None, options=None):
        seen.append(None if options is None else options.scanner_names)
        return sample

    module.run = run  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "quantumtrace.pipeline", module)
    data = tmp_path / "r.zip"
    _zip(data, {"repo-main/app.py": "import hashlib"})
    main.scan_upload(UploadFile(file=io.BytesIO(data.read_bytes()), filename="r.zip"), "code")
    main.scan_upload(UploadFile(file=io.BytesIO(data.read_bytes()), filename="r.zip"))
    assert seen == [["code.manifest", "code.regex", "config.keyfile", "config.webserver"], None]
    with pytest.raises(HTTPException) as error:
        main.scan_upload(UploadFile(file=io.BytesIO(data.read_bytes()), filename="r.zip"), "cloud,nope")
    assert error.value.status_code == 400


def test_github_scan_takes_types(sample: ScanResult, monkeypatch: pytest.MonkeyPatch):
    seen: list[object] = []
    module = types.ModuleType("quantumtrace.pipeline")

    def run(inputs, probes=None, options=None):
        seen.append(None if options is None else options.scanner_names)
        return sample

    module.run = run  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "quantumtrace.pipeline", module)
    monkeypatch.setattr(archive, "download", lambda url, path: _zip(path, {"r-main/app.py": "x"}))
    main.scan_github(main.GithubRequest(url="https://github.com/owner/repo", types=["network"]))
    assert seen == [["pcap"]]
