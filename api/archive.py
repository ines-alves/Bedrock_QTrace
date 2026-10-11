"""Safe intake of a repository as a zip, from an upload or a public GitHub link.

The archive is unpacked into a throwaway folder, scanned like any folder, and deleted. Nothing in it is run.
"""

import hashlib
import re
import shutil
import stat
import threading
import urllib.error
import urllib.request
import zipfile
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import HTTPException

from quantumtrace.models import ScanResult

MAX_ARCHIVE_BYTES = 50 * 1024 * 1024
MAX_UNPACKED_BYTES = 400 * 1024 * 1024
MAX_FILES = 20_000
GITHUB_HOSTS = {"github.com", "codeload.github.com"}
_REPO_URL = re.compile(r"^https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$")
# One archive at a time: the unpack folder is named after the archive's hash, so the same zip scans the same way.
_LOCK = threading.Lock()


def _fail(detail: str, status: int = 400) -> HTTPException:
    return HTTPException(status_code=status, detail=detail)


def github_zip_url(url: str) -> tuple[str, str]:
    """The download link and display label for a public repository link, or a 400 for anything else."""
    match = _REPO_URL.match(url.strip())
    if match is None or any(set(part) <= {"."} for part in match.groups()):
        raise _fail("Use a link like https://github.com/owner/repository")
    owner, repo = match.groups()
    return f"https://github.com/{owner}/{repo}/archive/HEAD.zip", f"{owner}/{repo} (GitHub)"


class _GithubRedirects(urllib.request.HTTPRedirectHandler):
    """GitHub answers with a redirect to codeload; any other destination is refused."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        parts = urlsplit(newurl)
        if parts.scheme != "https" or parts.hostname not in GITHUB_HOSTS:
            raise urllib.error.URLError(f"redirect to {parts.hostname} refused")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(url: str, destination: Path) -> None:
    """Fetch the repository zip, refusing anything bigger than the archive limit."""
    request = urllib.request.Request(url, headers={"User-Agent": "QuantumTrace"})
    try:
        with urllib.request.build_opener(_GithubRedirects).open(request, timeout=30) as response:
            if int(response.headers.get("Content-Length") or 0) > MAX_ARCHIVE_BYTES:
                raise _fail("The repository is larger than the 50 MB limit.", 413)
            written = 0
            with destination.open("wb") as out:
                while chunk := response.read(1024 * 1024):
                    written += len(chunk)
                    if written > MAX_ARCHIVE_BYTES:
                        raise _fail("The repository is larger than the 50 MB limit.", 413)
                    out.write(chunk)
    except urllib.error.HTTPError as error:
        if error.code in (403, 404):
            raise _fail(
                "Repository not found or private. Only public repositories can be scanned."
            ) from error
        raise _fail(f"GitHub answered with HTTP {error.code}.", 502) from error
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise _fail(f"Could not download the repository: {error}", 502) from error


def extract(archive: Path, destination: Path) -> Path:
    """Unpack into destination and return the folder to scan (the single top folder GitHub adds, if any)."""
    root = destination.resolve()
    try:
        with zipfile.ZipFile(archive) as bundle:
            infos = [info for info in bundle.infolist() if not info.filename.startswith("__MACOSX/")]
            if len(infos) > MAX_FILES:
                raise _fail(f"The archive has more than {MAX_FILES} files.", 413)
            if sum(info.file_size for info in infos) > MAX_UNPACKED_BYTES:
                raise _fail("The archive is larger than 400 MB once unpacked.", 413)
            for info in infos:
                if stat.S_ISLNK(info.external_attr >> 16):
                    continue  # links are never unpacked; real repositories use them for shared licence files
                target = (root / info.filename).resolve()
                if not target.is_relative_to(root):
                    raise _fail(f"The archive contains an unsafe path: {info.filename}")
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with bundle.open(info) as source, target.open("wb") as out:
                    shutil.copyfileobj(source, out)
    except zipfile.BadZipFile as error:
        raise _fail("That is not a valid zip file.") from error
    entries = list(root.iterdir())
    return entries[0] if len(entries) == 1 and entries[0].is_dir() else root


def _anonymous(result: ScanResult, target: Path, label: str) -> ScanResult:
    """Replace the server's unpack path with the label, so reports carry no local path."""
    prefixes = [target.as_posix()]
    try:
        prefixes.append(target.relative_to(Path.cwd()).as_posix())
    except ValueError:
        pass
    errors = [
        error.model_copy(
            update={
                "path": next(
                    (error.path.removeprefix(p + "/") for p in prefixes if error.path.startswith(p + "/")),
                    error.path,
                )
            }
        )
        if error.path
        else error
        for error in result.errors
    ]
    return result.model_copy(update={"inputs": [label], "errors": errors})


def scan_zip(archive: Path, label: str, workdir: Path, run: Callable[..., ScanResult]) -> ScanResult:
    """Unpack, scan with the pipeline, delete the unpacked copy and return the result under the label."""
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()[:16]
    destination = workdir / digest
    with _LOCK:
        shutil.rmtree(destination, ignore_errors=True)
        destination.mkdir(parents=True)
        try:
            target = extract(archive, destination)
            result = run([target])
        finally:
            shutil.rmtree(destination, ignore_errors=True)
    return _anonymous(result, target, label)
