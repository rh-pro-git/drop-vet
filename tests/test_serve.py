from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from collections.abc import Iterator
from http.server import ThreadingHTTPServer

import pytest

from drop_vet import intake, ledger, scanner, serve
from drop_vet.config import Config
from tests.conftest import make_fixtures


@pytest.fixture
def server(cfg: Config) -> Iterator[tuple[str, Config]]:
    intake.ensure_dirs(cfg)
    part = cfg.landing / ".part-1"
    make_fixtures(part)
    part.rename(cfg.landing / "drop-1")
    intake.run(cfg, lambda b, _s: scanner.scan_batch(b, None))
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), serve.make_handler(cfg))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_port}", cfg
    httpd.shutdown()


def get(url: str) -> tuple[int, dict, bytes]:
    try:
        with urllib.request.urlopen(url) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def item_id(cfg: Config, name: str) -> int:
    return next(r["id"] for r in ledger.recent(ledger.read_only(cfg.ledger)) if r["name"] == name)


def test_page_and_api_list_every_item_without_paths(server: tuple[str, Config]) -> None:
    base, _ = server
    status, _, body = get(base + "/")
    assert status == 200 and b"drop-vet history" in body
    status, _, body = get(base + "/api/log.json")
    data = json.loads(body)
    assert status == 200 and len(data["items"]) == 16
    assert all("dest" not in r for r in data["items"])
    assert {r["name"] for r in data["items"] if r["dl"]} == {"clean.pdf", "hello.sh", "notes.md", "letter.docx"}


def test_ready_normal_file_downloads_as_attachment(server: tuple[str, Config]) -> None:
    base, cfg = server
    status, headers, body = get(f"{base}/file/{item_id(cfg, 'clean.pdf')}")
    assert status == 200
    assert body == (cfg.ready / "document/clean.pdf").read_bytes()
    assert headers["Content-Type"] == "application/octet-stream"
    assert headers["Content-Disposition"].startswith('attachment; filename="clean.pdf"')
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["Content-Security-Policy"] == "sandbox; default-src 'none'"


@pytest.mark.parametrize("name", ["pic.png", "ssn.txt", "key.pem", "js.pdf"])
def test_other_tiers_are_never_served(server: tuple[str, Config], name: str) -> None:
    base, cfg = server
    assert get(f"{base}/file/{item_id(cfg, name)}")[0] == 404


@pytest.mark.parametrize("path", ["/file/99999", "/file/../ledger.sqlite", "/file/1%2F..", "/file/-1"])
def test_bad_ids_are_404(server: tuple[str, Config], path: str) -> None:
    base, _ = server
    assert get(base + path)[0] == 404


def test_file_changed_after_release_is_refused(server: tuple[str, Config]) -> None:
    base, cfg = server
    target = cfg.ready / "text/notes.md"
    target.write_text(target.read_text() + "tampered\n")
    assert get(f"{base}/file/{item_id(cfg, 'notes.md')}")[0] == 409


def test_attachment_name_is_header_safe() -> None:
    assert serve.attachment_name("dir/résumé final.pdf") == (
        "attachment; filename=\"r_sum_ final.pdf\"; filename*=UTF-8''r%C3%A9sum%C3%A9%20final.pdf"
    )


def test_empty_root_serves_an_empty_page(cfg: Config) -> None:
    assert serve.snapshot(cfg)["items"] == []
