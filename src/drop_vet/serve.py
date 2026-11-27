"""Read-only history page, JSON API and gated downloads over the ledger. Bind to loopback."""

from __future__ import annotations

import hashlib
import json
import time
import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path

from drop_vet import ledger
from drop_vet.config import Config


def downloadable(cfg: Config, row: dict) -> Path | None:
    """Only fully scanned, normal-tier files that still sit under ready/."""
    if row.get("verdict") != "ready" or row.get("tier") != "normal" or not row.get("dest"):
        return None
    p = Path(row["dest"]).resolve()
    return p if p.is_relative_to(cfg.ready.resolve()) and p.is_file() else None


def snapshot(cfg: Config) -> dict:
    items = []
    if cfg.ledger.exists():
        for row in ledger.recent(ledger.read_only(cfg.ledger)):
            row["dl"] = downloadable(cfg, row) is not None
            row.pop("dest")
            items.append(row)
    age = time.time() - cfg.sig_stamp.stat().st_mtime if cfg.sig_stamp.exists() else None
    return {
        "items": items,
        "sigs_age_hours": round(age / 3600, 1) if age is not None else None,
        "generated": time.strftime("%Y-%m-%d %H:%M:%S %Z"),
    }


def attachment_name(name: str) -> str:
    base = Path(name).name
    ascii_name = "".join(c if (c.isascii() and c.isalnum()) or c in "._- " else "_" for c in base) or "download"
    return f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{urllib.parse.quote(base)}"


def make_handler(cfg: Config) -> type[BaseHTTPRequestHandler]:
    page = resources.files("drop_vet").joinpath("static/site.html").read_text()

    class Handler(BaseHTTPRequestHandler):
        def _send(self, body: bytes, ctype: str, status: HTTPStatus = HTTPStatus.OK, extra: dict | None = None) -> None:
            self.send_response(status)
            headers = {
                "Content-Type": ctype,
                "Content-Length": str(len(body)),
                "Cache-Control": "no-store",
                "Referrer-Policy": "no-referrer",
                "X-Content-Type-Options": "nosniff",
                **(extra or {}),
            }
            for k, v in headers.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            path = self.path.split("?", 1)[0]
            if path == "/":
                data = json.dumps(snapshot(cfg)).replace("<", "\\u003c")
                self._send(page.replace("__DATA__", data).encode(), "text/html; charset=utf-8")
            elif path == "/api/log.json":
                self._send(json.dumps(snapshot(cfg)).encode(), "application/json")
            elif path.startswith("/file/") and path[6:].isdigit():
                self._file(int(path[6:]))
            elif path == "/healthz":
                self._send(b"ok\n", "text/plain")
            else:
                self._send(b"not found\n", "text/plain", HTTPStatus.NOT_FOUND)

        def _file(self, item_id: int) -> None:
            row = ledger.get(ledger.read_only(cfg.ledger), item_id) if cfg.ledger.exists() else None
            p = downloadable(cfg, row) if row else None
            if not p:
                self._send(b"not available\n", "text/plain", HTTPStatus.NOT_FOUND)
                return
            body = p.read_bytes()
            if hashlib.sha256(body).hexdigest() != row["sha256"]:
                self._send(b"file changed since it was scanned; not served\n", "text/plain", HTTPStatus.CONFLICT)
                return
            self._send(
                body,
                "application/octet-stream",
                extra={
                    "Content-Disposition": attachment_name(row["name"]),
                    "Content-Security-Policy": "sandbox; default-src 'none'",
                },
            )

        def log_message(self, fmt: str, *args: object) -> None:
            print(fmt % args, flush=True)

    return Handler


def serve(cfg: Config) -> None:
    ThreadingHTTPServer((cfg.host, cfg.port), make_handler(cfg)).serve_forever()
