from __future__ import annotations

import base64
import os
import socket
import zipfile
from pathlib import Path

import pytest

from drop_vet import config

_real_connect = socket.socket.connect


@pytest.fixture(autouse=True)
def no_outbound(monkeypatch: pytest.MonkeyPatch) -> None:
    """Tests never reach the network. Loopback stays open for the serve tests."""

    def connect(self: socket.socket, address: object) -> None:
        host = address[0] if isinstance(address, tuple) else str(address)
        if host not in ("127.0.0.1", "::1", "localhost"):
            raise RuntimeError(f"outbound connection refused in tests: {host}")
        _real_connect(self, address)

    monkeypatch.setattr(socket.socket, "connect", connect)


@pytest.fixture
def cfg(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> config.Config:
    monkeypatch.setenv("DROP_VET_ROOT", str(tmp_path / "root"))
    monkeypatch.setenv("DROP_VET_SENSITIVE_DIR", str(tmp_path / "vault"))
    monkeypatch.setenv("DROP_VET_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("DROP_VET_CLAMAV_DB", str(tmp_path / "sigs"))
    monkeypatch.delenv("DROP_VET_NOTIFY_CMD", raising=False)
    c = config.load()
    (tmp_path / "vault").mkdir()
    c.sig_stamp.parent.mkdir(parents=True)
    c.sig_stamp.touch()
    return c


def make_pdf(path: Path, text: str = "", extra_cat: bytes = b"", extra_obj: bytes = b"") -> None:
    body = text or "Quarterly notes for the garden club meeting, with enough words to form a text layer."
    content = b"BT /F1 12 Tf 72 720 Td (" + body.encode() + b") Tj ET"
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R" + extra_cat + b" >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R"
        b" /Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length %d >>\nstream\n" % len(content) + content + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ] + ([extra_obj] if extra_obj else [])
    out, offs = b"%PDF-1.4\n", []
    for i, o in enumerate(objs, 1):
        offs.append(len(out))
        out += b"%d 0 obj\n" % i + o + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1) + b"".join(b"%010d 00000 n \n" % o for o in offs)
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref)
    path.write_bytes(out)


def make_fixtures(d: Path) -> None:
    """Invented test files, one per scanner outcome. Nothing here is real data."""
    d.mkdir(parents=True, exist_ok=True)
    make_pdf(d / "clean.pdf")
    make_pdf(d / "js.pdf", extra_cat=b" /OpenAction 6 0 R", extra_obj=b"<< /Type /Action /S /JavaScript /JS (x) >>")
    (d / "key.pem").write_text(
        "-----BEGIN OPENSSH PRIVATE KEY-----\n" + base64.b64encode(os.urandom(120)).decode() + "\n"
    )
    (d / "ssn.txt").write_text("Test record. SSN 123-45-6789. Not real.\n")
    (d / "utf16-ssn.txt").write_bytes("Test record. SSN 123-45-6789. Not real.".encode("utf-16"))
    (d / "hello.sh").write_text("#!/bin/sh\necho hello\n")
    (d / "hello.sh").chmod(0o755)
    (d / "notes.md").write_text("# Notes\nnothing special here\n")
    (d / "pic.png").write_bytes(
        base64.b64decode(
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
        )
    )
    with zipfile.ZipFile(d / "bad.zip", "w") as z:
        z.writestr("readme.txt", "hi")
        z.writestr("setup.exe", "MZfake")
    with zipfile.ZipFile(d / "fake-office.zip", "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml", "<w>hello</w>")
        z.writestr("setup.exe", "MZfake")
    with zipfile.ZipFile(d / "letter.docx", "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml", "<w:t>Dear neighbour, the fence repair is booked.</w:t>")
    with zipfile.ZipFile(d / "macro.docx", "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml", "<w:t>hi</w:t>")
        z.writestr("word/vbaProject.bin", "fake")
    (d / "tool.exe").write_bytes(b"MZ" + b"\x00" * 64)
    (d / "elf-tool").write_bytes(b"\x7fELF\x02\x01\x01" + b"\x00" * 120)
    (d / "token.txt").write_text("deploy token ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8" + "\n")
    (d / "link").symlink_to("/etc/hostname")


EXPECTED = {
    "clean.pdf": ("ready", "normal", []),
    "js.pdf": ("rejected", None, ["pdf_active"]),
    "key.pem": ("held", None, []),
    "ssn.txt": ("ready", "sensitive", []),
    "utf16-ssn.txt": ("ready", "sensitive", []),
    "hello.sh": ("ready", "normal", []),
    "notes.md": ("ready", "normal", []),
    "pic.png": ("ready", "unverified", ["image_not_text_scanned"]),
    "bad.zip": ("rejected", None, ["archive_member_denied"]),
    "fake-office.zip": ("rejected", None, ["archive_member_denied"]),
    "letter.docx": ("ready", "normal", []),
    "macro.docx": ("rejected", None, ["office_macro"]),
    "tool.exe": ("rejected", None, ["denied_extension"]),
    "elf-tool": ("rejected", None, ["disallowed_type"]),
    "token.txt": ("held", None, []),
    "link": ("rejected", None, ["symlink"]),
}
