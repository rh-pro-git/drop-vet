from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from drop_vet import sandbox, scanner
from tests.conftest import EXPECTED, make_fixtures, make_pdf


def test_every_fixture_gets_its_verdict(tmp_path: Path) -> None:
    make_fixtures(tmp_path)
    got = {r["rel"]: r for r in scanner.scan_batch(tmp_path, None)}
    for name, (verdict, tier, reasons) in EXPECTED.items():
        r = got[name]
        assert (r["verdict"], r.get("tier"), r["reasons"]) == (verdict, tier, reasons), name


def test_held_and_rejected_record_the_scanned_hash(tmp_path: Path) -> None:
    make_fixtures(tmp_path)
    got = {r["rel"]: r for r in scanner.scan_batch(tmp_path, None)}
    assert got["clean.pdf"]["sha256"] == hashlib.sha256((tmp_path / "clean.pdf").read_bytes()).hexdigest()
    assert got["key.pem"]["secrets"] == ["private-key"]
    assert got["token.txt"]["secrets"] == ["github"]


def test_fifo_is_rejected_without_opening(tmp_path: Path) -> None:
    os.mkfifo(tmp_path / "pipe")
    assert scanner.scan_batch(tmp_path, None) == [
        {"rel": "pipe", "verdict": "rejected", "reasons": ["special_file"], "size": 0}
    ]


def test_scanned_pdf_without_text_is_unverified(tmp_path: Path) -> None:
    make_pdf(tmp_path / "scan.pdf", text="x")
    r = scanner.classify(tmp_path / "scan.pdf", tmp_path)
    assert (r["verdict"], r["tier"], r["reasons"]) == ("ready", "unverified", ["no_text_layer"])


def test_pdf_personal_data_is_found(tmp_path: Path) -> None:
    make_pdf(tmp_path / "statement.pdf", text="Account number: 12345678 for the garden club treasury report")
    r = scanner.classify(tmp_path / "statement.pdf", tmp_path)
    assert (r["tier"], r["pii"]) == ("sensitive", ["account_number"])


def test_oversized_file_is_rejected_before_reading(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(scanner.rules, "MAX_BYTES", 10)
    (tmp_path / "big.txt").write_text("x" * 11)
    r = scanner.classify(tmp_path / "big.txt", tmp_path)
    assert (r["verdict"], r["reasons"], "sha256" in r) == ("rejected", ["too_large"], False)


def _bwrap_works() -> bool:
    if not shutil.which("bwrap"):
        return False
    probe = sandbox.command(Path("/tmp"), Path("/tmp"))
    probe = [*probe[: probe.index("/usr/bin/python3")], "/usr/bin/true"]
    return subprocess.run(probe, capture_output=True).returncode == 0


@pytest.mark.skipif(not _bwrap_works(), reason="bubblewrap with user namespaces not available")
def test_sandbox_has_no_network(tmp_path: Path) -> None:
    probe = "import socket; socket.create_connection(('1.1.1.1', 53), timeout=2)"
    cmd = sandbox.command(tmp_path, tmp_path)
    cmd = [*cmd[: cmd.index("/usr/bin/python3")], "/usr/bin/python3", "-c", probe]
    r = subprocess.run(cmd, capture_output=True, text=True)
    assert r.returncode != 0
    assert "Network is unreachable" in r.stderr or "OSError" in r.stderr
