from __future__ import annotations

import base64
import io
import os
from pathlib import Path

import pytest

from drop_vet import gate, intake
from drop_vet.config import Config


def b64(path: str) -> str:
    return base64.urlsafe_b64encode(path.encode()).decode().rstrip("=")


@pytest.fixture
def landing(cfg: Config) -> Path:
    intake.ensure_dirs(cfg)
    return cfg.landing


def put(cfg: Config, drop_id: str, path: str, data: bytes = b"hello") -> None:
    gate.handle(cfg, f"drop-vet put {drop_id} {b64(path)}", io.BytesIO(data))


def test_put_then_done_produces_a_finished_drop(cfg: Config, landing: Path) -> None:
    put(cfg, "abc-1", "notes.md", b"plain notes")
    put(cfg, "abc-1", "folder/sub/report.pdf", b"%PDF-1.4")
    gate.handle(cfg, "/opt/drop-vet/bin/drop-vet done abc-1", io.BytesIO())
    assert (landing / "drop-abc-1/notes.md").read_bytes() == b"plain notes"
    assert (landing / "drop-abc-1/folder/sub/report.pdf").read_bytes() == b"%PDF-1.4"
    assert (landing / "drop-abc-1/notes.md").stat().st_mode & 0o777 == 0o600
    assert not (landing / ".part-abc-1").exists()


@pytest.mark.parametrize(
    "request_",
    [
        "",
        "bash",
        "scp -t landing/",
        "internal-sftp",
        "cat ledger.sqlite",
        "drop-vet serve",
        "drop-vet done",
        "drop-vet done ../x",
        "drop-vet put ../x bm90ZXM",
        "drop-vet put abc",
        "drop-vet put abc bm90ZXM extra",
        "rm -rf drop-vet put abc x",
        "drop-vet put abc 'unterminated",
    ],
)
def test_anything_but_put_and_done_is_refused(cfg: Config, landing: Path, request_: str) -> None:
    with pytest.raises(gate.Refused):
        gate.handle(cfg, request_, io.BytesIO(b"x"))
    assert list(landing.iterdir()) == []


@pytest.mark.parametrize(
    "path", ["../escape.txt", "/etc/passwd", "a/../../b", "a//b", "./a", "bad\x07name", "a/" * 21 + "b"]
)
def test_paths_cannot_escape_or_smuggle(cfg: Config, landing: Path, path: str) -> None:
    with pytest.raises(gate.Refused):
        put(cfg, "abc", path)


def test_non_base64_path_is_refused(cfg: Config, landing: Path) -> None:
    with pytest.raises(gate.Refused):
        gate.handle(cfg, "drop-vet put abc !!!", io.BytesIO(b"x"))


def test_existing_files_are_never_overwritten(cfg: Config, landing: Path) -> None:
    put(cfg, "abc", "a.txt", b"first")
    with pytest.raises(FileExistsError):
        put(cfg, "abc", "a.txt", b"second")
    assert (landing / ".part-abc/a.txt").read_bytes() == b"first"


def test_symlinks_inside_the_upload_are_not_followed(cfg: Config, landing: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (landing / ".part-abc").mkdir()
    os.symlink(outside, landing / ".part-abc/link")
    with pytest.raises(gate.Refused):
        put(cfg, "abc", "link/x.txt")
    os.symlink(outside / "target.txt", landing / ".part-abc/file-link")
    with pytest.raises(OSError):
        put(cfg, "abc", "file-link")
    assert list(outside.iterdir()) == []


def test_oversized_file_is_refused_and_removed(cfg: Config, landing: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gate.rules, "MAX_BYTES", 10)
    with pytest.raises(gate.Refused):
        put(cfg, "abc", "big.txt", b"x" * 11)
    assert not (landing / ".part-abc/big.txt").exists()


def test_too_many_files_is_refused(cfg: Config, landing: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gate, "MAX_FILES", 2)
    put(cfg, "abc", "1.txt")
    put(cfg, "abc", "2.txt")
    with pytest.raises(gate.Refused):
        put(cfg, "abc", "3.txt")


def test_done_cannot_overwrite_a_finished_drop(cfg: Config, landing: Path) -> None:
    put(cfg, "abc", "a.txt")
    gate.handle(cfg, "drop-vet done abc", io.BytesIO())
    put(cfg, "abc", "b.txt")
    with pytest.raises(gate.Refused):
        gate.handle(cfg, "drop-vet done abc", io.BytesIO())
    assert sorted(p.name for p in (landing / "drop-abc").iterdir()) == ["a.txt"]


def test_main_reads_the_ssh_original_command(cfg: Config, landing: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SSH_ORIGINAL_COMMAND", "cat /etc/passwd")
    assert gate.main(cfg) == 1
    monkeypatch.setenv("SSH_ORIGINAL_COMMAND", "drop-vet done nothing-here")
    assert gate.main(cfg) == 1


def test_cli_put_and_done_work_without_a_forced_command(
    cfg: Config, landing: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from drop_vet import cli

    monkeypatch.setattr("sys.stdin", io.TextIOWrapper(io.BytesIO(b"via cli")))
    assert cli.main(["put", "cli-1", b64("x.txt")]) == 0
    assert cli.main(["done", "cli-1"]) == 0
    assert (landing / "drop-cli-1/x.txt").read_bytes() == b"via cli"
    assert cli.main(["put", "../bad", b64("x.txt")]) == 1
