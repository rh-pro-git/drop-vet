from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from drop_vet import intake, ledger, scanner
from drop_vet.config import Config
from tests.conftest import EXPECTED, make_fixtures


def scan(batch: Path, _sigs: Path) -> list[dict]:
    return scanner.scan_batch(batch, None)


def drop(cfg: Config, src_builder, name: str = "drop-1") -> None:
    intake.ensure_dirs(cfg)
    part = cfg.landing / f".part-{name}"
    src_builder(part)
    part.rename(cfg.landing / name)


def rows(cfg: Config) -> dict[str, dict]:
    return {r["name"]: r for r in ledger.recent(ledger.read_only(cfg.ledger))}


def test_full_batch_lands_in_the_right_tiers(cfg: Config) -> None:
    drop(cfg, make_fixtures)
    assert intake.run(cfg, scan) == 0
    got = rows(cfg)
    assert set(got) == set(EXPECTED)
    for name, (verdict, tier, _) in EXPECTED.items():
        assert (got[name]["verdict"], got[name]["tier"]) == (verdict, tier), name
    assert (cfg.ready / "document/clean.pdf").stat().st_mode & 0o777 == 0o640
    assert (cfg.ready / "code/hello.sh").stat().st_mode & 0o777 == 0o640
    assert (cfg.unverified / "image/pic.png").exists()
    assert (cfg.sensitive_dir / "text/ssn.txt").exists()
    assert not any(cfg.landing.iterdir()) and not any(cfg.quarantine.iterdir())


def test_stale_signatures_release_nothing(cfg: Config) -> None:
    old = time.time() - 4 * 86400
    os.utime(cfg.sig_stamp, (old, old))
    drop(cfg, make_fixtures)
    assert intake.run(cfg, scan) == 1
    assert (cfg.landing / "drop-1").is_dir()
    assert not cfg.ledger.exists()


def test_without_a_sensitive_store_personal_files_are_held(cfg: Config) -> None:
    cfg = Config(**{**cfg.__dict__, "sensitive_dir": None})
    drop(cfg, lambda d: (d.mkdir(), (d / "ssn.txt").write_text("SSN 123-45-6789")))
    intake.run(cfg, scan)
    r = rows(cfg)["ssn.txt"]
    assert (r["verdict"], r["reasons"]) == ("held", ["no_sensitive_store"])


def test_missing_sensitive_store_keeps_the_batch_in_quarantine(cfg: Config) -> None:
    cfg.sensitive_dir.rmdir()
    drop(cfg, lambda d: (d.mkdir(), (d / "ssn.txt").write_text("SSN 123-45-6789")))
    intake.run(cfg, scan)
    assert [p.name for p in cfg.quarantine.rglob("ssn.txt")] == ["ssn.txt"]
    assert rows(cfg) == {}


def test_file_changed_after_scan_is_not_released(cfg: Config) -> None:
    def tampering_scan(batch: Path, sigs: Path) -> list[dict]:
        out = scan(batch, sigs)
        (batch / "notes.md").write_text("swapped after the scan")
        return out

    drop(cfg, lambda d: (d.mkdir(), (d / "notes.md").write_text("plain notes")))
    intake.run(cfg, tampering_scan)
    assert not (cfg.ready / "text/notes.md").exists()
    assert list(cfg.quarantine.rglob("notes.md"))


def test_drop_landing_mid_run_is_processed_in_the_same_run(cfg: Config) -> None:
    calls: list[str] = []

    def scan_and_drop_another(batch: Path, sigs: Path) -> list[dict]:
        calls.append(batch.name)
        if len(calls) == 1:
            drop(cfg, lambda d: (d.mkdir(), (d / "second.txt").write_text("second drop")), "drop-2")
        return scan(batch, sigs)

    drop(cfg, lambda d: (d.mkdir(), (d / "first.txt").write_text("first drop")))
    intake.run(cfg, scan_and_drop_another)
    assert len(calls) == 2
    assert {"first.txt", "second.txt"} <= set(rows(cfg))


def test_special_file_does_not_block(cfg: Config) -> None:
    drop(cfg, lambda d: (d.mkdir(), os.mkfifo(d / "pipe")))
    intake.run(cfg, scan)
    r = rows(cfg)["pipe"]
    assert (r["verdict"], r["reasons"]) == ("rejected", ["special_file"])


def test_incomplete_upload_is_rejected_and_kept_for_the_retention_window(cfg: Config) -> None:
    intake.ensure_dirs(cfg)
    part = cfg.landing / ".part-stuck"
    part.mkdir()
    old = time.time() - 30 * 86400
    os.utime(part, (old, old))
    intake.run(cfg, scan)
    assert (cfg.rejected / ".part-stuck").is_dir()


def test_purge_removes_only_expired_rejects(cfg: Config) -> None:
    intake.ensure_dirs(cfg)
    fresh, stale = cfg.rejected / "fresh", cfg.rejected / "stale"
    fresh.mkdir()
    stale.mkdir()
    old = time.time() - 15 * 86400
    os.utime(stale, (old, old))
    intake.purge(cfg)
    assert fresh.exists() and not stale.exists()


def test_unknown_verdicts_and_reasons_from_the_scanner_are_not_trusted(cfg: Config) -> None:
    def odd_scan(batch: Path, _sigs: Path) -> list[dict]:
        return [{"rel": "a.txt", "verdict": "approved", "reasons": ["<script>"], "size": 1}]

    drop(cfg, lambda d: (d.mkdir(), (d / "a.txt").write_text("a")))
    intake.run(cfg, odd_scan)
    r = rows(cfg)["a.txt"]
    assert (r["verdict"], r["reasons"]) == ("held", [])


@pytest.mark.parametrize("name", ["bad\x1bname.txt"])
def test_control_characters_are_stripped_from_ledger_names(cfg: Config, name: str) -> None:
    drop(cfg, lambda d: (d.mkdir(), (d / name).write_text("plain")))
    intake.run(cfg, scan)
    assert "bad?name.txt" in rows(cfg)
