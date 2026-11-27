from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _path(name: str, default: Path) -> Path:
    value = os.environ.get(name, "").strip()
    return Path(value).expanduser() if value else default


@dataclass(frozen=True)
class Config:
    root: Path
    sensitive_dir: Path | None
    sigs_dir: Path
    sig_stamp: Path
    sig_max_age: float
    purge_age: float
    notify_cmd: str
    host: str
    port: int

    @property
    def landing(self) -> Path:
        return self.root / "landing"

    @property
    def quarantine(self) -> Path:
        return self.root / "quarantine"

    @property
    def ready(self) -> Path:
        return self.root / "ready"

    @property
    def unverified(self) -> Path:
        return self.root / "unverified"

    @property
    def held(self) -> Path:
        return self.root / "held"

    @property
    def rejected(self) -> Path:
        return self.root / "rejected"

    @property
    def ledger(self) -> Path:
        return self.root / "ledger.sqlite"


def load() -> Config:
    root = _path("DROP_VET_ROOT", Path.home() / "drop-vet")
    sensitive = os.environ.get("DROP_VET_SENSITIVE_DIR", "").strip()
    state = _path("DROP_VET_STATE_DIR", Path.home() / ".local/state/drop-vet")
    return Config(
        root=root,
        sensitive_dir=Path(sensitive).expanduser() if sensitive else None,
        sigs_dir=_path("DROP_VET_CLAMAV_DB", Path.home() / ".clamtk/db"),
        sig_stamp=state / "sigs-ok",
        sig_max_age=float(os.environ.get("DROP_VET_SIG_MAX_AGE_DAYS", "3")) * 86400,
        purge_age=float(os.environ.get("DROP_VET_PURGE_DAYS", "14")) * 86400,
        notify_cmd=os.environ.get("DROP_VET_NOTIFY_CMD", "").strip(),
        host=os.environ.get("DROP_VET_HOST", "127.0.0.1"),
        port=int(os.environ.get("DROP_VET_PORT", "8750")),
    )
