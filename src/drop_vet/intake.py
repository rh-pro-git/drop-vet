"""Orchestrator: landing/ -> quarantine/ -> scan -> ready | unverified | sensitive | held | rejected."""

from __future__ import annotations

import fcntl
import hashlib
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path

from drop_vet import ledger, rules, sandbox
from drop_vet.config import Config

Scanner = Callable[[Path, Path], list[dict]]
VERDICTS = {"ready", "held", "rejected"}
CATEGORIES = {"document", "image", "code", "data", "text", "archive"}


def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def clean_name(s: str) -> str:
    return re.sub(r"[\x00-\x1f\x7f]", "?", s)[:200]


def notify(cfg: Config, text: str) -> None:
    if not cfg.notify_cmd:
        return
    r = subprocess.run([*shlex.split(cfg.notify_cmd), text], capture_output=True, timeout=30)
    print(f"notify rc={r.returncode}: {text}", file=sys.stderr)


def free_dest(d: Path) -> Path:
    if not d.exists():
        return d
    for n in range(2, 1000):
        c = d.with_name(f"{d.stem} ({n}){d.suffix}")
        if not c.exists():
            return c
    raise RuntimeError("no free name")


def place(src: Path, dest: Path, digest: str, mode: int) -> Path:
    dest = free_dest(dest)
    dest.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    shutil.move(str(src), str(dest))
    os.chmod(dest, mode)
    if sha256(dest) != digest:
        raise RuntimeError("hash changed during release")
    return dest


def stamp(t: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(t))


def process(cfg: Config, batch: Path, scan: Scanner, sigs_at: str) -> dict[str, list[str]]:
    results = scan(batch, cfg.sigs_dir)
    seen = {r["rel"] for r in results}
    for p in batch.rglob("*"):
        if (p.is_file() or p.is_symlink()) and str(p.relative_to(batch)) not in seen:
            results.append({"rel": str(p.relative_to(batch)), "verdict": "held", "reasons": ["not_scanned"], "size": 0})
    summary: dict[str, list[str]] = {k: [] for k in ("ready", "unverified", "sensitive", "held", "rejected")}
    con = ledger.connect(cfg.ledger)
    received = stamp(batch.stat().st_mtime)
    for r in results:
        src = batch / r["rel"]
        if not src.is_symlink() and not src.resolve().is_relative_to(batch.resolve()):
            raise RuntimeError("path escape")
        verdict = r.get("verdict") if r.get("verdict") in VERDICTS else "held"
        category = r.get("category") if r.get("category") in CATEGORIES else "other"
        tier = r.get("tier") if verdict == "ready" else None
        reasons = [x for x in r.get("reasons", []) if x in rules.REASONS]
        regular = src.is_file() and not src.is_symlink()
        digest = ""
        if not regular:
            src.unlink()
            verdict, tier = "rejected", None
        else:
            digest = r.get("sha256") or sha256(src)
            if sha256(src) != digest:
                raise RuntimeError("file changed after scan")
        if verdict == "ready" and tier == "sensitive" and cfg.sensitive_dir is None:
            verdict, tier = "held", None
            reasons.append("no_sensitive_store")
        if verdict == "ready" and tier == "sensitive" and not cfg.sensitive_dir.is_dir():
            raise RuntimeError("sensitive store is not available (encrypted volume not mounted?)")
        dest: Path | None = None
        if verdict == "ready":
            base = {"sensitive": cfg.sensitive_dir, "unverified": cfg.unverified}.get(tier) or cfg.ready
            dest = place(src, base / category / r["rel"], digest, 0o640)
            summary[tier if tier in ("sensitive", "unverified") else "ready"].append(category)
        elif verdict == "held":
            dest = place(src, cfg.held / batch.name / r["rel"], digest, 0o600)
            summary["held"].append(",".join(r.get("secrets") or reasons or ["unknown"]))
        else:
            dest = place(src, cfg.rejected / batch.name / r["rel"], digest, 0o600) if regular else None
            summary["rejected"].append(",".join(reasons or ["unknown"]))
        ledger.insert(
            con,
            {
                "batch": batch.name,
                "name": clean_name(r["rel"]),
                "sha256": digest,
                "size": r.get("size"),
                "mime": r.get("mime"),
                "verdict": verdict,
                "tier": tier,
                "category": category if verdict == "ready" else None,
                "reasons": reasons,
                "secrets": r.get("secrets"),
                "pii": r.get("pii"),
                "dest": str(dest) if dest else None,
                "received_at": received,
                "decided_at": stamp(time.time()),
                "sigs_at": sigs_at,
            },
        )
    for d in sorted(batch.rglob("*"), reverse=True):
        if d.is_dir():
            d.rmdir()
    batch.rmdir()
    return summary


def purge(cfg: Config) -> None:
    now = time.time()
    for d in cfg.rejected.iterdir() if cfg.rejected.exists() else []:
        if now - d.stat().st_mtime > cfg.purge_age:
            shutil.rmtree(d) if d.is_dir() else d.unlink()


def ensure_dirs(cfg: Config) -> None:
    cfg.root.mkdir(parents=True, exist_ok=True)
    os.chmod(cfg.root, 0o750)
    for d in (cfg.landing, cfg.quarantine, cfg.ready, cfg.unverified, cfg.held, cfg.rejected):
        d.mkdir(exist_ok=True)
        os.chmod(d, 0o750 if d in (cfg.ready, cfg.unverified) else 0o700)


def run(cfg: Config, scan: Scanner = sandbox.scan) -> int:
    if not cfg.sig_stamp.exists() or time.time() - cfg.sig_stamp.stat().st_mtime > cfg.sig_max_age:
        notify(cfg, "drop-vet: virus definitions are stale - nothing released until they update")
        return 1
    sigs_at = stamp(cfg.sig_stamp.stat().st_mtime)
    totals: dict[str, list[str]] = {k: [] for k in ("ready", "unverified", "sensitive", "held", "rejected")}
    for e in sorted(cfg.landing.iterdir()):
        if e.name.startswith(".part-") and time.time() - e.stat().st_mtime > 86400:
            d = free_dest(cfg.rejected / e.name)
            shutil.move(str(e), str(d))
            os.utime(d)
            totals["rejected"].append("incomplete_upload")
    while pending := sorted(e for e in cfg.landing.iterdir() if not e.name.startswith(".")):
        e = pending[0]
        batch = free_dest(cfg.quarantine / f"{time.strftime('%Y%m%d-%H%M%S')}-{e.name}")
        if e.is_dir() and not e.is_symlink():
            shutil.move(str(e), str(batch))
        else:
            batch.mkdir(mode=0o700)
            shutil.move(str(e), str(batch / e.name))
        try:
            for k, v in process(cfg, batch, scan, sigs_at).items():
                totals[k] += v
        except Exception as ex:
            print(f"batch {batch.name} left in quarantine: {type(ex).__name__}", file=sys.stderr)
            notify(cfg, f"drop-vet: a batch was left in quarantine ({type(ex).__name__})")
    purge(cfg)
    if any(totals.values()):
        parts = [f"{len(v)} {k}" for k, v in totals.items() if v]
        detail = [f"{k}: {', '.join(sorted(set(v)))}" for k, v in totals.items() if v and k in ("held", "rejected")]
        notify(cfg, "drop-vet: " + ", ".join(parts) + (" | " + "; ".join(detail) if detail else ""))
    return 0


def main(cfg: Config, purge_only: bool = False) -> int:
    ensure_dirs(cfg)
    with open(cfg.root / ".lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if purge_only:
            purge(cfg)
            return 0
        return run(cfg)
