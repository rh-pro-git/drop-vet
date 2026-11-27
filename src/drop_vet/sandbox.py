"""Run the scanner over one batch inside bubblewrap: no network, no environment, read-only inputs."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

PKG_ROOT = Path(__file__).resolve().parent.parent
ENTRY = "import sys; sys.path.insert(0, '/pkg'); from drop_vet.scanner import main; sys.exit(main())"


def command(batch: Path, sigs: Path) -> list[str]:
    binds = [
        "--ro-bind",
        "/usr",
        "/usr",
        "--symlink",
        "usr/lib",
        "/lib",
        "--symlink",
        "usr/lib64",
        "/lib64",
        "--symlink",
        "usr/bin",
        "/bin",
        "--symlink",
        "usr/sbin",
        "/sbin",
    ]
    for etc in ("/etc/ld.so.cache", "/etc/alternatives", "/etc/clamav/certs"):
        if Path(etc).exists():
            binds += ["--ro-bind", etc, etc]
    return [
        "bwrap",
        "--unshare-all",
        "--die-with-parent",
        "--new-session",
        "--clearenv",
        *binds,
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        "--ro-bind",
        str(batch),
        "/in",
        "--ro-bind",
        str(sigs),
        "/sigs",
        "--ro-bind",
        str(PKG_ROOT),
        "/pkg",
        "--setenv",
        "PATH",
        "/usr/bin",
        "--setenv",
        "HOME",
        "/tmp",
        "/usr/bin/python3",
        "-I",
        "-c",
        ENTRY,
        "/in",
        "/sigs",
    ]


def scan(batch: Path, sigs: Path) -> list[dict]:
    r = subprocess.run(command(batch, sigs), capture_output=True, text=True, timeout=1800)
    if r.returncode != 0:
        raise RuntimeError(f"scanner exited {r.returncode}")
    return [json.loads(line) for line in r.stdout.splitlines() if line.strip()]
