"""Forced command for a drop-only SSH key.

Put it on the key in ~/.ssh/authorized_keys:

    restrict,command="DROP_VET_ROOT=$HOME/drop-vet $HOME/.local/bin/drop-vet ssh-gate" ssh-ed25519 AAAA...

sshd then runs this for every connection made with that key, whatever command the client asked for, and
passes the request in SSH_ORIGINAL_COMMAND. Exactly two requests are honoured; everything else (a shell,
scp, sftp, port forwarding is already off via `restrict`) is refused:

    drop-vet put <id> <base64url path>   stdin -> landing/.part-<id>/<path>
    drop-vet done <id>                   landing/.part-<id> -> landing/drop-<id>

The key can create new files inside one upload directory and finish that upload. It cannot read, list,
overwrite, delete, or touch anything outside landing/, so a stolen laptop key can drop files and nothing else.
"""

from __future__ import annotations

import base64
import binascii
import os
import re
import shlex
import sys
from pathlib import Path

from drop_vet import rules
from drop_vet.config import Config

ID = re.compile(r"^[A-Za-z0-9-]{1,64}$")
MAX_FILES = 1000
MAX_DROP_BYTES = 2 * 1024 * 1024 * 1024
MAX_DEPTH = 20


class Refused(Exception):
    pass


def decode_path(encoded: str) -> list[str]:
    try:
        raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        rel = raw.decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError) as e:
        raise Refused("path is not valid base64url UTF-8") from e
    parts = rel.split("/")
    if not rel or len(parts) > MAX_DEPTH or rel.startswith("/"):
        raise Refused("path must be relative and at most 20 levels deep")
    for p in parts:
        if p in ("", ".", "..") or len(p.encode()) > 255 or re.search(r"[\x00-\x1f\x7f]", p):
            raise Refused("bad path component")
    return parts


def _usage(part: Path) -> tuple[int, int]:
    files = size = 0
    for p in part.rglob("*"):
        st = p.lstat()
        if p.is_file():
            files += 1
            size += st.st_size
    return files, size


def put(cfg: Config, drop_id: str, encoded: str, stdin: object) -> None:
    parts = decode_path(encoded)
    part = cfg.landing / f".part-{drop_id}"
    if not part.exists():
        part.mkdir(mode=0o700)
    if part.is_symlink() or not part.is_dir():
        raise Refused("upload directory is not a directory")
    files, size = _usage(part)
    if files >= MAX_FILES:
        raise Refused("too many files in one drop")
    d = part
    for name in parts[:-1]:
        d = d / name
        if not d.exists() and not d.is_symlink():
            d.mkdir(mode=0o700)
        if d.is_symlink() or not d.is_dir():
            raise Refused("path component is not a directory")
    target = d / parts[-1]
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    limit = min(rules.MAX_BYTES, MAX_DROP_BYTES - size)
    written = 0
    try:
        with os.fdopen(fd, "wb") as out:
            while chunk := stdin.read(1 << 20):
                written += len(chunk)
                if written > limit:
                    raise Refused("file or drop is over the size limit")
                out.write(chunk)
    except Refused:
        target.unlink()
        raise


def done(cfg: Config, drop_id: str) -> None:
    part = cfg.landing / f".part-{drop_id}"
    final = cfg.landing / f"drop-{drop_id}"
    if part.is_symlink() or not part.is_dir():
        raise Refused("no such upload")
    if final.exists():
        raise Refused("drop already finished")
    part.rename(final)


def handle(cfg: Config, request: str, stdin: object) -> None:
    try:
        argv = shlex.split(request)
    except ValueError as e:
        raise Refused("unparseable request") from e
    if len(argv) < 3 or Path(argv[0]).name != "drop-vet" or not ID.match(argv[2]):
        raise Refused("only 'drop-vet put <id> <path>' and 'drop-vet done <id>' are allowed")
    if argv[1] == "put" and len(argv) == 4:
        put(cfg, argv[2], argv[3], stdin)
    elif argv[1] == "done" and len(argv) == 3:
        done(cfg, argv[2])
    else:
        raise Refused("only 'drop-vet put <id> <path>' and 'drop-vet done <id>' are allowed")


def main(cfg: Config) -> int:
    request = os.environ.get("SSH_ORIGINAL_COMMAND", "")
    if not cfg.landing.is_dir():
        print("drop-vet: landing/ does not exist on the server", file=sys.stderr)
        return 1
    try:
        handle(cfg, request, sys.stdin.buffer)
    except (Refused, FileExistsError, OSError) as e:
        print(f"drop-vet: refused: {e}", file=sys.stderr)
        return 1
    return 0
