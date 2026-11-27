from __future__ import annotations

import argparse
import shlex
import sys

from drop_vet import __version__, config, gate, intake, serve


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="drop-vet", description="Quarantine, scan and tier dropped files.")
    parser.add_argument("--version", action="version", version=f"drop-vet {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("intake", help="process everything in landing/ (run by the systemd path unit)")
    sub.add_parser("purge", help="delete rejected items older than DROP_VET_PURGE_DAYS")
    sub.add_parser("serve", help="run the read-only history page on DROP_VET_HOST:DROP_VET_PORT")
    sub.add_parser("init", help="create the directory layout")
    sub.add_parser("ssh-gate", help="forced command for a drop-only SSH key (see docs/networking.md)")
    put = sub.add_parser("put", help="receive one file on stdin into an upload (what the Mac app runs)")
    put.add_argument("id")
    put.add_argument("path", help="base64url-encoded relative path")
    done = sub.add_parser("done", help="finish an upload so the intake picks it up")
    done.add_argument("id")
    args = parser.parse_args(argv)
    cfg = config.load()
    if args.cmd == "intake":
        return intake.main(cfg)
    if args.cmd == "purge":
        return intake.main(cfg, purge_only=True)
    if args.cmd == "ssh-gate":
        return gate.main(cfg)
    if args.cmd in ("put", "done"):
        request = shlex.join(["drop-vet", args.cmd, args.id] + ([args.path] if args.cmd == "put" else []))
        try:
            gate.handle(cfg, request, sys.stdin.buffer)
        except (gate.Refused, OSError) as e:
            print(f"drop-vet: refused: {e}", file=sys.stderr)
            return 1
        return 0
    if args.cmd == "init":
        intake.ensure_dirs(cfg)
        print(f"created {cfg.root}")
        return 0
    serve.serve(cfg)
    return 0


if __name__ == "__main__":
    sys.exit(main())
