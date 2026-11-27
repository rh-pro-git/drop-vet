from __future__ import annotations

import argparse
import sys

from drop_vet import __version__, config, intake, serve


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="drop-vet", description="Quarantine, scan and tier dropped files.")
    parser.add_argument("--version", action="version", version=f"drop-vet {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("intake", help="process everything in landing/ (run by the systemd path unit)")
    sub.add_parser("purge", help="delete rejected items older than DROP_VET_PURGE_DAYS")
    sub.add_parser("serve", help="run the read-only history page on DROP_VET_HOST:DROP_VET_PORT")
    sub.add_parser("init", help="create the directory layout")
    args = parser.parse_args(argv)
    cfg = config.load()
    if args.cmd == "intake":
        return intake.main(cfg)
    if args.cmd == "purge":
        return intake.main(cfg, purge_only=True)
    if args.cmd == "init":
        intake.ensure_dirs(cfg)
        print(f"created {cfg.root}")
        return 0
    serve.serve(cfg)
    return 0


if __name__ == "__main__":
    sys.exit(main())
