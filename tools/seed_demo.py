"""Build a demo drop root from invented files, for screenshots. ClamAV is skipped; nothing here is real data.

python tools/seed_demo.py /tmp/drop-vet-demo
DROP_VET_ROOT=/tmp/drop-vet-demo DROP_VET_STATE_DIR=/tmp/drop-vet-demo/.state drop-vet serve
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from drop_vet import config, intake, scanner

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tests.conftest import make_fixtures, make_pdf


def main() -> int:
    root = Path(sys.argv[1]).resolve()
    os.environ.update(
        DROP_VET_ROOT=str(root),
        DROP_VET_STATE_DIR=str(root / ".state"),
        DROP_VET_SENSITIVE_DIR=str(root / ".vault"),
    )
    cfg = config.load()
    cfg.sensitive_dir.mkdir(parents=True, exist_ok=True)
    cfg.sig_stamp.parent.mkdir(parents=True, exist_ok=True)
    cfg.sig_stamp.touch()
    intake.ensure_dirs(cfg)
    batches = {
        "fixtures": make_fixtures,
        "reading": lambda d: (d.mkdir(), make_pdf(d / "trail-map.pdf"), (d / "packing-list.md").write_text("- tent\n")),
    }
    for name, build in batches.items():
        part = cfg.landing / f".part-{name}"
        build(part)
        part.rename(cfg.landing / f"drop-{name}")
    intake.run(cfg, lambda b, _s: scanner.scan_batch(b, None))
    print(f"demo root ready at {root}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
