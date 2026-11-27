"""The classifier. In production it runs inside the sandbox (see sandbox.py) over one batch directory.

It prints one JSON line per file: path, size, MIME type, sha256 of the bytes it classified, a verdict
and enum reasons. Extracted text never leaves this process.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
import zipfile
from pathlib import Path

from drop_vet import rules


def mime_of(p: Path) -> str:
    return subprocess.run(["file", "--mime-type", "-b", str(p)], capture_output=True, text=True).stdout.strip()


def pdf_text(p: Path) -> tuple[str, bool]:
    try:
        r = subprocess.run(["pdftotext", "-q", str(p), "-"], capture_output=True, timeout=300)
    except subprocess.TimeoutExpired:
        return "", False
    ok = r.returncode == 0 and len(r.stdout) <= rules.MAX_TEXT
    return r.stdout[: rules.MAX_TEXT].decode("utf-8", "replace"), ok


def pdf_active(p: Path, raw: bytes) -> bool:
    js = subprocess.run(["pdfinfo", "-js", str(p)], capture_output=True, text=True, timeout=60).stdout
    if js.strip():
        return True
    att = subprocess.run(["pdfdetach", "-list", str(p)], capture_output=True, text=True, timeout=60).stdout
    if re.search(r"^[1-9]\d* embedded files", att, re.M):
        return True
    return bool(rules.PDF_ACTIVE.search(raw))


def _zip(p: Path, size: int, out: dict) -> str | None:
    """Check every member of any zip, Office files included. Returns extracted text, or None if decided."""
    try:
        z = zipfile.ZipFile(p)
    except zipfile.BadZipFile:
        return _reject(out, "bad_archive")
    infos = z.infolist()
    if any(i.flag_bits & 0x1 for i in infos):
        return _reject(out, "encrypted_archive")
    total = sum(i.file_size for i in infos)
    if total > rules.MAX_UNZIPPED or (size and total / size > rules.MAX_RATIO):
        return _reject(out, "zip_bomb")
    names = {i.filename for i in infos}
    office = "[Content_Types].xml" in names and any(m in names for m in rules.OFFICE_MAIN)
    out["category"] = "document" if office else "archive"
    parts: list[str] = []
    budget = rules.MAX_TEXT
    for i in infos:
        if i.is_dir():
            continue
        n = i.filename.lower()
        if office and (n.endswith("vbaproject.bin") or "/activex/" in n):
            return _reject(out, "office_macro")
        if Path(n).suffix in rules.DENY_EXT or n.endswith(rules.ARCHIVE_EXT):
            return _reject(out, "archive_member_denied")
        if (i.external_attr >> 16) & 0o170000 == 0o120000:
            return _reject(out, "archive_symlink")
        data = z.read(i)
        if rules.KEY_MARKERS.search(data):
            return _hold(out, ["private-key"])
        if data[:4] == b"%PDF" and rules.PDF_ACTIVE.search(data):
            return _reject(out, "archive_member_denied")
        if data[:4] in rules.EXEC_MAGIC or data[:2] == b"MZ":
            return _reject(out, "archive_member_denied")
        if data[:4] in (b"%PDF", b"PK\x03\x04"):
            out["reasons"].append("archive_member_not_text_scanned")
            continue
        text, ok = rules.decode_text(data)
        if not ok:
            out["reasons"].append("archive_member_not_text_scanned")
            continue
        if len(text) > budget:
            out["reasons"].append("text_budget_exceeded")
            break
        budget -= len(text)
        parts.append(re.sub(r"<[^>]+>", " ", text) if office and n.endswith((".xml", ".rels")) else text)
    return "\n".join(parts)


def _reject(out: dict, reason: str) -> None:
    out["verdict"] = "rejected"
    out["reasons"].append(reason)


def _hold(out: dict, secrets: list[str]) -> None:
    out["verdict"] = "held"
    out["secrets"] = secrets


def classify(p: Path, root: Path) -> dict:
    out: dict = {"rel": str(p.relative_to(root)), "size": p.stat().st_size, "reasons": [], "secrets": [], "pii": []}
    if out["size"] > rules.MAX_BYTES:
        _reject(out, "too_large")
        return out
    ext = p.suffix.lower()
    mime = mime_of(p)
    raw = p.read_bytes()
    out["mime"], out["sha256"] = mime, hashlib.sha256(raw).hexdigest()
    if ext in rules.DENY_EXT:
        _reject(out, "denied_extension")
        return out
    if rules.KEY_MARKERS.search(raw):
        _hold(out, ["private-key"])
        return out

    text: str | None = ""
    if mime == "application/pdf":
        if pdf_active(p, raw):
            _reject(out, "pdf_active")
            return out
        text, ok = pdf_text(p)
        out["category"] = "document"
        if not ok:
            out["reasons"].append("extraction_failed")
        elif len(text.strip()) < 50:
            out["reasons"].append("no_text_layer")
    elif mime in rules.IMAGE_MIME:
        out["category"] = "image"
        out["reasons"].append("image_not_text_scanned")
    elif mime.startswith(rules.OFFICE_MIME_PREFIX) or mime == "application/zip":
        text = _zip(p, out["size"], out)
        if text is None:
            return out
    elif mime.startswith("text/") or mime in rules.TEXT_MIME:
        if raw[:2] == b"#!" and ext == "":
            _reject(out, "denied_extension")
            return out
        text, ok = rules.decode_text(raw)
        if not ok:
            out["reasons"].append("extraction_failed")
        out["category"] = rules.category_for_text(ext)
    else:
        _reject(out, "disallowed_type")
        return out

    out["secrets"] = rules.secret_kinds(text)
    out["pii"] = rules.pii_kinds(text)
    if out["secrets"]:
        out["verdict"] = "held"
    else:
        out["verdict"] = "ready"
        out["tier"] = rules.tier(out["pii"], out["reasons"])
    return out


def clam(files: list[Path], sigs: Path) -> set[str]:
    r = subprocess.run(
        [
            "clamscan",
            f"--database={sigs}",
            "--no-summary",
            "--infected",
            "--scan-archive=yes",
            "--alert-encrypted=yes",
            "--max-filesize=200M",
            "--max-scansize=1000M",
            *map(str, files),
        ],
        capture_output=True,
        text=True,
    )
    if r.returncode not in (0, 1):
        raise RuntimeError(f"clamscan failed rc={r.returncode}")
    return {line.rpartition(": ")[0] for line in r.stdout.splitlines() if line.endswith(" FOUND")}


def scan_batch(root: Path, sigs: Path | None) -> list[dict]:
    """Classify every entry under root. sigs=None skips ClamAV (tests only)."""
    files, out = [], []
    for p in sorted(root.rglob("*")):
        rel = str(p.relative_to(root))
        if p.is_symlink():
            out.append({"rel": rel, "verdict": "rejected", "reasons": ["symlink"], "size": 0})
        elif p.is_file():
            files.append(p)
        elif not p.is_dir():
            out.append({"rel": rel, "verdict": "rejected", "reasons": ["special_file"], "size": 0})
    hits = clam(files, sigs) if files and sigs else set()
    for p in files:
        rel = str(p.relative_to(root))
        if str(p) in hits:
            raw = p.read_bytes()
            out.append(
                {
                    "rel": rel,
                    "verdict": "rejected",
                    "reasons": ["malware"],
                    "size": len(raw),
                    "mime": mime_of(p),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                }
            )
            continue
        try:
            out.append(classify(p, root))
        except Exception as e:
            out.append(
                {
                    "rel": rel,
                    "verdict": "held",
                    "reasons": ["scan_error"],
                    "error": type(e).__name__,
                    "size": p.stat().st_size,
                }
            )
    return out


def main() -> int:
    for row in scan_batch(Path(sys.argv[1]), Path(sys.argv[2])):
        print(json.dumps(row))
    return 0


if __name__ == "__main__":
    sys.exit(main())
