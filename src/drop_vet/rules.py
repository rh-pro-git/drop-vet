"""Pure decision rules: file-type lists, secret and PII patterns, text decoding.

Nothing here touches the filesystem or the network, so the scanner and the tests share it.
"""

from __future__ import annotations

import re

MAX_BYTES = 200 * 1024 * 1024
MAX_UNZIPPED = 1024 * 1024 * 1024
MAX_RATIO = 100
MAX_TEXT = 50 * 1024 * 1024

DENY_EXT = {
    ".command",
    ".scpt",
    ".scptd",
    ".app",
    ".pkg",
    ".mpkg",
    ".dmg",
    ".iso",
    ".img",
    ".docm",
    ".xlsm",
    ".pptm",
    ".dotm",
    ".xltm",
    ".exe",
    ".msi",
    ".dll",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".jar",
    ".terminal",
    ".workflow",
    ".action",
    ".kext",
    ".dylib",
    ".so",
}
CODE_EXT = {
    ".py",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".swift",
    ".sh",
    ".zsh",
    ".bash",
    ".rb",
    ".go",
    ".rs",
    ".c",
    ".h",
    ".cpp",
    ".java",
    ".kt",
    ".sql",
    ".html",
    ".css",
    ".toml",
    ".ini",
}
DATA_EXT = {".csv", ".tsv", ".json", ".yaml", ".yml", ".xml", ".jsonl"}
ARCHIVE_EXT = (".zip", ".7z", ".rar", ".tar", ".gz")
IMAGE_MIME = {"image/png", "image/jpeg", "image/heic", "image/heif", "image/webp", "image/gif", "image/tiff"}
TEXT_MIME = {"application/json", "application/csv", "application/x-ndjson"}
OFFICE_MIME_PREFIX = "application/vnd.openxmlformats-officedocument."
OFFICE_MAIN = ("word/document.xml", "xl/workbook.xml", "ppt/presentation.xml")
EXEC_MAGIC = (b"\x7fELF", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe")

# Reasons that mean "content passed the safety checks but could not be fully read for personal data".
UNREAD = {
    "image_not_text_scanned",
    "no_text_layer",
    "archive_member_not_text_scanned",
    "extraction_failed",
    "text_budget_exceeded",
}
REASONS = UNREAD | {
    "malware",
    "too_large",
    "denied_extension",
    "pdf_active",
    "office_macro",
    "bad_archive",
    "encrypted_archive",
    "zip_bomb",
    "archive_member_denied",
    "archive_symlink",
    "disallowed_type",
    "symlink",
    "special_file",
    "scan_error",
    "not_scanned",
    "incomplete_upload",
    "no_sensitive_store",
}

KEY_MARKERS = re.compile(
    rb"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY|-----BEGIN OPENSSH PRIVATE KEY|-----BEGIN PGP PRIVATE KEY"
    rb"|PuTTY-User-Key-File|AGE-SECRET-KEY-1"
)
PDF_ACTIVE = re.compile(rb"/(?:JavaScript|JS|Launch|EmbeddedFile|RichMedia|XFA)\b")

SECRETS = [
    ("aws", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}|\bgithub_pat_[A-Za-z0-9_]{50,}")),
    ("gitlab", re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}")),
    ("slack", re.compile(r"\bxox[baprse]-[A-Za-z0-9\-]{10,}")),
    ("stripe", re.compile(r"\b[rs]k_(?:live|test)_[A-Za-z0-9]{20,}")),
    ("google", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("openai", re.compile(r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{32,}")),
    ("anthropic", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")),
    ("private-key", re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY")),
    ("bearer", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9/+_\-\.=~]{20,}")),
    (
        "labeled",
        re.compile(
            r"(?i)\b(?:api[-_ ]?key|secret[-_ ]?key|access[-_ ]?token|client[-_ ]?secret|password)\s*[:=]\s*"
            r"['\"]?[A-Za-z0-9/+_\-\.=~]{12,}"
        ),
    ),
]

PII = [
    ("ssn", re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")),
    ("account_number", re.compile(r"(?i)\b(?:account|acct|routing|aba)\s*(?:number|no\.?|#)?\s*[:#]?\s*[\dX*\-]{6,}")),
    ("dob", re.compile(r"(?i)\b(?:date of birth|d\.o\.b\.?|dob)\b")),
    ("id_document", re.compile(r"(?i)\b(?:passport|driver'?s? licen[cs]e)\s*(?:number|no\.?|#)")),
    ("iban", re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")),
    ("tax_form", re.compile(r"(?i)\b(?:form\s+)?(?:w-2|1099(?:-[a-z]+)?|1040)\b")),
]
CARD = re.compile(r"\b(?:\d[ -]?){13,19}\b")


def luhn(digits: str) -> bool:
    total, alt = 0, False
    for d in reversed(digits):
        n = int(d)
        if alt:
            n = n * 2 - 9 if n > 4 else n * 2
        total += n
        alt = not alt
    return total % 10 == 0


def decode_text(data: bytes) -> tuple[str, bool]:
    """Decode by BOM, then UTF-8, then Latin-1. NUL bytes without a BOM mean unreadable."""
    boms = (
        (b"\xff\xfe\x00\x00", "utf-32"),
        (b"\x00\x00\xfe\xff", "utf-32"),
        (b"\xff\xfe", "utf-16"),
        (b"\xfe\xff", "utf-16"),
    )
    for bom, enc in boms:
        if data.startswith(bom):
            return data.decode(enc, "replace"), True
    if b"\x00" in data:
        return "", False
    try:
        return data.decode("utf-8"), True
    except UnicodeDecodeError:
        return data.decode("latin-1"), True


def secret_kinds(text: str) -> list[str]:
    return sorted({kind for kind, rx in SECRETS if rx.search(text)})


def pii_kinds(text: str) -> list[str]:
    found = [name for name, rx in PII if rx.search(text)]
    for m in CARD.finditer(text):
        digits = re.sub(r"\D", "", m.group(0))
        if 13 <= len(digits) <= 19 and luhn(digits):
            found.append("card_number")
            break
    return found


def tier(pii: list[str], reasons: list[str]) -> str:
    if pii:
        return "sensitive"
    return "unverified" if UNREAD & set(reasons) else "normal"


def category_for_text(ext: str) -> str:
    return "code" if ext in CODE_EXT else "data" if ext in DATA_EXT else "text"
