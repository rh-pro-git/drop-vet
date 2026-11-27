#!/usr/bin/env python3
"""Example Claude Code PreToolUse hook: keep an agent out of the unscanned and withheld areas.

This is a check, not a boundary. The agent and the drops share a Unix user, so a determined script
can still reach these paths; the sandbox and the fail-closed release are the real controls.
Register it in settings.json under hooks.PreToolUse with matcher "Read|Grep|Glob|Bash".
"""

import json
import os
import re
import sys

root = re.escape(os.path.basename(os.environ.get("DROP_VET_ROOT", "drop-vet").rstrip("/")))
BLOCKED = re.compile(rf"{root}/(?:landing|quarantine|held|rejected)\b")
READERS = re.compile(
    r"\b(?:cat|head|tail|less|more|strings|xxd|od|hexdump|pdftotext|pdfinfo|sed|awk|grep|rg|python3?|"
    r"cp|rsync|scp|base64|file|exiftool|open|unzip|zcat|vim?|nano|code|tar|zip)\b"
)

event = json.load(sys.stdin)
inp = event.get("tool_input", {})
if event.get("tool_name") == "Bash":
    cmd = inp.get("command", "")
    hit = BLOCKED.search(cmd) and READERS.search(cmd)
else:
    hit = any(BLOCKED.search(str(inp.get(k, ""))) for k in ("file_path", "path", "pattern"))
if hit:
    print("Blocked: landing/quarantine/held/rejected are not readable. Use ready/ and the ledger.", file=sys.stderr)
    sys.exit(2)
