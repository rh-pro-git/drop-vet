# Architecture

## Flow

```
Mac (drop-vet.app)                      Server (DROP_VET_ROOT)
──────────────────                      ──────────────────────
drop window
  ssh   mkdir landing/.part-<id>
  scp   files → landing/.part-<id>/
  ssh   mv .part-<id> → drop-<id>  ───►  landing/drop-<id>
                                           │  drop-vet-intake.path (PathChanged)
                                           │  definitions older than N days? → exit 1, notify, wait
                                           ▼
                                         quarantine/<ts>-drop-<id>/            0700
                                           │  bwrap --unshare-all: scanner → JSON lines
                                           │  verdicts validated against enums, hashes compared
                                           ▼
        ready/<cat>/   unverified/<cat>/   $DROP_VET_SENSITIVE_DIR/<cat>/   held/<batch>/   rejected/<batch>/
        0640           0640                0640                             0600            0600, purged
           │
           └── ledger.sqlite (one metadata row per file) ──► drop-vet serve (history page, downloads)
```

The rename is the "upload complete" signal. The intake ignores dot-entries, so it never sees a
half-copied drop. A `.part-*` directory idle for a day is moved to `rejected/` as an incomplete
upload.

## Modules

| Module | Concern |
|---|---|
| `config.py` | Environment variables → a frozen `Config`, with the layout paths derived from the root |
| `rules.py` | Pure rules: denylists, allowlists, secret and PII patterns, Luhn, BOM-aware decoding, tier choice |
| `scanner.py` | Classifies files. Runs inside the sandbox in production and in-process in tests. Emits JSON lines. |
| `sandbox.py` | Builds the `bwrap` command line and parses the scanner's output |
| `intake.py` | Lock, freshness gate, landing → quarantine, placement by verdict, ledger rows, notify, purge |
| `ledger.py` | SQLite schema and queries |
| `serve.py` | Read-only history page, JSON API, gated downloads |
| `cli.py` | `drop-vet intake / purge / serve / init` |
| `mac/drop-vet.swift` | AppKit floating drop panel; settings from `defaults`; uploads with `ssh`/`scp` |

## Decisions

**A sandbox per batch, not a scanning daemon.** ClamAV's `clamd` would scan faster, but it is a
long-lived root-adjacent service with a socket. `clamscan` inside `bwrap` costs about 15 s per batch
to load definitions and gives a clean boundary: no network, no environment, read-only input. Drops are
rare and human-paced, so latency doesn't matter.

**Enum-only output from the sandbox.** The scanner could return extracted text for a later stage,
but then the text would leave the sandbox and could reach logs, the ledger or an agent. It returns
reason codes, sizes, MIME types and a hash; the intake also drops any reason it doesn't recognize.

**Release pinned to the scanned bytes.** The scanner hashes exactly what it classified. The intake
refuses to move a file whose current hash differs, and re-checks the destination after the move.
Without this, a process could swap a file between scan and release.

**`unverified` as its own tier.** The first version sent images straight to `ready`. But "virus-free"
is not "checked for personal data", and an image of a passport would have been backed up offsite. A
separate tier keeps the file usable while keeping it out of backups and downloads.

**A missing sensitive store fails closed.** If `DROP_VET_SENSITIVE_DIR` sat on an encrypted volume
that isn't mounted, writing there would put personal data on the unencrypted disk underneath. The
intake never creates that directory: it must already exist, so pointing it at a subdirectory inside
the mount makes an unmounted volume look like a missing store, and the batch stays in quarantine. If the
variable is unset, personal-data files are held.

**Path unit plus a loop.** `PathChanged=` can coalesce events, and a drop can land while a scan is
running. The intake keeps taking entries from `landing/` until it is empty, and the daily
definitions job starts it again after any refresh.

**No login on the history page.** It binds to loopback. Authentication belongs to whatever
publishes it (tailnet, VPN, reverse proxy). Downloads are limited to the `ready` tier so the
exposure is the same as the backups.

## Deployment notes

- **AppArmor:** Ubuntu's `freshclam` profile lets an unprivileged user write only `~/.clamtk/db` and
  read config from `/etc/clamav` or `/tmp`. That is why the units copy `freshclam.conf` into the
  service's private `/tmp` and why `DROP_VET_CLAMAV_DB` defaults to `~/.clamtk/db`.
- **bwrap** needs unprivileged user namespaces. Inside the sandbox, ClamAV also needs
  `/etc/clamav/certs` to verify signed databases; `sandbox.py` binds it read-only when present.
- **systemd hardening:** the intake unit is `ProtectSystem=strict` with write access to the drop root
  only (add your sensitive directory to `ReadWritePaths=`). The history unit is
  `ProtectHome=read-only` with every non-ready area in `InaccessiblePaths=`.

## Data layout and backups

| Path | Contents | Back up? |
|---|---|---|
| `ready/` | released, fully checked files | yes |
| `unverified/` | released, not checked for personal data | no |
| `$DROP_VET_SENSITIVE_DIR` | personal-data files | no, keep a single copy on encrypted storage |
| `held/`, `rejected/`, `landing/`, `quarantine/` | withheld or unprocessed | no |
| `ledger.sqlite` | metadata, including names of sensitive files | your call; it holds no content |
