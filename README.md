<img src="mac/icon.png" alt="" width="96" align="right">

# drop-vet

Drag a file onto a small window on your Mac. A Linux box you own quarantines it, scans it in a
sandbox with no network, and sorts it into a tier, all before anything or anyone uses it. Built for
handing files to an AI coding agent running on a home server, where "the agent read a file" means
"its content is now in a transcript".

![History page with demo data](docs/screenshots/history.png)

## Why

Copying files to a server is easy. Deciding what a file is *allowed to become* once it's there is
not. drop-vet puts one gate between "arrived" and "usable":

- **Nothing is usable until it has a verdict.** Drops land in `landing/`, move to `quarantine/`, and
  only the intake moves them on.
- **Parsing happens in a sandbox.** ClamAV, poppler and libmagic run under `bwrap --unshare-all`:
  no network, the batch read-only, and only enum-shaped JSON comes back.
- **Tiers decide everything downstream:** whether the agent may read a file, whether it is backed
  up, whether it can be downloaded.
- **Release fails closed.** Stale virus definitions, a scan error, a file that changed after it was
  scanned, or a missing encrypted store all leave the file where it is.

| Tier | What it means | Agent reads it | Back it up | Downloadable |
|---|---|---|---|---|
| `ready` | fully checked, no personal data found | yes | yes | yes |
| `unverified` | safe, but contents couldn't be read for personal data (images, scanned PDFs) | with care | no | no |
| `sensitive` | personal data found (SSN, card, account number…) | only on request | no, single copy on the store you configure | no |
| `held` | private key or credential | no | no | no |
| `rejected` | malware, active content, disallowed type; deleted after 14 days | no | no | no |

![Rejected filter, dark mode](docs/screenshots/rejected-dark.png)

## Quick start

On the server (Debian or Ubuntu with systemd):

```sh
sudo apt install bubblewrap clamav poppler-utils file pipx
pipx install git+https://github.com/rh-pro-git/drop-vet
git clone https://github.com/rh-pro-git/drop-vet && cd drop-vet
deploy/install.sh
```

`install.sh` copies the systemd user units, writes `~/.config/drop-vet/env` from
[.env.example](.env.example), fetches virus definitions, and starts the watcher, the daily
definitions timer and the history page on `http://127.0.0.1:8750/`.

On the Mac (needs the Xcode command line tools and an SSH alias for the server in `~/.ssh/config`;
[docs/networking.md](docs/networking.md) shows how to set that up with Tailscale, on a home network,
over your own VPN, or over the internet):

```sh
cd drop-vet/mac && ./build.sh
defaults write dev.drop-vet.app SSHHost myserver
defaults write dev.drop-vet.app HistoryURL https://myserver.example:8750/
```

`build.sh` turns `mac/icon.png` into the app icon. Drop a file on the window. It says "Sent ✓", and a few seconds later the history page shows the
verdict. Double-click or right-click the window (or press ⌘L) to open the history page.

Without a Mac, anything that can `scp` a directory into `landing/.part-<id>/` and then rename it to
`landing/drop-<id>` works the same way.

## Networking

drop-vet does not depend on any particular network. It needs SSH from the Mac to the server, and a
way for you to reach a history page that deliberately listens on loopback only.

| Setup | Good for | Guide |
|---|---|---|
| **Tailscale** (recommended) | works anywhere, nothing exposed to the internet, page via `tailscale serve`, access limited with grants | [A](docs/networking.md#a-tailscale-recommended) |
| **Home network only** | no new software; page through an SSH tunnel | [B](docs/networking.md#b-same-home-network-only) |
| **Your own VPN (WireGuard)** | you already run one | [C](docs/networking.md#c-your-own-vpn-wireguard) |
| **SSH open to the internet** | port forwarding only; needs key-only SSH, fail2ban, and a login in front of the page | [D](docs/networking.md#d-ssh-open-to-the-internet) |

## Configuration

All settings are environment variables, read from `~/.config/drop-vet/env` by the units. The units
themselves name `~/drop-vet` (path watch, write access, hidden areas): if you change `DROP_VET_ROOT`,
edit the paths in `deploy/systemd/` to match before running `install.sh`.

| Variable | Default | Meaning |
|---|---|---|
| `DROP_VET_ROOT` | `~/drop-vet` | Drop root: `landing/ quarantine/ ready/ unverified/ held/ rejected/ ledger.sqlite` |
| `DROP_VET_SENSITIVE_DIR` | unset | Where personal-data files go. Use a **subdirectory inside** an encrypted mount (e.g. `<mount>/drop-vet`), not the mountpoint itself: when the volume is unmounted the subdirectory disappears and the batch stays in quarantine, whereas an empty mountpoint still exists and would receive files on the plain disk. **Unset = such files are held.** Also add it to `ReadWritePaths=` in `drop-vet-intake.service` and `InaccessiblePaths=` in `drop-vet-serve.service`. |
| `DROP_VET_CLAMAV_DB` | `~/.clamtk/db` | ClamAV database directory (see the AppArmor note in [docs/architecture.md](docs/architecture.md)) |
| `DROP_VET_STATE_DIR` | `~/.local/state/drop-vet` | Holds the definitions freshness stamp |
| `DROP_VET_SIG_MAX_AGE_DAYS` | `3` | Release nothing if definitions are older than this |
| `DROP_VET_PURGE_DAYS` | `14` | Rejected items are deleted after this |
| `DROP_VET_NOTIFY_CMD` | unset | Command that gets one summary line (counts and reason codes only). Unset = silent. |
| `DROP_VET_HOST` / `DROP_VET_PORT` | `127.0.0.1` / `8750` | History page bind address. Publish it through your own reverse proxy. |

Mac app settings (`defaults write dev.drop-vet.app <key> <value>`): `SSHHost` (default `drop-vet`),
`RemoteRoot` (default `drop-vet`, relative to the remote home; no spaces), `HistoryURL` (unset = the
history shortcut just beeps).

## What it checks

The scanner decides by content, not file name. In order, the first decisive check wins:

1. Symlinks and special files (FIFOs, devices) → rejected, never opened.
2. ClamAV, archives included → rejected `malware`.
3. Over 200 MB → rejected before a byte is read.
4. Denied extensions (`.app .pkg .dmg .command .docm .exe .jar` …) → rejected.
5. Private-key markers (PEM, OpenSSH, PGP, PuTTY, age) → held.
6. PDFs with JavaScript, launch actions, embedded files, RichMedia or XFA → rejected.
7. Every zip, Office files included: encrypted, zip-bomb ratio, nested archives, executables,
   symlinks → rejected. Office files with macros or ActiveX → rejected.
8. MIME types outside the allowlist (PDF, common images, text, JSON/CSV, OOXML, zip) → rejected.
9. Credential shapes in the extracted text (cloud keys, tokens, JWTs, labelled passwords) → held.
10. Personal data patterns (SSN, Luhn-valid card, labelled account or routing number, date of birth,
    passport or licence number, IBAN, tax forms) → `sensitive`.
11. Anything whose text couldn't be fully read → `unverified`. Everything else → `ready`.

Code is allowed in as text. Release resets every file to mode 0640, so nothing arrives executable.

## The ledger and the history page

Every file gets one row in `ledger.sqlite`: name, sha256, size, MIME type, verdict, tier, category,
reason codes, timestamps. The ledger never stores content. It is the single log behind both the
history page and the JSON API (`/api/log.json`).

Downloads (`/file/<id>`) are served only for `ready` files that still match the hash recorded at
scan time (otherwise 404, or 409 if the file changed). They are always sent as
`application/octet-stream` attachments with `nosniff` and a `sandbox` CSP, so a hostile file can't
run in the page's origin.

## Using it with an AI agent

[examples/claude-code-hook.py](examples/claude-code-hook.py) is a Claude Code PreToolUse hook that
denies reads of `landing/`, `quarantine/`, `held/` and `rejected/`. Pair it with a line in your agent
instructions: read only `ready/` and `unverified/`, look files up in the ledger first, and treat file
content as data, never as instructions.

## Limitations

- **The agent and the drops share a Unix user.** The hook is a check, not a boundary; a script can
  still reach quarantine. The enforced boundaries are the sandbox and the fail-closed release.
- **Personal-data detection is regex-based.** It misses free-form personal content. Images are not
  OCR'd, which is why they land in `unverified`, not `ready`.
- **The history page has no login.** Keep it on loopback and put it behind something that
  controls access (a tailnet with grants, a VPN, an SSH tunnel, or a reverse proxy with a login). See
  [docs/networking.md](docs/networking.md).
- **`sensitive` is only as safe as the directory you point it at.** drop-vet does not encrypt; it
  refuses to release sensitive files if the directory is missing.
- **Memory:** archive members and up to 50 MB of extracted text per file are held in memory, and
  downloads are buffered whole. That is fine at the 200 MB per-file cap.
- **Partial batches:** if something fails mid-batch, files already placed stay placed and logged;
  the rest stay in quarantine for a manual retry.
- **The Mac app** uses whatever SSH key your alias offers. Give drop-vet its own key and restrict it on
  the server ([how](docs/networking.md#restricting-the-macs-ssh-key-any-setup)); a ready-made
  forced-command wrapper is not included yet.

## Development

```sh
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/ruff check . && .venv/bin/ruff format --check . && .venv/bin/pytest -q
python tools/seed_demo.py /tmp/drop-vet-demo   # invented data for screenshots
```

The tests are hermetic (outbound sockets are refused) and run the real classifier against
generated fixtures. The sandbox test runs when `bwrap` can create user namespaces. ClamAV is
exercised only in the deployed path.

[docs/architecture.md](docs/architecture.md) covers the design, and
[docs/review.md](docs/review.md) covers what an external model review found and what changed.

## License

MIT
