# Changelog

## 1.1.0

- **Drop-only SSH keys.** New `drop-vet ssh-gate` forced command: a key restricted with it can stream new
  files into one upload directory and finish the upload, and nothing else (no shell, no scp/sftp, no
  reads, no overwrites, no path escapes, size and count limits). Setup in `docs/networking.md`.
- The Mac app now uploads with `drop-vet put` / `drop-vet done` over one multiplexed SSH connection
  instead of `mkdir` + `scp` + `mv`. Works with or without a restricted key.
- Mac setting `RemoteRoot` replaced by `RemoteCommand` (default `.local/bin/drop-vet`).
- App icon (`mac/icon.png`) built into the app by `build.sh`.
- `docs/networking.md`: Tailscale, home network, WireGuard and internet-exposed SSH setups.

## 1.0.0

- First release.
