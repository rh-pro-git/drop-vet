#!/usr/bin/env bash
# Install drop-vet's systemd user units on a Debian/Ubuntu host. Run from a checkout after `pipx install .`
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
units=~/.config/systemd/user
mkdir -p "$units" ~/.config/drop-vet ~/.local/state/drop-vet
install -m 0644 "$here"/systemd/* "$units/"
[[ -f ~/.config/drop-vet/freshclam.conf ]] || sed "s#/home/USER#$HOME#" "$here/freshclam.conf" > ~/.config/drop-vet/freshclam.conf
[[ -f ~/.config/drop-vet/env ]] || cp "$here/../.env.example" ~/.config/drop-vet/env
drop-vet init
systemctl --user daemon-reload
systemctl --user start drop-vet-sigs.service
systemctl --user enable --now drop-vet-intake.path drop-vet-sigs.timer drop-vet-serve.service
echo "installed. History page: http://127.0.0.1:${DROP_VET_PORT:-8750}/ (loopback; publish it with your reverse proxy if you want it remote)"
