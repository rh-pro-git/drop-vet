#!/bin/zsh
# Build DropVet.app into ~/Applications and launch it. Needs the Xcode command line tools.
# If icon.png (square, 1024 px or larger) sits next to this script it becomes the app icon.
set -e
cd "${0:A:h}"
A=~/Applications/DropVet.app
mkdir -p ~/Applications
swiftc -O -o /tmp/DropVet DropVet.swift
osascript -e 'quit app "DropVet"' 2>/dev/null || true
rm -rf "$A"; mkdir -p "$A/Contents/MacOS" "$A/Contents/Resources"
mv /tmp/DropVet "$A/Contents/MacOS/"; cp Info.plist "$A/Contents/"
if [[ -f icon.png ]]; then
  I=$(mktemp -d)/AppIcon.iconset; mkdir -p "$I"
  for sz in 16 32 128 256 512; do
    sips -z $sz $sz icon.png --out "$I/icon_${sz}x${sz}.png" >/dev/null
    sips -z $((sz * 2)) $((sz * 2)) icon.png --out "$I/icon_${sz}x${sz}@2x.png" >/dev/null
  done
  iconutil -c icns "$I" -o "$A/Contents/Resources/AppIcon.icns"
fi
codesign --force -s - "$A"
touch "$A"
open "$A"
