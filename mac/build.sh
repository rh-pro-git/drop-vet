#!/bin/zsh
# Build DropVet.app into ~/Applications and launch it. Needs the Xcode command line tools.
set -e
cd "${0:A:h}"
A=~/Applications/DropVet.app
mkdir -p ~/Applications
swiftc -O -o /tmp/DropVet DropVet.swift
osascript -e 'quit app "DropVet"' 2>/dev/null || true
rm -rf "$A"; mkdir -p "$A/Contents/MacOS"
mv /tmp/DropVet "$A/Contents/MacOS/"; cp Info.plist "$A/Contents/"
codesign --force -s - "$A"
open "$A"
