#!/bin/sh
set -eu

if [ "$(uname -s)" != "Darwin" ]; then
  echo "AMCP LaunchAgent removal is macOS-only" >&2
  exit 1
fi

plist="$HOME/Library/LaunchAgents/com.gohyperdev.amcp.agent.plist"
uid=$(id -u)
/bin/launchctl bootout "gui/$uid" "$plist" >/dev/null 2>&1 || true
rm -f "$plist"
echo "Removed $plist"
