#!/bin/sh
set -eu

if [ "$(uname -s)" != "Linux" ]; then
  echo "AMCP systemd user-service removal is Linux-only" >&2
  exit 1
fi

unit_root=${XDG_CONFIG_HOME:-"$HOME/.config"}/systemd/user
unit_path=$unit_root/com.gohyperdev.amcp.agent.service

systemctl --user disable --now com.gohyperdev.amcp.agent.service 2>/dev/null || true
rm -f "$unit_path"
systemctl --user daemon-reload
printf '%s\n' "Removed $unit_path"
