#!/bin/sh
set -eu

if [ "$(uname -s)" != "Linux" ]; then
  echo "AMCP systemd user-service installation is Linux-only" >&2
  exit 1
fi

agent_bin=${AMCP_AGENT_BIN:?Set AMCP_AGENT_BIN to the built amcp-agent binary}
unit_root=${XDG_CONFIG_HOME:-"$HOME/.config"}/systemd/user
unit_path=$unit_root/com.gohyperdev.amcp.agent.service

if [ ! -x "$agent_bin" ]; then
  echo "AMCP_AGENT_BIN is not executable: $agent_bin" >&2
  exit 1
fi

case "$agent_bin" in
  /*)
    ;;
  *)
    echo "AMCP_AGENT_BIN must be an absolute path" >&2
    exit 1
    ;;
esac

case "$agent_bin" in
  *[[:space:]]*)
    echo "AMCP_AGENT_BIN must not contain whitespace" >&2
    exit 1
    ;;
esac

mkdir -p "$unit_root"
chmod 700 "$unit_root" 2>/dev/null || true

cat >"$unit_path" <<EOF
[Unit]
Description=AMCP local Agent
After=default.target

[Service]
Type=simple
ExecStart=$agent_bin serve
Restart=on-failure
RestartSec=5
RestartPreventExitStatus=0

[Install]
WantedBy=default.target
EOF
chmod 600 "$unit_path"

systemctl --user daemon-reload
systemctl --user enable --now com.gohyperdev.amcp.agent.service
printf '%s\n' "Installed and started $unit_path"
