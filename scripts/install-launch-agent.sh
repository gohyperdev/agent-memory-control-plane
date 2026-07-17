#!/bin/sh
set -eu

if [ "$(uname -s)" != "Darwin" ]; then
  echo "AMCP LaunchAgent installation is macOS-only" >&2
  exit 1
fi

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
agent_bin=${AMCP_AGENT_BIN:-"$repo_root/target/debug/amcp-agent"}
if [ ! -x "$agent_bin" ]; then
  agent_bin=$(command -v amcp-agent || true)
fi
if [ -z "$agent_bin" ] || [ ! -x "$agent_bin" ]; then
  echo "amcp-agent executable not found; set AMCP_AGENT_BIN" >&2
  exit 1
fi

codex_home=${CODEX_HOME:-"$HOME/.codex"}
amcp_home="$HOME/Library/Application Support/AMCP"
launch_agents="$HOME/Library/LaunchAgents"
plist="$launch_agents/com.gohyperdev.amcp.agent.plist"
socket="$amcp_home/agent.sock"
log_dir="$amcp_home/logs"
template="$repo_root/packaging/macos/com.gohyperdev.amcp.agent.plist.template"

mkdir -p "$launch_agents" "$amcp_home" "$log_dir"
chmod 700 "$amcp_home" "$log_dir"
cp "$template" "$plist"

xml_escape() {
  printf '%s' "$1" | sed \
    -e 's/&/\&amp;/g' \
    -e 's/</\&lt;/g' \
    -e 's/>/\&gt;/g'
}

replace() {
  key=$1
  value=$(xml_escape "$2")
  value=$(printf '%s' "$value" | sed -e 's/[\\&|]/\\&/g')
  sed -i '' "s|$key|$value|g" "$plist"
}

replace __AMCP_AGENT_BIN__ "$agent_bin"
replace __AMCP_SOCKET__ "$socket"
replace __CODEX_HOME__ "$codex_home"
replace __AMCP_LOG_DIR__ "$log_dir"
/usr/bin/plutil -lint "$plist" >/dev/null

uid=$(id -u)
/bin/launchctl bootout "gui/$uid" "$plist" >/dev/null 2>&1 || true
/bin/launchctl bootstrap "gui/$uid" "$plist"
echo "Installed and started $plist"
