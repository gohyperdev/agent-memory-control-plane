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
state_dir="$amcp_home/agent-state"
log_dir="$amcp_home/logs"
template="$repo_root/packaging/macos/com.gohyperdev.amcp.agent.plist.template"
app_server_enabled=${AMCP_AGENT_APP_SERVER_ENABLED:-false}
launchctl_bin=${AMCP_LAUNCHCTL_BIN:-/bin/launchctl}
plutil_bin=${AMCP_PLUTIL_BIN:-/usr/bin/plutil}
dry_run=${AMCP_DRY_RUN:-false}

mkdir -p "$launch_agents" "$amcp_home" "$state_dir" "$log_dir"
chmod 700 "$amcp_home" "$state_dir" "$log_dir"

tmp_plist=$(mktemp "$launch_agents/.com.gohyperdev.amcp.agent.XXXXXX")
trap 'rm -f "$tmp_plist"' EXIT HUP INT TERM
cp "$template" "$tmp_plist"

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
  sed -i '' "s|$key|$value|g" "$tmp_plist"
}

replace __AMCP_AGENT_BIN__ "$agent_bin"
replace __AMCP_SOCKET__ "$socket"
replace __CODEX_HOME__ "$codex_home"
replace __AMCP_STATE_DIR__ "$state_dir"
replace __AMCP_APP_SERVER_ENABLED__ "$app_server_enabled"
replace __AMCP_LOG_DIR__ "$log_dir"
$plutil_bin -lint "$tmp_plist" >/dev/null
mv -f "$tmp_plist" "$plist"
chmod 600 "$plist"

if [ "$dry_run" = true ]; then
  echo "Rendered $plist (dry run; launchd was not changed)"
  exit 0
fi

uid=$(id -u)
$launchctl_bin bootout "gui/$uid" "$plist" >/dev/null 2>&1 || true
$launchctl_bin bootstrap "gui/$uid" "$plist"
$launchctl_bin kickstart -k "gui/$uid/com.gohyperdev.amcp.agent"
echo "Installed and started $plist"
