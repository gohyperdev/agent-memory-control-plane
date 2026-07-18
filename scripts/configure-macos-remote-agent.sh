#!/bin/sh
# Installs a per-user remote TLS Agent LaunchAgent after one-time enrollment.
# Pairing codes and credentials are intentionally not accepted or stored here.
set -eu

usage() {
  cat <<'EOF'
Usage:
  configure-macos-remote-agent.sh --agent-bin PATH --host-id ID --listen HOST:PORT \
    --tls-cert PATH --tls-key PATH [--codex-home PATH] [--app-server-enabled] [--dry-run]

Run this after a temporary Agent has been paired. The Agent resolves the rotated
credential from this host's Keychain; this script never writes tokens or codes.
EOF
}

[ "$(uname -s)" = Darwin ] || { echo "macOS is required" >&2; exit 1; }
agent_bin=
host_id=
listen=
tls_cert=
tls_key=
codex_home="$HOME/.codex"
app_server_enabled=false
dry_run=false
while [ "$#" -gt 0 ]; do
  case "$1" in
    --agent-bin) agent_bin=${2:?missing value for --agent-bin}; shift 2 ;;
    --host-id) host_id=${2:?missing value for --host-id}; shift 2 ;;
    --listen) listen=${2:?missing value for --listen}; shift 2 ;;
    --tls-cert) tls_cert=${2:?missing value for --tls-cert}; shift 2 ;;
    --tls-key) tls_key=${2:?missing value for --tls-key}; shift 2 ;;
    --codex-home) codex_home=${2:?missing value for --codex-home}; shift 2 ;;
    --app-server-enabled) app_server_enabled=true; shift ;;
    --dry-run) dry_run=true; shift ;;
    --help|-h) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

for value in "$agent_bin" "$host_id" "$listen" "$tls_cert" "$tls_key"; do
  [ -n "$value" ] || { usage >&2; exit 1; }
done
case "$agent_bin:$tls_cert:$tls_key:$codex_home" in /*:/*:/*:/*) ;; *) echo "all paths must be absolute" >&2; exit 1 ;; esac
case "$listen" in *:*);; *) echo "--listen must be HOST:PORT" >&2; exit 1 ;; esac
[ -x "$agent_bin" ] || { echo "Agent is not executable: $agent_bin" >&2; exit 1; }
[ -r "$tls_cert" ] || { echo "TLS certificate is not readable: $tls_cert" >&2; exit 1; }
[ -r "$tls_key" ] || { echo "TLS key is not readable: $tls_key" >&2; exit 1; }
[ -d "$codex_home" ] || { echo "Codex home does not exist: $codex_home" >&2; exit 1; }

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
template="$repo_root/packaging/macos/com.gohyperdev.amcp.remote-agent.plist.template"
amcp_home="$HOME/Library/Application Support/AMCP"
state_dir="$amcp_home/agent-state"
backup_dir="$amcp_home/backups"
log_dir="$amcp_home/logs"
launch_agents="$HOME/Library/LaunchAgents"
plist="$launch_agents/com.gohyperdev.amcp.remote-agent.plist"
if [ "$dry_run" = true ]; then
  render_dir=$(mktemp -d "${TMPDIR:-/tmp}/amcp-remote-agent-render.XXXXXX")
  tmp_plist="$render_dir/com.gohyperdev.amcp.remote-agent.plist"
  trap 'rm -rf "$render_dir"' EXIT HUP INT TERM
else
  mkdir -p "$amcp_home" "$state_dir" "$backup_dir" "$log_dir" "$launch_agents"
  chmod 700 "$amcp_home" "$state_dir" "$backup_dir" "$log_dir"
  tmp_plist=$(mktemp "$launch_agents/.com.gohyperdev.amcp.remote-agent.XXXXXX")
  trap 'rm -f "$tmp_plist"' EXIT HUP INT TERM
fi
cp "$template" "$tmp_plist"
xml_escape() { printf '%s' "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'; }
replace() {
  value=$(xml_escape "$2")
  value=$(printf '%s' "$value" | sed -e 's/[\\&|]/\\&/g')
  sed -i '' "s|$1|$value|g" "$tmp_plist"
}
replace __AMCP_AGENT_BIN__ "$agent_bin"
replace __AMCP_HOST_ID__ "$host_id"
replace __CODEX_HOME__ "$codex_home"
replace __AMCP_STATE_DIR__ "$state_dir"
replace __AMCP_BACKUP_DIR__ "$backup_dir"
replace __AMCP_TCP_BIND__ "$listen"
replace __AMCP_TLS_CERT__ "$tls_cert"
replace __AMCP_TLS_KEY__ "$tls_key"
replace __AMCP_APP_SERVER_ENABLED__ "$app_server_enabled"
replace __AMCP_LOG_DIR__ "$log_dir"
/usr/bin/plutil -lint "$tmp_plist" >/dev/null
if [ "$dry_run" = true ]; then
  echo "Validated remote Agent LaunchAgent configuration (dry run; filesystem and launchd unchanged)"
  exit 0
fi
mv -f "$tmp_plist" "$plist"
chmod 600 "$plist"
uid=$(id -u)
/bin/launchctl bootout "gui/$uid" "$plist" >/dev/null 2>&1 || true
/bin/launchctl bootstrap "gui/$uid" "$plist"
/bin/launchctl kickstart -k "gui/$uid/com.gohyperdev.amcp.remote-agent"
printf 'Installed and started %s\n' "$plist"
