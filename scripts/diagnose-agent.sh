#!/bin/sh
set -eu

if [ "$(uname -s)" != "Darwin" ]; then
  echo "AMCP diagnostics are macOS-only" >&2
  exit 1
fi

amcp_home="$HOME/Library/Application Support/AMCP"
plist="$HOME/Library/LaunchAgents/com.gohyperdev.amcp.agent.plist"
socket="$amcp_home/agent.sock"
log_dir="$amcp_home/logs"
stamp=$(date -u '+%Y%m%dT%H%M%SZ')
output_dir=${1:-"$HOME/Desktop/amcp-diagnostic-$stamp"}
archive="${output_dir%/}.tar.gz"

mkdir -p "$output_dir"
chmod 700 "$output_dir"

{
  echo "AMCP diagnostic export"
  echo "created_at=$stamp"
  echo "hostname=$(scutil --get ComputerName 2>/dev/null || hostname)"
  echo "os=$(sw_vers -productVersion 2>/dev/null || true)"
  echo
  echo "== launchd =="
  /bin/launchctl print "gui/$(id -u)/com.gohyperdev.amcp.agent" 2>&1 || true
  echo
  echo "== plist =="
  if [ -f "$plist" ]; then
    /usr/bin/plutil -p "$plist" 2>&1 || true
  else
    echo "plist not installed: $plist"
  fi
  echo
  echo "== socket =="
  if [ -S "$socket" ]; then
    /usr/bin/stat -f 'mode=%Sp path=%N' "$socket" 2>&1 || true
  else
    echo "socket unavailable: $socket"
  fi
} >"$output_dir/status.txt"

redact_log() {
  /usr/bin/sed -E \
    -e 's/(api[_-]?key|token|password|secret|authorization)[[:space:]]*[:=][[:space:]]*[^[:space:]]+/\1=[REDACTED]/Ig' \
    -e 's/Bearer[[:space:]]+[A-Za-z0-9._~+\/-]+/Bearer [REDACTED]/Ig'
}

for name in agent.stdout.log agent.stderr.log; do
  if [ -f "$log_dir/$name" ]; then
    /usr/bin/tail -n 200 "$log_dir/$name" | redact_log >"$output_dir/$name"
  else
    echo "log unavailable: $log_dir/$name" >"$output_dir/$name"
  fi
done

/usr/bin/tar -czf "$archive" -C "$output_dir" .
chmod 600 "$archive"
echo "$archive"
