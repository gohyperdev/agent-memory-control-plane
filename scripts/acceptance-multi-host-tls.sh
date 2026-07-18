#!/bin/sh
# Exercises remote Agent TLS transport and a shared Controller catalog using
# two isolated loopback hosts. It creates only temporary data beneath /tmp.
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"

for dependency in openssl nc sqlite3; do
  if ! command -v "$dependency" >/dev/null 2>&1; then
    echo "$dependency is required for this acceptance script" >&2
    exit 1
  fi
done

port_a=${AMCP_TLS_ACCEPTANCE_PORT_A:-45451}
port_b=${AMCP_TLS_ACCEPTANCE_PORT_B:-45452}
if [ "$port_a" = "$port_b" ]; then
  echo "AMCP TLS acceptance ports must be distinct" >&2
  exit 1
fi

cargo build --bin amcp-agent --bin amcp-controller >/dev/null

acceptance_dir=$(mktemp -d /tmp/amcp-multi-host-tls.XXXXXX)
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$acceptance_dir/ca.key" \
  -out "$acceptance_dir/ca.crt" \
  -days 1 \
  -subj '/CN=AMCP test CA' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes \
  -keyout "$acceptance_dir/agent.key" \
  -out "$acceptance_dir/agent.csr" \
  -subj '/CN=localhost' \
  -addext 'basicConstraints=critical,CA:FALSE' \
  -addext 'keyUsage=critical,digitalSignature,keyEncipherment' \
  -addext 'extendedKeyUsage=serverAuth' \
  -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' >/dev/null 2>&1
openssl x509 -req \
  -in "$acceptance_dir/agent.csr" \
  -CA "$acceptance_dir/ca.crt" \
  -CAkey "$acceptance_dir/ca.key" \
  -CAcreateserial \
  -out "$acceptance_dir/agent.crt" \
  -days 1 \
  -copy_extensions copy >/dev/null 2>&1
openssl verify -CAfile "$acceptance_dir/ca.crt" "$acceptance_dir/agent.crt" >/dev/null

cp -R fixtures/codex "$acceptance_dir/host-a-codex"
cp -R fixtures/codex "$acceptance_dir/host-b-codex"

start_agent() {
  host_id=$1
  port=$2
  state_dir=$3
  backup_dir=$4
  codex_home=$5
  pairing_code=$6
  AMCP_HOST_ID="$host_id" \
    AMCP_AGENT_STATE_DIR="$state_dir" \
    AMCP_AGENT_BACKUP_DIR="$backup_dir" \
    target/debug/amcp-agent \
      --tcp-bind "127.0.0.1:$port" \
      --tls-cert "$acceptance_dir/agent.crt" \
      --tls-key "$acceptance_dir/agent.key" \
      --token tls-acceptance-token \
      --codex-home "$codex_home" \
      --pairing-code "$pairing_code" \
      serve >"$acceptance_dir/$host_id.out" 2>"$acceptance_dir/$host_id.err" &
  agent_pid=$!
}

start_agent tls-host-a "$port_a" "$acceptance_dir/host-a-state" "$acceptance_dir/host-a-backups" "$acceptance_dir/host-a-codex" tls-pair-a
pid_a=$agent_pid
start_agent tls-host-b "$port_b" "$acceptance_dir/host-b-state" "$acceptance_dir/host-b-backups" "$acceptance_dir/host-b-codex" tls-pair-b
pid_b=$agent_pid
cleanup() {
  kill "$pid_a" "$pid_b" 2>/dev/null || true
  wait "$pid_a" "$pid_b" 2>/dev/null || true
}
trap cleanup EXIT

for port in "$port_a" "$port_b"; do
  ready=0
  for attempt in $(seq 1 30); do
    if nc -z 127.0.0.1 "$port" 2>/dev/null; then
      ready=1
      break
    fi
    sleep 0.1
  done
  [ "$ready" = 1 ]
done

for port in "$port_a" "$port_b"; do
  target/debug/amcp-controller run-once \
    --agent-url "tcp://127.0.0.1:$port" \
    --tls-ca "$acceptance_dir/ca.crt" \
    --tls-server-name localhost \
    --token tls-acceptance-token \
    --no-start-agent \
    --provider-id codex \
    --db "$acceptance_dir/controller.sqlite" \
    --json >"$acceptance_dir/collection-$port.json"
done

host_count=$(sqlite3 "$acceptance_dir/controller.sqlite" 'select count(*) from hosts;')
provider_count=$(sqlite3 "$acceptance_dir/controller.sqlite" 'select count(*) from providers;')
artifact_count=$(sqlite3 "$acceptance_dir/controller.sqlite" 'select count(*) from artifacts;')
connection_count=$(sqlite3 "$acceptance_dir/controller.sqlite" 'select count(*) from agent_connections;')

[ "$host_count" -eq 2 ]
[ "$provider_count" -eq 2 ]
[ "$artifact_count" -gt 0 ]
[ "$connection_count" -eq 2 ]
if rg -q 'panic' "$acceptance_dir"/*.err; then
  echo "Agent panic found in temporary acceptance logs" >&2
  exit 1
fi

printf 'multi-host TLS acceptance passed\n'
printf 'temporary evidence directory: %s\n' "$acceptance_dir"
printf 'hosts: %s; providers: %s; artifacts: %s; connections: %s\n' \
  "$host_count" "$provider_count" "$artifact_count" "$connection_count"
