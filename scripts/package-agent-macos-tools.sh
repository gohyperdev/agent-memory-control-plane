#!/bin/sh
# Packages the small, source-only macOS bootstrap tooling published alongside
# Agent binaries. It contains no built binary, credentials, TLS material, or
# Codex state.
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
output_dir=${1:-"$repo_root/dist/agent"}
archive_name=amcp-agent-macos-tools.tar.gz
archive="$output_dir/$archive_name"

mkdir -p "$output_dir"
staging=$(mktemp -d "${TMPDIR:-/tmp}/amcp-agent-tools-package.XXXXXX")
trap 'rm -rf "$staging"' EXIT HUP INT TERM
package_dir="$staging/amcp-agent-macos-tools"
mkdir -p "$package_dir/scripts" "$package_dir/packaging/macos"
cp "$repo_root/scripts/install-agent-macos-release.sh" "$package_dir/scripts/"
cp "$repo_root/scripts/configure-macos-remote-agent.sh" "$package_dir/scripts/"
cp "$repo_root/packaging/macos/com.gohyperdev.amcp.remote-agent.plist.template" \
  "$package_dir/packaging/macos/"
chmod 755 "$package_dir/scripts/"*.sh

tar -C "$staging" -czf "$archive" amcp-agent-macos-tools
(
  cd "$output_dir"
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$archive_name" >SHA256SUMS
  else
    sha256sum "$archive_name" >SHA256SUMS
  fi
)
printf 'packaged %s\n' "$archive"
