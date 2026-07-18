#!/bin/sh
# Packages one already-built, target-specific AMCP Agent binary for a GitHub
# Release. Signing/notarization is intentionally separate from this developer
# artifact step; the matching SHA-256 receipt is emitted beside the archive.
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
target=${1:?usage: package-agent-release.sh <rust-target> [output-directory]}
output_dir=${2:-"$repo_root/dist/agent"}
binary="$repo_root/target/$target/release/amcp-agent"
archive_name="amcp-agent-$target.tar.gz"
archive="$output_dir/$archive_name"

if [ ! -x "$binary" ]; then
  echo "missing executable Agent binary: $binary" >&2
  exit 1
fi

mkdir -p "$output_dir"
staging=$(mktemp -d "${TMPDIR:-/tmp}/amcp-agent-package.XXXXXX")
trap 'rm -rf "$staging"' EXIT HUP INT TERM
package_dir="$staging/amcp-agent-$target"
mkdir -p "$package_dir"
cp "$binary" "$package_dir/amcp-agent"
chmod 755 "$package_dir/amcp-agent"

tar -C "$staging" -czf "$archive" "amcp-agent-$target"
(
  cd "$output_dir"
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$archive_name" >SHA256SUMS
  else
    sha256sum "$archive_name" >SHA256SUMS
  fi
)

printf 'packaged %s\n' "$archive"
