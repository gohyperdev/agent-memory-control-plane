#!/bin/sh
# Builds the AMCP executables that Tauri packages as desktop sidecars.
# Tauri requires the target triple in the source filename, then removes it
# while copying each executable next to the desktop application at bundle time.
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
target_triple=${AMCP_SIDECAR_TARGET:-$(rustc -vV | sed -n 's/^host: //p')}

if [ -z "$target_triple" ]; then
  echo "could not determine Rust target triple" >&2
  exit 1
fi

case "$target_triple" in
  *windows*) executable_suffix=.exe ;;
  *) executable_suffix= ;;
esac

cargo build --manifest-path "$repo_root/Cargo.toml" --release --target "$target_triple" \
  --bin amcp-agent --bin amcp-controller --bin amcp-mcp

sidecar_dir="$repo_root/apps/amcp-desktop/src-tauri/binaries"
mkdir -p "$sidecar_dir"
for binary in amcp-agent amcp-controller amcp-mcp; do
  source_path="$repo_root/target/$target_triple/release/$binary$executable_suffix"
  destination="$sidecar_dir/$binary-$target_triple$executable_suffix"
  if [ ! -f "$source_path" ]; then
    echo "missing built sidecar: $source_path" >&2
    exit 1
  fi
  cp "$source_path" "$destination"
  chmod +x "$destination"
done

printf 'Prepared AMCP desktop sidecars for %s\n' "$target_triple"
