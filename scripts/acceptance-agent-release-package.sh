#!/bin/sh
# Verifies the offline, target-specific GitHub Release packaging contract.
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
case "$(uname -s):$(uname -m)" in
  Darwin:arm64) target=aarch64-apple-darwin ;;
  Darwin:x86_64) target=x86_64-apple-darwin ;;
  *) echo "this packaging acceptance currently runs on macOS" >&2; exit 1 ;;
esac

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/amcp-agent-release-acceptance.XXXXXX")
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM
cargo build --release --target "$target" --bin amcp-agent
"$repo_root/scripts/package-agent-release.sh" "$target" "$work_dir/release"
"$repo_root/scripts/package-agent-macos-tools.sh" "$work_dir/tools"

archive="$work_dir/release/amcp-agent-$target.tar.gz"
[ -f "$archive" ]
tar -tzf "$archive" | grep -qx "amcp-agent-$target/amcp-agent"
(
  cd "$work_dir/release"
  shasum -a 256 -c SHA256SUMS
)
tar -tzf "$work_dir/tools/amcp-agent-macos-tools.tar.gz" | \
  grep -qx 'amcp-agent-macos-tools/scripts/install-agent-macos-release.sh'
(
  cd "$work_dir/tools"
  shasum -a 256 -c SHA256SUMS
)
printf 'agent release packaging acceptance passed for %s\n' "$target"
