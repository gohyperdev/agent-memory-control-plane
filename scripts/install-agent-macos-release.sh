#!/bin/sh
# Downloads a versioned AMCP Agent from a GitHub Release, verifies its
# published SHA-256 digest, and atomically points the local install at it.
# It never downloads credentials, TLS keys, pairing codes, or Codex state.
set -eu

usage() {
  cat <<'EOF'
Usage:
  install-agent-macos-release.sh --repo OWNER/REPOSITORY --version vX.Y.Z [options]

Options:
  --target TARGET          Override detected Rust target triple.
  --install-dir DIRECTORY  Default: ~/Library/Application Support/AMCP
  --help                   Show this help.

The selected release must contain amcp-agent-<target>.tar.gz and SHA256SUMS.
EOF
}

repo=
version=
target=
install_dir="$HOME/Library/Application Support/AMCP"
while [ "$#" -gt 0 ]; do
  case "$1" in
    --repo) repo=${2:?missing value for --repo}; shift 2 ;;
    --version) version=${2:?missing value for --version}; shift 2 ;;
    --target) target=${2:?missing value for --target}; shift 2 ;;
    --install-dir) install_dir=${2:?missing value for --install-dir}; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

[ -n "$repo" ] || { echo "--repo is required" >&2; exit 1; }
[ -n "$version" ] || { echo "--version is required" >&2; exit 1; }
case "$repo" in */*) ;; *) echo "--repo must be OWNER/REPOSITORY" >&2; exit 1 ;; esac

if [ -z "$target" ]; then
  case "$(uname -m)" in
    arm64) target=aarch64-apple-darwin ;;
    x86_64) target=x86_64-apple-darwin ;;
    *) echo "unsupported macOS architecture: $(uname -m)" >&2; exit 1 ;;
  esac
fi

for command in curl tar awk shasum; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "$command is required" >&2
    exit 1
  }
done

archive_name="amcp-agent-$target.tar.gz"
release_base="https://github.com/$repo/releases/download/$version"
temporary=$(mktemp -d "${TMPDIR:-/tmp}/amcp-agent-install.XXXXXX")
trap 'rm -rf "$temporary"' EXIT HUP INT TERM
archive="$temporary/$archive_name"
checksums="$temporary/SHA256SUMS"

curl --fail --location --proto '=https' --tlsv1.2 "$release_base/$archive_name" -o "$archive"
curl --fail --location --proto '=https' --tlsv1.2 "$release_base/SHA256SUMS" -o "$checksums"
expected=$(awk -v name="$archive_name" '$2 == name { print $1 }' "$checksums")
[ -n "$expected" ] || { echo "SHA256SUMS does not contain $archive_name" >&2; exit 1; }
actual=$(shasum -a 256 "$archive" | awk '{ print $1 }')
[ "$actual" = "$expected" ] || { echo "release checksum verification failed" >&2; exit 1; }

tar -xzf "$archive" -C "$temporary"
source_binary="$temporary/amcp-agent-$target/amcp-agent"
[ -f "$source_binary" ] || { echo "release archive has no expected Agent binary" >&2; exit 1; }

release_dir="$install_dir/releases/$version/$target"
binary_dir="$install_dir/bin"
mkdir -p "$release_dir" "$binary_dir"
chmod 700 "$install_dir" "$install_dir/releases" "$binary_dir"
install -m 755 "$source_binary" "$release_dir/amcp-agent"
temporary_link="$binary_dir/.amcp-agent-$target-$$"
ln -s "$release_dir/amcp-agent" "$temporary_link"
mv -f "$temporary_link" "$binary_dir/amcp-agent"

if command -v codesign >/dev/null 2>&1 && codesign --verify --strict --verbose=2 "$release_dir/amcp-agent" >/dev/null 2>&1; then
  signature_status=signed
else
  signature_status=unsigned-or-unverified
fi
printf 'installed Agent: %s\nchecksum: verified\nsignature: %s\n' \
  "$binary_dir/amcp-agent" "$signature_status"
