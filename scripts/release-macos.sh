#!/bin/sh
# Produces a signed and notarized AMCP.app. This intentionally performs an
# external Apple submission only when the caller supplies both release
# credentials below; the development acceptance script remains offline.
set -eu

usage() {
  cat <<'EOF'
Usage:
  AMCP_CODESIGN_IDENTITY='Developer ID Application: ...' \
  AMCP_NOTARY_PROFILE='notarytool-keychain-profile' \
  ./scripts/release-macos.sh

Optional:
  AMCP_SIDECAR_TARGET=<rust-target>  Build sidecars for an explicit target.

The named notary profile must already exist in the caller's macOS Keychain.
This script signs every bundled AMCP executable with hardened runtime, submits
the ZIP archive to Apple notary service, staples the accepted ticket, and
performs codesign, stapler and Gatekeeper verification.
EOF
}

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
  usage
  exit 0
fi

if [ "$(uname -s)" != "Darwin" ]; then
  echo "macOS is required for Developer ID signing and notarization" >&2
  exit 1
fi

: "${AMCP_CODESIGN_IDENTITY:?set AMCP_CODESIGN_IDENTITY to a Developer ID Application identity}"
: "${AMCP_NOTARY_PROFILE:?set AMCP_NOTARY_PROFILE to a notarytool Keychain profile}"

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
desktop_dir="$repo_root/apps/amcp-desktop"
app="$desktop_dir/src-tauri/target/release/bundle/macos/AMCP.app"
archive="$desktop_dir/src-tauri/target/release/bundle/macos/AMCP-notarization.zip"

for dependency in npm codesign ditto spctl xcrun; do
  if ! command -v "$dependency" >/dev/null 2>&1; then
    echo "$dependency is required for macOS release" >&2
    exit 1
  fi
done

case "$AMCP_CODESIGN_IDENTITY" in
  *"Developer ID Application:"*) ;;
  *)
    echo "AMCP_CODESIGN_IDENTITY must name a Developer ID Application certificate" >&2
    exit 1
    ;;
esac

cd "$desktop_dir"
npm run tauri -- build --bundles app

if [ ! -d "$app" ]; then
  echo "Tauri did not create $app" >&2
  exit 1
fi

# Sign nested executables before the application bundle. Avoid --deep because
# it masks incorrectly signed nested code and Apple's notarization guidance
# expects each executable to be signed explicitly.
for binary in amcp-agent amcp-controller amcp-mcp amcp-desktop; do
  target="$app/Contents/MacOS/$binary"
  if [ ! -x "$target" ]; then
    echo "missing bundled executable: $target" >&2
    exit 1
  fi
  codesign --force --timestamp --options runtime --sign "$AMCP_CODESIGN_IDENTITY" "$target"
done
codesign --force --timestamp --options runtime --sign "$AMCP_CODESIGN_IDENTITY" "$app"
codesign --verify --strict --verbose=2 "$app"

rm -f "$archive"
ditto -c -k --keepParent "$app" "$archive"
xcrun notarytool submit "$archive" --keychain-profile "$AMCP_NOTARY_PROFILE" --wait
xcrun stapler staple "$app"
xcrun stapler validate "$app"
spctl --assess --type execute --verbose=2 "$app"

printf 'signed and notarized AMCP release bundle: %s\n' "$app"
