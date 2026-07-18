#!/bin/sh
# Builds the macOS desktop bundle and verifies its local ad-hoc signature.
# This does not notarize the application; a Developer ID certificate and
# Apple notarization remain mandatory before distribution outside development.
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
desktop_dir="$repo_root/apps/amcp-desktop"

for dependency in npm codesign plutil; do
  if ! command -v "$dependency" >/dev/null 2>&1; then
    echo "$dependency is required for this macOS acceptance script" >&2
    exit 1
  fi
done

cd "$desktop_dir"
npm run tauri -- build --bundles app

app=src-tauri/target/release/bundle/macos/AMCP.app
if [ ! -d "$app" ]; then
  echo "Tauri did not create $app" >&2
  exit 1
fi

# Tauri leaves the local bundle unsigned when no Developer ID is configured.
# Re-sign it ad hoc to validate bundle resources and code-signing structure.
codesign --force --deep --sign - "$app"
codesign --verify --deep --strict --verbose=2 "$app"

identifier=$(plutil -extract CFBundleIdentifier raw "$app/Contents/Info.plist")
[ "$identifier" = "com.hyperdev.amcp" ]
[ -f "$app/Contents/Resources/icon.icns" ]
[ -x "$app/Contents/MacOS/amcp-desktop" ]
for sidecar in amcp-agent amcp-controller amcp-mcp; do
  [ -x "$app/Contents/MacOS/$sidecar" ]
done
"$app/Contents/MacOS/amcp-controller" --help >/dev/null

printf 'desktop bundle acceptance passed with AMCP sidecars (ad-hoc signature only)\n'
printf 'bundle: %s\n' "$desktop_dir/$app"
printf 'distribution still requires Developer ID signing and notarization\n'
