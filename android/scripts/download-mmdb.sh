#!/usr/bin/env bash
set -euo pipefail

# Download Country.mmdb for local builds
# Places it in android/app/src/main/assets/Country.mmdb

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
ASSETS_DIR="$ROOT_DIR/android/app/src/main/assets"
MMDB_URL="https://github.com/Dreamacro/maxmind-geoip/releases/latest/download/Country.mmdb"
DEST="$ASSETS_DIR/Country.mmdb"

mkdir -p "$ASSETS_DIR"

if [ -f "$DEST" ]; then
    SIZE=$(stat -c%s "$DEST" 2>/dev/null || stat -f%z "$DEST" 2>/dev/null || echo 0)
    if [ "$SIZE" -gt 1048576 ]; then
        echo "Country.mmdb already present ($(du -h "$DEST" | cut -f1))"
        exit 0
    fi
fi

echo "Downloading Country.mmdb..."
curl -fSL --progress-bar -o "$DEST" "$MMDB_URL"

SIZE=$(stat -c%s "$DEST" 2>/dev/null || stat -f%z "$DEST" 2>/dev/null || echo 0)
echo "Downloaded Country.mmdb ($(du -h "$DEST" | cut -f1))"
