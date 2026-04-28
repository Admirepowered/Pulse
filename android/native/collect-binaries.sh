#!/usr/bin/env bash
set -euo pipefail

# Collect cross-compiled binaries into android/app/src/main/jniLibs/

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
NATIVE_DIR="$ROOT_DIR/android/native"
BUILD_DIR="$NATIVE_DIR/build/install"
JNILIBS_DIR="$ROOT_DIR/android/app/src/main/jniLibs"

ABIS=("arm64-v8a" "armeabi-v7a" "x86_64")

for ABI in "${ABIS[@]}"; do
    SRC="$BUILD_DIR/$ABI/bin/vless_proxy"
    DST_DIR="$JNILIBS_DIR/$ABI"
    mkdir -p "$DST_DIR"

    if [ -f "$SRC" ]; then
        cp "$SRC" "$DST_DIR/vless_proxy"
        chmod 755 "$DST_DIR/vless_proxy"
        echo "Copied $ABI binary ($(du -h "$DST_DIR/vless_proxy" | cut -f1))"
    else
        echo "Warning: $ABI binary not found at $SRC"
    fi
done

echo "Binaries collected to $JNILIBS_DIR"
