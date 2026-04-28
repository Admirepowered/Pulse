#!/usr/bin/env bash
set -euo pipefail

# Local build helper: downloads mmdb, builds native binaries, assembles APK
# Usage: ./build-apk.sh [release|debug]

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
ANDROID_DIR="$ROOT_DIR/android"
BUILD_TYPE="${1:-debug}"

echo "=== Pulse Proxy Android Build ==="

# Step 1: Download Country.mmdb
echo "[1/3] Downloading Country.mmdb..."
bash "$ANDROID_DIR/scripts/download-mmdb.sh"

# Step 2: Cross-compile native binaries (if NDK available)
if [ -n "${ANDROID_NDK_HOME:-}" ]; then
    echo "[2/3] Building native binaries..."
    bash "$ANDROID_DIR/native/build-android.sh"
    bash "$ANDROID_DIR/native/collect-binaries.sh"
else
    echo "[2/3] ANDROID_NDK_HOME not set, skipping native build (use prebuilt binaries)"
fi

# Step 3: Build APK
echo "[3/3] Building Android APK ($BUILD_TYPE)..."
cd "$ANDROID_DIR"
if [ ! -f "gradlew" ]; then
    echo "Gradle wrapper not found. Generate it with: gradle wrapper"
    exit 1
fi
chmod +x gradlew
./gradlew "assemble${BUILD_TYPE^}"

APK_PATH="$ANDROID_DIR/app/build/outputs/apk/$BUILD_TYPE/app-$BUILD_TYPE.apk"
if [ -f "$APK_PATH" ]; then
    echo "APK built: $APK_PATH ($(du -h "$APK_PATH" | cut -f1))"
else
    echo "APK not found at expected path: $APK_PATH"
    find "$ANDROID_DIR/app/build" -name "*.apk" 2>/dev/null || true
fi
