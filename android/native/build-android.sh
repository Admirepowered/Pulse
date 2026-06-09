#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="$ROOT_DIR/android/native/build/arm64-v8a"
mkdir -p "$OUT_DIR"

NDK_HOME="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}"
if [[ -z "$NDK_HOME" && -n "${ANDROID_HOME:-}" ]]; then
  NDK_HOME="$(find "$ANDROID_HOME/ndk" -maxdepth 1 -mindepth 1 -type d 2>/dev/null | sort -V | tail -n 1 || true)"
fi

if [[ -z "$NDK_HOME" || ! -d "$NDK_HOME" ]]; then
  echo "ANDROID_NDK_HOME or ANDROID_NDK_ROOT is required" >&2
  exit 1
fi

HOST_TAG="linux-x86_64"
if [[ "$(uname -s)" == "Darwin" ]]; then
  HOST_TAG="darwin-x86_64"
fi

CLANG="$NDK_HOME/toolchains/llvm/prebuilt/$HOST_TAG/bin/aarch64-linux-android23-clang"
if [[ ! -x "$CLANG" ]]; then
  echo "Android clang not found: $CLANG" >&2
  exit 1
fi

cd "$ROOT_DIR"
CC="$CLANG" CGO_ENABLED=1 GOOS=android GOARCH=arm64 \
  go build -buildvcs=false -trimpath -buildmode=c-shared \
  -tags "cmfa with_gvisor" \
  -o "$OUT_DIR/libpulsecore.so" ./android/native/pulsecore

ls -lh "$OUT_DIR/libpulsecore.so"
