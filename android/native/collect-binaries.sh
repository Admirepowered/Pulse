#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SRC="$ROOT_DIR/android/native/build/arm64-v8a/libpulsecore.so"
DST_DIR="$ROOT_DIR/android/app/src/main/jniLibs/arm64-v8a"

if [[ ! -f "$SRC" ]]; then
  echo "native library not found: $SRC" >&2
  echo "run android/native/build-android.sh first" >&2
  exit 1
fi

mkdir -p "$DST_DIR"
cp "$SRC" "$DST_DIR/libpulsecore.so"
ls -lh "$DST_DIR/libpulsecore.so"
