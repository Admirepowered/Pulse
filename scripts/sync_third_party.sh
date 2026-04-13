#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
THIRD_PARTY_DIR="$ROOT_DIR/third_party"
SRC_DIR="$THIRD_PARTY_DIR/src"
TMP_DIR="$(mktemp -d)"
TARGET="${1:-all}"

. "$THIRD_PARTY_DIR/versions.sh"

cleanup() {
    rm -rf "$TMP_DIR"
}

trap cleanup EXIT

download_archive() {
    local url="$1"
    local archive="$2"

    curl \
        --fail \
        --location \
        --retry 3 \
        --retry-all-errors \
        --retry-delay 1 \
        "$url" \
        -o "$archive"
}

strip_upstream_junk() {
    local dest="$1"

    rm -rf \
        "$dest/.git" \
        "$dest/.github" \
        "$dest/.clusterfuzzlite"
    rm -f \
        "$dest/.gitignore" \
        "$dest/.gitmodules"
}

extract_archive() {
    local url="$1"
    local dest="$2"
    local strip="${3:-1}"
    local archive="$TMP_DIR/archive.tar.gz"

    rm -f "$archive"
    rm -rf "$dest"
    mkdir -p "$dest"

    download_archive "$url" "$archive"

    if [ "$strip" = "1" ]; then
        tar -xzf "$archive" --strip-components=1 -C "$dest"
    else
        tar -xzf "$archive" -C "$dest"
    fi
}

sync_openssl() {
    echo "==> Syncing OpenSSL $OPENSSL_VERSION"
    extract_archive "$OPENSSL_ARCHIVE_URL" "$SRC_DIR/openssl-$OPENSSL_TAG"
    strip_upstream_junk "$SRC_DIR/openssl-$OPENSSL_TAG"
}

sync_nghttp3() {
    local nghttp3_dir="$SRC_DIR/nghttp3-$NGHTTP3_VERSION"

    echo "==> Syncing nghttp3 $NGHTTP3_VERSION"
    extract_archive "$NGHTTP3_ARCHIVE_URL" "$nghttp3_dir"
    strip_upstream_junk "$nghttp3_dir"

    echo "==> Syncing sfparse $SFPARSE_VERSION"
    extract_archive "$SFPARSE_ARCHIVE_URL" "$nghttp3_dir/lib/sfparse"
    strip_upstream_junk "$nghttp3_dir/lib/sfparse"
}

mkdir -p "$SRC_DIR"

case "$TARGET" in
    all)
        sync_openssl
        sync_nghttp3
        ;;
    openssl)
        sync_openssl
        ;;
    nghttp3)
        sync_nghttp3
        ;;
    *)
        echo "Usage: $0 [all|openssl|nghttp3]"
        exit 1
        ;;
esac

echo
echo "Third-party sources synced into:"
if [ "$TARGET" = "all" ] || [ "$TARGET" = "openssl" ]; then
    echo "  $SRC_DIR/openssl-$OPENSSL_TAG"
fi
if [ "$TARGET" = "all" ] || [ "$TARGET" = "nghttp3" ]; then
    echo "  $SRC_DIR/nghttp3-$NGHTTP3_VERSION"
fi
echo
echo "Pinned versions come from:"
echo "  $THIRD_PARTY_DIR/versions.sh"
echo "Edit that file, then rerun this script to update vendored sources."
