#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SRC_DIR="$ROOT_DIR/third_party/src"
BUILD_ROOT="${PULSE_LINUX_BUILD_DIR:-/tmp/pulse-third-party-build}"
PREFIX_DIR="${PULSE_LINUX_PREFIX:-$ROOT_DIR/third_party/prefix/linux}"

. "$ROOT_DIR/third_party/versions.sh"

OPENSSL_SRC_DIR="$SRC_DIR/openssl-$OPENSSL_TAG"
NGHTTP3_SRC_DIR="$SRC_DIR/nghttp3-$NGHTTP3_VERSION"
OPENSSL_BUILD_DIR="$BUILD_ROOT/openssl-$OPENSSL_TAG"
NGHTTP3_BUILD_DIR="$BUILD_ROOT/nghttp3-$NGHTTP3_VERSION"
JOBS="${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)}"

prepare_build_tree() {
    local src_dir="$1"
    local build_dir="$2"

    rm -rf "$build_dir"
    mkdir -p "$build_dir"
    tar -C "$src_dir" -cf - . | tar -C "$build_dir" -xf -
}

build_openssl() {
    if [ -f "$PREFIX_DIR/include/openssl/quic.h" ] &&
       [ -f "$PREFIX_DIR/lib/pkgconfig/openssl.pc" ] &&
       grep -q 'OSSL_QUIC_client_method' "$PREFIX_DIR/include/openssl/quic.h"; then
        echo "==> OpenSSL ${OPENSSL_VERSION} already available in $PREFIX_DIR"
        return
    fi

    echo "==> Building OpenSSL ${OPENSSL_VERSION}"
    if [ ! -d "$OPENSSL_SRC_DIR" ]; then
        echo "Missing vendored source: $OPENSSL_SRC_DIR"
        echo "Run ./scripts/sync_third_party.sh first."
        exit 1
    fi
    prepare_build_tree "$OPENSSL_SRC_DIR" "$OPENSSL_BUILD_DIR"

    cd "$OPENSSL_BUILD_DIR"
    make distclean >/dev/null 2>&1 || true
    ./Configure linux-x86_64 \
        --prefix="$PREFIX_DIR" \
        --openssldir="$PREFIX_DIR/ssl" \
        --libdir=lib \
        shared
    make -j"$JOBS"
    make install_sw
}

prepare_nghttp3_source() {
    if [ ! -d "$NGHTTP3_SRC_DIR" ]; then
        echo "Missing vendored source: $NGHTTP3_SRC_DIR"
        echo "Run ./scripts/sync_third_party.sh first."
        exit 1
    fi

    if [ ! -f "$NGHTTP3_SRC_DIR/lib/sfparse/sfparse.h" ]; then
        echo "Vendored nghttp3 source is incomplete: missing lib/sfparse."
        echo "Run ./scripts/sync_third_party.sh again."
        exit 1
    fi

    prepare_build_tree "$NGHTTP3_SRC_DIR" "$NGHTTP3_BUILD_DIR"
}

build_nghttp3() {
    if [ -f "$PREFIX_DIR/lib/pkgconfig/libnghttp3.pc" ]; then
        echo "==> nghttp3 ${NGHTTP3_VERSION} already available in $PREFIX_DIR"
        return
    fi

    echo "==> Building nghttp3 ${NGHTTP3_VERSION}"
    prepare_nghttp3_source

    cd "$NGHTTP3_BUILD_DIR"
    autoreconf -fi
    ./configure \
        --prefix="$PREFIX_DIR" \
        --libdir="$PREFIX_DIR/lib" \
        --enable-lib-only
    make -j"$JOBS"
    make install
}

mkdir -p "$SRC_DIR" "$BUILD_ROOT" "$PREFIX_DIR"

build_openssl
build_nghttp3

echo
echo "Linux dependencies installed to:"
echo "  $PREFIX_DIR"
echo "Build workspace:"
echo "  $BUILD_ROOT"
echo
echo "You can now build inside WSL with:"
echo "  make OBJ_DIR=obj/linux BIN_DIR=bin/linux"
