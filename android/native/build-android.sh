#!/usr/bin/env bash
set -euo pipefail

# Cross-compile Pulse Proxy for Android
# Requires: ANDROID_NDK_HOME environment variable
# Produces static binaries per ABI in android/native/build/install/<abi>/bin/vless_proxy

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
NATIVE_DIR="$ROOT_DIR/android/native"
THIRD_PARTY_SRC="$ROOT_DIR/third_party/src"
PULSE_SRC="$ROOT_DIR/src"
BUILD_DIR="$NATIVE_DIR/build"
INSTALL_BASE="$BUILD_DIR/install"

ABIS=("arm64-v8a" "armeabi-v7a" "x86_64")

declare -A TRIPLETS=(
    ["arm64-v8a"]="aarch64-linux-android"
    ["armeabi-v7a"]="armv7a-linux-androideabi"
    ["x86_64"]="x86_64-linux-android"
)
declare -A OPENSSL_TARGETS=(
    ["arm64-v8a"]="linux-aarch64"
    ["armeabi-v7a"]="linux-armv4"
    ["x86_64"]="linux-x86_64"
)
declare -A HOSTS=(
    ["arm64-v8a"]="aarch64-linux-android"
    ["armeabi-v7a"]="arm-linux-androideabi"
    ["x86_64"]="x86_64-linux-android"
)

API=21

if [ -z "${ANDROID_NDK_HOME:-}" ]; then
    echo "Error: ANDROID_NDK_HOME is not set"
    exit 1
fi

TOOLCHAIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64"

# Source files
PULSE_SOURCES=(
    "$PULSE_SRC/app/main.c"
    "$PULSE_SRC/core/pulse.c"
    "$PULSE_SRC/core/mmdb.c"
    "$PULSE_SRC/core/socket_io.c"
    "$PULSE_SRC/inbounds/server.c"
    "$PULSE_SRC/manager/config.c"
    "$PULSE_SRC/manager/subscription.c"
    "$PULSE_SRC/outbounds/stream.c"
    "$PULSE_SRC/outbounds/protocol_helpers.c"
    "$PULSE_SRC/outbounds/anytls.c"
    "$PULSE_SRC/outbounds/shadowsocks.c"
    "$PULSE_SRC/outbounds/stubs.c"
    "$PULSE_SRC/outbounds/trojan.c"
    "$PULSE_SRC/outbounds/vmess.c"
    "$PULSE_SRC/outbounds/vless.c"
    "$PULSE_SRC/outbounds/hysteria2.c"
)

for ABI in "${ABIS[@]}"; do
    TRIPLE="${TRIPLETS[$ABI]}"
    OPENSSL_TARGET="${OPENSSL_TARGETS[$ABI]}"
    HOST="${HOSTS[$ABI]}"
    INSTALL_DIR="$INSTALL_BASE/$ABI"
    CC="$TOOLCHAIN/bin/${TRIPLE}${API}-clang"
    AR="$TOOLCHAIN/bin/llvm-ar"
    RANLIB="$TOOLCHAIN/bin/llvm-ranlib"
    CFLAGS="-fPIC -DANDROID -D__ANDROID_API__=$API"

    echo "=== Building for $ABI ($TRIPLE) ==="

    mkdir -p "$INSTALL_DIR/lib" "$INSTALL_DIR/bin"

    # 1. Build OpenSSL (if not cached)
    if [ ! -f "$INSTALL_DIR/lib/libssl.a" ]; then
        echo "  Building OpenSSL for $ABI..."
        OPENSSL_SRC="$THIRD_PARTY_SRC/openssl-openssl-3.6.2"
        if [ ! -d "$OPENSSL_SRC" ]; then
            echo "  OpenSSL source not found at $OPENSSL_SRC, skipping OpenSSL build"
            exit 1
        fi
        (
            cd "$OPENSSL_SRC"
            export ANDROID_NDK_HOME
            export ANDROID_NDK_ROOT="$ANDROID_NDK_HOME"
            export PATH="$TOOLCHAIN/bin:$PATH"
            export CC="$TOOLCHAIN/bin/${TRIPLE}${API}-clang"
            export CXX="$TOOLCHAIN/bin/${TRIPLE}${API}-clang++"
            export AR="$TOOLCHAIN/bin/llvm-ar"
            export RANLIB="$TOOLCHAIN/bin/llvm-ranlib"
            export LD="$TOOLCHAIN/bin/ld.lld"
            export CFLAGS="-fPIC -DANDROID -D__ANDROID_API__=$API"
            export CXXFLAGS="-fPIC -DANDROID -D__ANDROID_API__=$API"
            make clean 2>/dev/null || true
            ./Configure "$OPENSSL_TARGET" \
                --prefix="$INSTALL_DIR" \
                --openssldir="$INSTALL_DIR/ssl" \
                no-tests no-shared no-dso \
                no-autoload-config no-engine \
                CC="$CC" AR="$AR" RANLIB="$RANLIB"
            make -j"$(nproc)" build_sw 2>&1 | tail -5
            make install_sw 2>&1 | tail -3
            # Ensure static libs are installed (OpenSSL install_sw sometimes skips them)
            cp -f libssl.a libcrypto.a "$INSTALL_DIR/lib/" 2>/dev/null || true
        )
        echo "  OpenSSL for $ABI done."
    else
        echo "  OpenSSL for $ABI (cached)."
    fi

    # 2. Build nghttp3 (if not cached)
    if [ ! -f "$INSTALL_DIR/lib/libnghttp3.a" ]; then
        echo "  Building nghttp3 for $ABI..."
        NGHTTP3_SRC="$THIRD_PARTY_SRC/nghttp3-1.15.0"
        if [ ! -d "$NGHTTP3_SRC" ]; then
            echo "  nghttp3 source not found at $NGHTTP3_SRC, skipping"
            exit 1
        fi
        (
            cd "$NGHTTP3_SRC"
            rm -rf build-ng3
            mkdir -p build-ng3
            cd build-ng3
            # Manual build — avoids autoconf configure script issues
            NG3_CFLAGS="-fPIC -DANDROID -D__ANDROID_API__=$API -I../lib/includes -I../lib -I../lib/sfparse -I."
            # Copy config.h template
            cat > config.h << 'NG3CONFIG'
#define HAVE_ARPA_INET_H 1
#define HAVE_STDDEF_H 1
#define HAVE_STDINT_H 1
#define HAVE_STDLIB_H 1
#define HAVE_STRING_H 1
#define HAVE_UNISTD_H 1
#define PACKAGE_NAME "nghttp3"
#define PACKAGE_VERSION "1.15.0"
#define HAVE_DECL_HTONL 1
#define HAVE_DECL_NTOHL 1
NG3CONFIG
            # Generate version.h from template
            sed 's/@PACKAGE_VERSION@/1.15.0/; s/@PACKAGE_VERSION_NUM@/0x010f00/' \
                ../lib/includes/nghttp3/version.h.in \
                > ../lib/includes/nghttp3/version.h
            # Compile all nghttp3 lib sources
            LIB_SRC=../lib
            echo '  Compiling nghttp3 sources...'
            for src in "$LIB_SRC"/*.c "$LIB_SRC"/sfparse/sfparse.c; do
                "$CC" -std=c99 $NG3_CFLAGS -c "$src" 2>&1 || exit 1
            done
            "$AR" rcs libnghttp3.a *.o
            cp libnghttp3.a "$INSTALL_DIR/lib/"
            mkdir -p "$INSTALL_DIR/include/nghttp3"
            cp "$LIB_SRC/includes/nghttp3/"*.h "$INSTALL_DIR/include/nghttp3/"
            cp "$LIB_SRC/includes/nghttp3/version.h" "$INSTALL_DIR/include/nghttp3/" 2>/dev/null || true
            cp "$LIB_SRC/"*.h "$INSTALL_DIR/include/" 2>/dev/null || true
        )
        echo "  nghttp3 for $ABI done."
    else
        echo "  nghttp3 for $ABI (cached)."
    fi

    # 3. Build Pulse Proxy
    echo "  Building pulse_proxy for $ABI..."
    "$CC" -std=c11 -O2 -Wall \
        -I"$PULSE_SRC" \
        -I"$PULSE_SRC/core" \
        -I"$INSTALL_DIR/include" \
        -DPULSE_HAVE_HYSTERIA2=1 \
        -DNGHTTP3_STATICLIB \
        -DPULSE_ANDROID \
        "${PULSE_SOURCES[@]}" \
        -L"$INSTALL_DIR/lib" \
        -lssl -lcrypto -lnghttp3 \
        -static \
        -o "$INSTALL_DIR/bin/vless_proxy"

    echo "  pulse_proxy for $ABI: $INSTALL_DIR/bin/vless_proxy"
    echo "=== $ABI done ==="
done

echo "All ABIs built successfully."
