#!/usr/bin/env bash
set -euo pipefail

echo "========================================="
echo "  PulseProxy Android Build (WSL)"
echo "========================================="


echo "$PASS" | sudo -S echo "sudo OK" 2>/dev/null

export DEBIAN_FRONTEND=noninteractive

# ---- Step 1: Install system dependencies ----
echo ""
echo ">>> Step 1: Installing system dependencies..."
echo "$PASS" | sudo -S apt-get update -qq
echo "$PASS" | sudo -S apt-get install -y -qq \
    openjdk-17-jdk-headless \
    unzip \
    curl \
    wget \
    git \
    make \
    clang \
    > /dev/null 2>&1

export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
export PATH="$JAVA_HOME/bin:$PATH"
echo "  Java: $(java -version 2>&1 | head -1)"

# ---- Step 2: Install Android SDK command-line tools ----
echo ""
echo ">>> Step 2: Installing Android SDK..."
ANDROID_SDK_ROOT="/opt/android-sdk"
ANDROID_HOME="$ANDROID_SDK_ROOT"
echo "$PASS" | sudo -S mkdir -p "$ANDROID_SDK_ROOT/cmdline-tools"
echo "$PASS" | sudo -S chown -R "$(whoami)" "$ANDROID_SDK_ROOT"

CMDLINE_TOOLS_URL="https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip"
TMP_ZIP="/tmp/cmdline-tools.zip"
if [ ! -f "$ANDROID_SDK_ROOT/cmdline-tools/latest/bin/sdkmanager" ]; then
    echo "  Downloading Android command-line tools..."
    curl -fsSL "$CMDLINE_TOOLS_URL" -o "$TMP_ZIP"
    unzip -q -o "$TMP_ZIP" -d /tmp/cmdline-tools-tmp
    rm -rf "$ANDROID_SDK_ROOT/cmdline-tools/latest"
    mv /tmp/cmdline-tools-tmp/cmdline-tools "$ANDROID_SDK_ROOT/cmdline-tools/latest"
    rm -rf /tmp/cmdline-tools-tmp "$TMP_ZIP"
fi

export ANDROID_HOME
export ANDROID_SDK_ROOT
export PATH="$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools:$PATH"

echo "  Accepting licenses..."
yes | sdkmanager --licenses > /dev/null 2>&1 || true

echo "  Installing SDK packages..."
sdkmanager "platform-tools" "platforms;android-35" "build-tools;35.0.0" --verbose 2>&1 | tail -3

# ---- Step 3: Install NDK ----
echo ""
echo ">>> Step 3: Installing NDK..."
NDK_VERSION="23.2.8568313"
NDK_DIR="$ANDROID_HOME/ndk/$NDK_VERSION"
if [ ! -d "$NDK_DIR" ]; then
    sdkmanager "ndk;$NDK_VERSION" --verbose 2>&1 | tail -3
fi
export ANDROID_NDK_HOME="$NDK_DIR"
export ANDROID_NDK_ROOT="$NDK_DIR"
echo "  NDK: $NDK_DIR"
ls -la "$NDK_DIR/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android21-clang" 2>/dev/null && echo "  NDK toolchain OK"

# ---- Step 4: Sync third-party sources ----
echo ""
echo ">>> Step 4: Syncing third-party sources..."
PROJECT_DIR="/mnt/e/Project/Pulse"
cd "$PROJECT_DIR"
chmod +x scripts/sync_third_party.sh
bash scripts/sync_third_party.sh all

# ---- Step 5: Download Country.mmdb ----
echo ""
echo ">>> Step 5: Downloading Country.mmdb..."
mkdir -p android/app/src/main/assets
if [ ! -f android/app/src/main/assets/Country.mmdb ]; then
    curl -fsSL -o android/app/src/main/assets/Country.mmdb \
        https://github.com/Dreamacro/maxmind-geoip/releases/latest/download/Country.mmdb
fi
ls -lh android/app/src/main/assets/Country.mmdb

# ---- Step 6: Cross-compile native binaries ----
echo ""
echo ">>> Step 6: Cross-compiling native binaries..."
chmod +x android/native/build-android.sh
./android/native/build-android.sh

# ---- Step 7: Collect binaries ----
echo ""
echo ">>> Step 7: Collecting native binaries..."
chmod +x android/native/collect-binaries.sh
./android/native/collect-binaries.sh
ls -lhR android/app/src/main/jniLibs/

# ---- Step 8: Generate Gradle wrapper and build APK ----
echo ""
echo ">>> Step 8: Building APK..."
cd android

# Generate local.properties
echo "sdk.dir=$ANDROID_HOME" > local.properties
echo "ndk.dir=$ANDROID_NDK_HOME" >> local.properties

# Install Gradle if needed
if ! command -v gradle &>/dev/null; then
    echo "  Installing Gradle..."
    GRADLE_VER="8.11.1"
    GRADLE_ZIP="/tmp/gradle-${GRADLE_VER}-bin.zip"
    if [ ! -f "$GRADLE_ZIP" ]; then
        curl -fsSL "https://services.gradle.org/distributions/gradle-${GRADLE_VER}-bin.zip" -o "$GRADLE_ZIP"
    fi
    echo "$PASS" | sudo -S unzip -q -o "$GRADLE_ZIP" -d /opt
    echo "$PASS" | sudo -S ln -sf /opt/gradle-${GRADLE_VER}/bin/gradle /usr/local/bin/gradle
fi

echo "  Gradle version: $(gradle --version 2>&1 | head -3)"

# Generate wrapper if missing
if [ ! -f "gradlew" ]; then
    echo "  Generating Gradle wrapper..."
    gradle wrapper --gradle-version 8.11.1
fi
chmod +x gradlew

echo "  Building release APK..."
./gradlew assembleRelease --no-daemon 2>&1

echo ""
echo "========================================="
echo "  Build Complete!"
echo "========================================="
echo "  APK location:"
ls -lh app/build/outputs/apk/release/*.apk 2>/dev/null || echo "  (check build output above for errors)"
