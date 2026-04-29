#!/usr/bin/env bash
set -euo pipefail

export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
export ANDROID_HOME=/opt/android-sdk
export ANDROID_SDK_ROOT=/opt/android-sdk
export PATH="$JAVA_HOME/bin:$ANDROID_HOME/cmdline-tools/latest/bin:$PATH"

cd /mnt/e/Project/Pulse/android

# Remove any old init.gradle that conflicts
rm -f ~/.gradle/init.d/mirrors.gradle

# Generate local.properties - no ndk.dir (native libs are pre-compiled)
echo "sdk.dir=$ANDROID_HOME" > local.properties

chmod +x gradlew

echo "Starting APK build..."
./gradlew assembleRelease --no-daemon -Dorg.gradle.jvmargs="-Xmx1024m" 2>&1
