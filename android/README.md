# Pulse Android

Pulse Android 是桌面版 Pulse 的原生 Android 实现，使用 Material Design 3 + Jetpack Compose 构建界面，通过 Android `VpnService` 接管网络流量。核心方向保持为 Go 语言 mihomo，Android 层负责权限、前台服务、配置管理和 UI。

## 当前结构

- `app/`: Android 应用工程。
- `app/src/main/java/com/admirepowered/pulse/ui/`: Compose 页面、状态模型和主题。
- `app/src/main/java/com/admirepowered/pulse/vpn/`: `VpnService` 实现，负责申请并持有 TUN fd。
- `app/src/main/java/com/admirepowered/pulse/core/`: Go native core 加载入口。
- `native/pulsecore/`: Go `c-shared` native library，目前链接 mihomo 版本常量并预留 start/stop/fd 接口。
- `native/build-android.sh`: 使用 Android NDK 交叉编译 `libpulsecore.so`。
- `native/collect-binaries.sh`: 将 native library 收集到 `app/src/main/jniLibs/arm64-v8a/`。

## 构建

需要 Android SDK、NDK 和 Go。WSL 环境建议：

```bash
export ANDROID_HOME=/opt/android-sdk
export ANDROID_NDK_HOME=/mnt/e/Tools/android-ndk-r23c
go env -w GOPROXY=https://goproxy.cn,direct GOSUMDB=sum.golang.google.cn
cd /mnt/e/Project/Pulse
chmod +x android/native/build-android.sh android/native/collect-binaries.sh
android/native/build-android.sh
android/native/collect-binaries.sh
cd android
gradle wrapper --gradle-version 8.11.1
./gradlew assembleDebug
./gradlew assembleRelease
```

本地 release 包默认使用 Android debug keystore 签名，产物是：

```bash
adb install -r app/build/outputs/apk/release/app-release.apk
```

如果看到 `app-release-unsigned.apk`，说明使用的是旧构建产物，重新执行 `./gradlew assembleRelease` 即可。

CI 使用 `.github/workflows/build-android.yml`，只在 `android/**` 或 Android workflow 自身发生变更时触发。桌面构建 workflow 已忽略 Android-only 变更。

## 设计约定

- Android 使用 `VpnService`，不迁移 Windows 的 TUN 管理项。
- UI 保持桌面版主要动线：主页、订阅、节点、连接、设置。
- 主题支持浅色、深色、跟随系统。
- 订阅 URL 会下载到 app 数据目录 `files/profiles/`，当前订阅会写入 SharedPreferences。
- VPNService 会建立 TUN fd，并把 fd 复制后交给 Go mihomo core。
- Go core 启动前会读取当前 YAML，注入 Android `tun.file-descriptor`、`tun.enable`、`dns-hijack` 和 `external-controller: 127.0.0.1:9090`。
- 节点页通过 mihomo API `/proxies` 读取策略组节点，点击节点会调用 `/proxies/{group}` 切换。
- Android 快捷启动使用 Quick Settings Tile。首次使用仍需先进入 App 完成 VPN 权限授权。

## Native Core 接口

Go library 当前导出 C/JNI 两类入口：

- `PulseCoreMihomoVersion`
- `PulseCoreStart`
- `PulseCoreStop`
- `PulseCoreRunning`
- `PulseCoreFreeString`
- `PulseCoreBridge.nativeVersion`
- `PulseCoreBridge.nativeStart`
- `PulseCoreBridge.nativeStop`
- `PulseCoreBridge.nativeRunning`
- `PulseCoreBridge.nativeLastError`

Android 将配置路径、home 目录和 TUN fd 传给 Go core，Go core 负责启动 mihomo、处理 TUN 包、暴露状态和错误信息。

## Review 重点

- `PulseVpnService` 是否符合 Android 版本的前台服务限制。
- TUN fd 的生命周期是否只由 VPNService 管理。
- Go bridge 接 mihomo 时不要把桌面端 Windows service 逻辑带入 Android。
- Compose 页面继续拆分，不要把新功能堆到单个 Kotlin 文件里。
- 正式发布证书建议进入 Gradle signingConfig，不再用 GitHub Action 二次签名 APK。
