# Pulse Android

Pulse Android 是桌面版 Pulse 的原生 Android 实现，使用 Material Design 3 + Jetpack Compose 构建界面，通过 Android `VpnService` 接管网络流量。核心仍然走 Go 语言 mihomo，Android 层负责权限、前台服务、配置管理、订阅管理和 UI。

Android 版不迁移 Windows 的 TUN 管理页面。移动端只保留 Android `VpnService` 需要的访问控制、自动连接、订阅、节点、规则、日志和设置能力。

## 当前结构

- `app/`: Android 应用工程。
- `app/src/main/java/com/admirepowered/pulse/ui/`: Compose 页面、状态模型、导航和主题。
- `app/src/main/java/com/admirepowered/pulse/ui/screens/`: 主页、订阅、节点、连接、规则、提供者、日志、设置、访问控制等页面。
- `app/src/main/java/com/admirepowered/pulse/core/`: 订阅、设置、日志、WebDAV、背景、更新检查和 mihomo API 封装。
- `app/src/main/java/com/admirepowered/pulse/vpn/`: `VpnService` 实现，负责申请并持有 TUN fd。
- `native/pulsecore/`: Go `c-shared` native library，负责启动 mihomo、接收 TUN fd、暴露 core 状态。
- `native/build-android.sh`: 使用 Android NDK 交叉编译 `libpulsecore.so`。
- `native/collect-binaries.sh`: 将 native library 收集到 `app/src/main/jniLibs/arm64-v8a/`。

## 页面功能

主要列表页的搜索框都支持一键清空，多条件列表提供重置筛选，便于在订阅、节点、连接、规则、提供者、日志和访问控制之间快速切换筛选条件。

### 主页

- 启动 / 停止 Pulse VPN。
- 切换规则、全局、直连模式。
- 显示 core 状态、版本、实时上下行、总流量和上传 / 下载双线速度图。
- 显示当前订阅、订阅流量、当前节点 / 策略组选择和代理模式，摘要面板长按可复制。
- 支持自动刷新 / 暂停、手动刷新、重启核心、复制 / 分享 / 导出当前运行状态。
- 指标卡片长按可复制单项数值，便于单独记录流量、速度、连接数或内存。
- VPN 前台通知提供规则、全局、直连动作，方便在不回到 App 的情况下快速切换；停止代理仍可通过 Quick Settings Tile 或主页完成。
- 从通知或主页切换模式成功后，通知、Quick Settings Tile 和 App 回到前台的模式显示会保持同步。

### 订阅

- 从 URL、文件、剪贴板、分享链接、分享的 YAML 文本或多个分享文件导入订阅；App 内文件选择器支持多选，剪贴板和分享文本中的多个订阅链接会按顺序导入。
- URL 导入输入框支持一键清空，便于连续测试多个订阅地址。
- 支持 `clash://install-config?url=...`、`clashmeta://`、`mihomo://` 和 `pulse://` 订阅跳转；URL 参数会兼容大小写和双重编码。
- 拉取订阅时使用 Clash Verge UA，避免服务端返回 Base64 格式。
- 订阅名称优先从订阅文件名 / 响应信息推断，失败后回退到域名。
- 显示订阅已用 / 可用 / 总流量、过期时间和更新间隔，并用进度条展示流量占用。
- 支持搜索订阅，并按全部、远程订阅、本地配置和订阅状态筛选计数；订阅状态可区分有订阅信息、无订阅信息、即将到期和已过期，计数会跟随当前搜索和类型筛选动态更新；支持按最近更新、名称、到期时间和流量使用排序。
- 标题栏可复制当前筛选后的订阅列表，内容包含当前选中项、类型、更新时间、URL 和订阅流量信息。
- 支持选择、内联重命名、内联编辑 URL、编辑 YAML、复制 URL、分享 / 导出配置、删除确认。
- 订阅卡片长按会打开和三点按钮相同的操作菜单，可快速重命名、复制订阅信息、编辑、更新、筛选同类型、筛选同状态、分享、导出或删除。
- YAML 编辑器支持配置内搜索、清空搜索、匹配高亮、基础关键词高亮、行列 / 长度状态、复制当前行、跳转到行、常用片段、关键词补全、撤销 / 重做、按光标 / 选区插入、缩进、反缩进、注释切换、清理尾随空白、复制 / 分享 / 导出当前编辑内容、基础格式诊断以及复制 / 分享诊断提示；保存前会校验是否为 mihomo YAML，误粘贴 Base64 节点列表时会直接提示。
- 支持单个订阅和全部远程订阅通过代理或直连更新，批量更新菜单也可以按设置一键更新全部远程订阅。

### 节点

- 使用 mihomo API `/proxies` 读取策略组。
- 按订阅组 / Selector 展示，默认折叠。
- 组内节点使用紧凑网格展示，适配两列或三列。
- 支持搜索、节点状态摘要、按分组类型以及全部 / 当前 / 已测速 / 未测速 / 超时筛选并动态计数、按默认 / 延迟 / 名称排序、全部展开 / 收起、切换节点、测试全部节点、测试单个组、测试单个节点。
- 分组标题长按会弹出操作菜单，可展开 / 收起、测速当前分组、复制分组信息或复制当前节点。
- 节点长按会弹出操作菜单，可切换、测速、复制节点名称、筛选当前节点或筛选同分组，对应桌面端右键菜单的移动端交互。
- 支持复制 / 分享 / 导出当前筛选后的节点视图。

### 连接

- 放在设置页的二级页面中。
- 支持活动连接和已断开连接两个视图。
- 显示总流量、实时速度、连接数等概览。
- 支持自动刷新 / 暂停、手动刷新、搜索、网络 / 类型 / 规则 / 进程摘要、按网络类型 / 连接类型 / 规则命中 / 进程筛选并动态计数、重置筛选、排序、展开详情、复制 / 分享 / 导出筛选结果、结束单个连接、确认关闭全部连接和清空已断开历史。
- 连接长按会弹出操作菜单，可复制、展开详情，活动连接还可以直接断开，也可按当前连接筛选同网络、同类型、同规则或同进程，对应桌面端右键排查连接。

### 规则与自定义规则

- 规则页支持搜索、按类型 / 策略筛选并动态计数、按内容 / 类型 / 策略排序、刷新、复制 / 分享当前筛选结果和导出为文件。
- 规则项长按会弹出操作菜单，可复制完整规则、规则内容或策略名，也可直接筛选同类型或同策略规则，方便排查命中规则。
- 自定义规则是二级编辑页，支持搜索、按类型 / 策略筛选并动态计数、新增、编辑、上移 / 下移、按类型 / 策略 / 内容快速重排、删除确认、保存、复制、分享、剪贴板导入、文件导入和导出为文件。
- 自定义规则标题行长按会弹出操作菜单，可复制、复制为新规则、上移、下移、筛选同类型、筛选同策略或删除当前规则。
- 自定义规则保存后会重新生成运行时配置，VPN 运行中会触发核心重载 / 重启。

### 提供者

- 支持 Proxy Providers 和 Rule Providers。
- 支持搜索、按代理 / 规则 / 来源筛选并动态计数，当前视图会汇总代理 provider、规则 provider、条目总数和来源数。
- 支持按名称 / 更新时间 / 数量排序、刷新、更新单个 provider、更新当前筛选 provider、更新全部 provider。
- Provider 项长按会弹出操作菜单，可更新、复制完整信息或复制名称，也可直接筛选同类型或同来源 provider。
- 支持复制 / 分享 / 导出当前筛选后的 provider 列表。

### 日志

- 设置页二级页面。
- 汇总本地日志和 mihomo 日志。
- 支持刷新、自动刷新、搜索、错误 / 警告 / 来源摘要、按级别 / 来源筛选并动态计数、按时间 / 级别 / 来源 / 消息内容排序、复制 / 分享 / 导出筛选结果、清空日志确认。
- 日志项长按会弹出操作菜单，可复制完整日志、消息内容或来源和级别，也可直接筛选同级别或同来源日志。
- 日志页面返回会回到设置页。

### 设置

- 主题支持跟随系统、浅色、深色，并持久保存。
- 设置页支持搜索设置项，可快速定位背景、访问控制、日志、WebDAV、外部资源和更新等入口。
- 设置页的开关项支持点击整行切换，避免只点右侧小开关。
- 支持导入 App 背景图片，图片复制到 App 数据目录后再加载。
- 支持点击背景图片行选择背景、清除当前背景、删除确认、透明度和模糊强度。
- 支持允许局域网、启动时自动连接、代理更新订阅、按订阅间隔自动更新。
- 支持核心日志级别、测速 URL、测速 URL 一键清空和恢复默认、重启核心。
- 支持外部资源更新，包括 `GeoSite.dat` 和 `geoip.metadb`；单个资源失败不会阻断其它资源更新，VPN 运行中更新成功会自动重载核心。开启代理更新且 VPN 运行时，外部资源下载会优先走本地代理，失败后自动直连；资源状态行可点击复制，便于排查。
- 支持检查更新、复制更新状态、禁用自动检查更新、安装确认、下载进度提示和安装 APK 更新；开启代理更新且 VPN 运行时，GitHub Release 检查和 APK 下载会优先走本地代理，失败后自动直连。
- 支持点击版本信息行复制 Pulse Android 和 mihomo core 版本，便于反馈问题。
- 支持 WebDAV 同步和本地备份导入 / 导出，WebDAV 状态可一键复制，URL 和用户名可一键清空，WebDAV 密码可临时显示或隐藏，恢复类操作会先确认；备份会包含订阅、设置、自定义规则和 App 数据目录内的背景图片，恢复后背景会重新写入当前设备数据目录。
- Quick Settings Tile 可快速启动 / 停止代理，运行中会显示当前规则、全局或直连模式；首次未授权时会打开 App 并直接发起 VPN 授权。

### 访问控制

- 独立二级页面，从设置页进入。
- 顶部直接选择黑名单、白名单或关闭，不需要额外进入开关再切模式。
- 读取完整已安装应用列表，支持按全部应用 / 用户应用 / 系统应用筛选，再按全部 / 已选 / 未选筛选并动态计数。
- 支持搜索应用、按名称 / 包名 / 选择状态排序、逐个勾选、全选、清空和反选。
- 应用项长按会弹出操作菜单，可选中 / 取消选中、复制应用信息或复制包名。
- 支持复制、分享或导出当前筛选列表，也可以只复制或分享已选应用，便于备份和排查配置。
- 应用勾选、全选、清空和反选会合并触发运行中核心重载，避免连续选择时反复重启。
- 左上角返回和系统返回都会回到设置页。
- VPNService 会把设置写入 `VpnService.Builder`：
  - 白名单使用 `addAllowedApplication`。
  - 黑名单使用 `addDisallowedApplication`。
  - Pulse 自身默认绕过，避免代理自循环。

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

Android 将配置路径、home 目录和 TUN fd 传给 Go core。Go core 启动前会读取当前 YAML，注入 Android 运行时需要的 `tun.file-descriptor`、`tun.enable`、`dns-hijack` 和 `external-controller: 127.0.0.1:9090`。

## 构建

需要 Android SDK、NDK 和 Go。中国大陆环境建议先设置 Go 代理：

```bash
go env -w GOPROXY=https://goproxy.cn,direct GOSUMDB=sum.golang.google.cn
```

WSL 本地构建示例：

```bash
export ANDROID_HOME=/opt/android-sdk
export ANDROID_SDK_ROOT=/opt/android-sdk
export ANDROID_NDK_HOME=/mnt/e/Tools/android-ndk-r23c
cd /mnt/e/Project/Pulse
chmod +x android/native/build-android.sh android/native/collect-binaries.sh
android/native/build-android.sh
android/native/collect-binaries.sh
cd android
./gradlew assembleDebug
./gradlew assembleRelease
```

常用验证命令：

```bash
cd /mnt/e/Project/Pulse/android
./gradlew :app:compileDebugKotlin --rerun-tasks --no-daemon
./gradlew assembleDebug --no-daemon --max-workers=1
```

Release 构建已禁用 AGP 默认创建的 `mergeReleaseArtProfile`、`compileReleaseArtProfile` 和 `mergeReleaseStartupProfile`，并在 `assembleRelease` 结束后清理 `outputs/apk/release/baselineProfiles`，避免把 baseline profile 目录混进日常产物。

当前 APK 只打包 `arm64-v8a`，对应 `native/build-android.sh` 产出的 Go core。Release 构建禁用 `stripReleaseDebugSymbols`，避免本地 WSL 或 CI 在处理 Go shared library / 依赖 native library 时因为内存不足失败。

本地 release 包默认使用 Android debug keystore 签名，产物是：

```bash
adb install -r app/build/outputs/apk/release/app-release.apk
```

如果看到 `app-release-unsigned.apk`，说明使用的是旧构建产物，重新执行 `./gradlew assembleRelease` 即可。

CI 使用 `.github/workflows/build-android.yml`，只在 `android/**` 或 Android workflow 自身发生变更时触发。桌面构建 workflow 已忽略 Android-only 变更。

## Review 重点

- `PulseVpnService` 要符合 Android 前台服务限制，避免后台启动失败。
- TUN fd 的生命周期只由 `PulseVpnService` 管理。
- Go bridge 接 mihomo 时不要把桌面端 Windows service 逻辑带入 Android。
- 访问控制、自动连接、订阅更新等设置变更要在 VPN 运行中正确重载或重启 core。
- Compose 页面继续拆分，避免把新增功能堆到单个 Kotlin 文件里。
- 正式发布证书建议进入 Gradle `signingConfig`，不要长期依赖 debug keystore 或 GitHub Action 二次签名。

## 后续可继续补齐

- YAML 编辑器可以继续增强更精细的结构化补全和基于 parser 的完整校验。
- 更新提示和安装流程可以继续做更贴近桌面版的动画反馈。
- 日志、连接、节点列表可以继续补桌面端同款统计摘要、批量操作动画和更细的导出格式。
- 可以为 README 增加 Android 截图，方便发布页展示。
