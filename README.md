# Pulse Proxy

一个用 C 写的本地代理：

- 本地提供 `SOCKS5` / `HTTP` / `mixed` 入站
- 远端按统一协议出站接口调度
- 支持 `TCP`
- 支持 `VLESS TCP`
- 支持 `VLESS TLS + WebSocket`
- 支持 `Shadowsocks TCP AEAD`
- 支持 `VMess TCP`
- 支持 `VMess TLS + WebSocket`
- 支持 `Trojan TLS`
- 支持 `Trojan TLS + WebSocket`
- 支持 `Hysteria2 QUIC + HTTP/3` 认证和 TCP 转发
- 支持主配置加载其他配置文件
- 支持 `rules` 规则匹配选择 `proxy` / `direct` / `reject`
- 支持订阅下载命令 `vless sub`
- 已为 `SS / SSR / VMess / TUIC / AnyTLS` 预留统一配置、订阅识别和出站扩展位

当前可运行的出站协议：

- `SS`
- `VMess`
- `VLESS`
- `Trojan`
- `Hysteria2`
- `direct`

当前已接入配置模型但尚未完整实现运行时转发的协议：

- `SSR`
- `TUIC`
- `AnyTLS`

当前不支持或未完整支持：

- `UDP ASSOCIATE`
- `flow` / XTLS / REALITY
- `client-fingerprint` 的 uTLS 指纹模拟
- `Hysteria2` 的 UDP 转发
- `SSR / TUIC / AnyTLS` 的完整运行时出站握手
- `Shadowsocks` 的插件模式、UDP、AEAD-2022
- `VMess AEAD` 请求头、UDP、mux、padding / authenticated-length / alterId 高级兼容

## 构建

Windows:

```bash
make
```

Linux:

```bash
bash scripts/build_linux_deps.sh
make OBJ_DIR=obj/linux BIN_DIR=bin/linux
```

## 运行

默认读取：

```text
config/config.toml
```

启动代理：

```bash
bin/vless_proxy.exe run
```

或指定配置：

```bash
bin/vless_proxy.exe run path/to/config.toml
```

下载订阅：

```bash
bin/vless_proxy.exe sub https://example.com/sub
bin/vless_proxy.exe sub https://example.com/sub --proxy
bin/vless_proxy.exe sub https://example.com/sub --proxy 127.0.0.1:1081
```

说明：

- `vless run` 才会真正启动代理服务
- `vless sub URL --proxy` 不带地址时，默认走已经运行的本地 `127.0.0.1:1080`
- `vless sub URL --proxy host:port` 会改为走指定的 SOCKS5 代理下载订阅
- 订阅返回值会按 base64 文本解码，再解析 `ss://` / `vmess://` / `vless://` / `hysteria2://` / `trojan://`
- 保存路径为 `config/<订阅域名>.toml`

## 源码目录

- `src/app`:
  程序入口
- `src/core`:
  平台适配、公共数据模型、公共 IO
- `src/inbounds`:
  入站监听、HTTP/SOCKS5/mixed 握手
- `src/outbounds`:
  协议出站实现与公共流层
- `src/manager`:
  配置加载、订阅管理

## 配置模型

主配置文件负责：

- `[local]`
- `[main]`
- `[rules.*]`
- `[regions.*]`
- 本地手写的 `[endpoints.*]`
- `include = [...]`

被 `include` 的外部配置文件只建议放：

- `[endpoints.<key>]`
- `[endpoints.<key>.ws-opts]`

外部配置允许数字键，例如：

```toml
[endpoints.0]
type = "vless"
...
```

然后在主配置里可以这样引用：

```toml
[main]
include = ["subscription.example.toml"]
endpoint = "subscription.example[0]"
```

## 规则

规则仅在主配置文件里生效，例如：

```toml
[rules.direct-cn]
action = "direct"
domain-suffixes = ["qq.com", "bilibili.com"]

[rules.proxy-openai]
action = "proxy"
endpoint = "subscription.example[0]"
domains = ["api.openai.com", "*.openai.com"]

[regions.cn]
cidrs = ["1.0.1.0/24", "223.5.5.0/24"]

[rules.resolve-cn]
action = "direct"
region = "cn"
resolve = true
```

支持字段：

- `[local].type = "socks5" | "http" | "mixed"`
- `action = "proxy" | "direct" | "reject"`
- `endpoint = "name"` 或 `endpoint = "imported-file[0]"`
- `domains = [...]`
- `domain-suffixes = [...]`
- `domain-keywords = [...]`
- `region = "name"`
- `resolve = true`

匹配逻辑：

1. 按配置顺序从上到下匹配第一条命中的规则
2. `domains` / `domain-suffixes` / `domain-keywords` 用于域名匹配
3. `region + resolve = true` 会先解析域名 IP，再判断是否落在指定区域 CIDR 内
4. 没命中规则时，走 `[main].endpoint`

## 示例

主配置见：

- [config.toml.example](/d:/Project/Pulse/config/config.toml.example)

外部订阅配置示例见：

- [subscription.toml.example](/d:/Project/Pulse/config/subscription.toml.example)
