# proxy_ob

轻量级加密隧道代理。用 Go 语言编写，通过 ChaCha20-Poly1305 加密将本地 SOCKS5/HTTP 请求安全转发到远端服务器，支持本地端口转发和反向端口转发。

## 功能特性

- 单可执行文件，支持 client / server / forward / reverse 四种模式运行
- SOCKS5 TCP CONNECT 代理协议（RFC 1928）
- HTTP/HTTPS 代理协议（CONNECT + 普通 HTTP 代理，自动检测）
- 本地端口转发（类似 SSH `-L`，映射本地端口到远程内网地址）
- 反向端口转发（类似 SSH `-R`，服务器端口映射回客户端内网）
- 反向通用代理（服务器暴露 SOCKS5/HTTP 代理，目标动态指定）
- 上游代理链（client/forward/reverse 连接 server 时穿过 HTTP/SOCKS5 入口代理）
- 出口代理链（server 连接目标、reverse 连接本地目标时穿过 HTTP/SOCKS5 出口代理）
- ChaCha20-Poly1305 AEAD 加密隧道
- 预共享密钥认证（支持密码短语和 hex 密钥两种输入方式）
- 跨平台：Linux / Windows / macOS
- 命令行参数 + 可选 JSON 配置文件
- 优雅关闭（Ctrl+C）
- Verbose 调试模式（`-v` 记录请求域名/IP 等连接详情）
- 后台 Daemon 模式（`-d` 跨平台，Linux/macOS `setsid`，Windows `CREATE_NEW_PROCESS_GROUP`）
- 零外部依赖（仅 `golang.org/x/crypto`）
- 编译后体积小：macOS 4.6MB, Linux 2.9MB, Windows 3.0MB

## 工作原理

```
本地机器 (Client)                           远端服务器 (Server)
┌──────────────────────────┐    加密隧道     ┌──────────────────────────┐
│  应用程序 (curl/浏览器)    │               │                          │
│       │                  │               │                          │
│       ▼                  │               │                          │
│  SOCKS5 监听 (:1080)      │               │  隧道监听 (:8388)         │
│       │                  │               │       │                  │
│       ▼                  │   ChaCha20    │       ▼                  │
│  SOCKS5 协议解析          │ ◄═══════════► │  握手验证 + 解密          │
│       │                  │  Poly1305加密  │       │                  │
│       ▼                  │               │       ▼                  │
│  加密 + 帧封装            │               │  目标地址解析             │
│       │                  │               │       │                  │
└───────┼──────────────────┘               └───────┼──────────────────┘
        │                                          │
        └─────────── TCP 连接 ─────────────────────┘
                                            ──────► 目标服务器 (如 httpbin.org)
```

端口转发模式：

```
本地机器 (Forward)                           远端服务器 (Server)
┌──────────────────────────┐    加密隧道     ┌──────────────────────────┐
│  本地应用 (如 MySQL 客户端) │               │                          │
│       │                  │               │                          │
│       ▼                  │               │  隧道监听 (:8388)         │
│  TCP 监听 (:3306)         │               │       │                  │
│       │                  │   ChaCha20    │       ▼                  │
│       ▼                  │ ◄═══════════► │  握手验证 + 解密          │
│  直接加密 + 帧封装         │  Poly1305加密  │       │                  │
│       │                  │  (预配置目标)   │       ▼                  │
└───────┼──────────────────┘               └───────┼──────────────────┘
        │                                          │
        └─────────── 加密隧道 ──────────────────────┘
                                           ──────► 内网目标 (如 10.0.0.5:3306)
```

数据流（SOCKS5 模式）：

1. 应用程序发送 SOCKS5 请求到本地 1080 端口
2. Client 解析 SOCKS5 CONNECT 请求，提取目标地址
3. Client 建立到远端 Server 的 TCP 连接
4. 双方通过 HMAC-SHA256 密钥令牌进行握手认证
5. Client 将目标地址加密后发送给 Server
6. Server 解密目标地址，建立到目标的 TCP 连接
7. 双向数据通过 ChaCha20-Poly1305 加密隧道中继

数据流（端口转发模式）：

1. 本地应用连接到本地监听端口（如 :3306）
2. Forward 建立到远端 Server 的加密隧道连接
3. 双方通过 HMAC-SHA256 密钥令牌进行握手认证
4. Forward 将预配置的目标地址加密后发送给 Server
5. Server 解密目标地址，建立到内网目标的 TCP 连接
6. 双向数据通过加密隧道中继

## 快速开始

```bash
# 编译
go build -o proxy_ob .

# 在远端服务器启动 (Linux)
./proxy_ob server -l :8388 -k "my-secret-password"

# 在本地机器启动 (macOS/Windows/Linux)
./proxy_ob client -s "your-server-ip:8388" -k "my-secret-password"

# 测试
curl --socks5 127.0.0.1:1080 http://httpbin.org/ip
```

## 命令行用法

```
proxy_ob <client|server|forward|version> [flags]
```

### client 子命令

在本地启动代理，自动检测 SOCKS5 和 HTTP/HTTPS 协议（同一端口），将流量通过加密隧道转发到远端服务器。

**支持的代理协议：**
- **SOCKS5** — `curl --socks5` / 浏览器 SOCKS5 代理
- **HTTPS (CONNECT)** — `curl -x http://` / 浏览器 HTTP 代理（HTTPS 网站）
- **HTTP** — 普通 HTTP 代理（绝对 URI 请求，自动改写为相对路径）

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-l` | 本地 SOCKS5/HTTP 代理监听地址 | `127.0.0.1:1080` |
| `-s` | 远端隧道服务器地址（必填） | 无 |
| `-k` | 加密密钥（必填） | 无 |
| `-P` | 入口代理 URL（连 server 时穿过，`http://host:port` 或 `socks5://host:port`） | 无 |
| `-U` | 入口代理凭证 `user:pass`（仅 HTTP Basic 认证） | 无 |
| `-v` | 详细调试日志（记录目标域名/IP） | 关闭 |
| `-d` | 后台 Daemon 模式 | 关闭 |
| `-c` | JSON 配置文件路径 | 无 |

示例：

```bash
./proxy_ob client -s "1.2.3.4:8388" -k "my-secret-password"
./proxy_ob client -s "1.2.3.4:8388" -k "0123456789abcdef...abcdef" -l :9090

# 通过公司 HTTP 代理连接 server
./proxy_ob client -s "server:8388" -k "key" -P http://corp-proxy:8080

# 通过需要 Basic 认证的 HTTP 代理
./proxy_ob client -s "server:8388" -k "key" -P http://corp-proxy:8080 -U alice:p@ss:word

# 通过 SOCKS5 上游代理连接 server
./proxy_ob client -s "server:8388" -k "key" -P socks5://127.0.0.1:1080

# SOCKS5 代理
curl --socks5 127.0.0.1:1080 http://httpbin.org/ip

# HTTP 代理
curl -x http://127.0.0.1:1080 http://httpbin.org/ip

# HTTPS 代理（CONNECT 隧道）
curl -x http://127.0.0.1:1080 https://httpbin.org/ip
```

### server 子命令

在远端服务器启动隧道监听，接收客户端连接并转发到目标地址。

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-l` | 隧道监听地址 | `:8388` |
| `-k` | 加密密钥（必填） | 无 |
| `-E` | 出口代理 URL（连接目标时穿过，`http://` 或 `socks5://`） | 无 |
| `-U` | 出口代理凭证 `user:pass`（仅 HTTP Basic） | 无 |
| `-v` | 详细调试日志 | 关闭 |
| `-d` | 后台 Daemon 模式 | 关闭 |
| `-c` | JSON 配置文件路径 | 无 |

示例：

```bash
./proxy_ob server -l :8388 -k "my-secret-password"
./proxy_ob server -k "abcdef...0123456789" -l :9999

# server 连接目标时穿过出口代理（如内网 squid）
./proxy_ob server -k "key" -E http://10.0.0.1:3128

# 出口代理需要 Basic 认证
./proxy_ob server -k "key" -E http://10.0.0.1:3128 -U 'user:pass'
```

### version 子命令

打印版本号：

```bash
./proxy_ob version
# proxy_ob v0.3.0
```

### forward 子命令

将本地 TCP 端口通过加密隧道映射到远程内网地址（类似 SSH `-L` 本地端口转发）。无需 SOCKS5 协议，目标地址在启动时预配置。

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-l` | 本地监听地址（必填） | 无 |
| `-t` | 远程目标地址 host:port（必填） | 无 |
| `-s` | 远端隧道服务器地址（必填） | 无 |
| `-k` | 加密密钥（必填） | 无 |
| `-P` | 入口代理 URL（`http://` 或 `socks5://`） | 无 |
| `-U` | 入口代理凭证 `user:pass`（仅 HTTP Basic） | 无 |
| `-v` | 详细调试日志 | 关闭 |
| `-d` | 后台 Daemon 模式 | 关闭 |
| `-c` | JSON 配置文件路径 | 无 |

示例：

```bash
# 将本地 :3306 转发到远程内网 MySQL
./proxy_ob forward -l :3306 -t 10.0.0.5:3306 -s "server-ip:8388" -k "my-secret"

# 通过上游代理连接 server
./proxy_ob forward -l :3306 -t 10.0.0.5:3306 -s "server-ip:8388" -k "my-secret" -P http://corp-proxy:8080

# 将本地 :8080 转发到远程内网 Web 服务
./proxy_ob forward -l :8080 -t internal-api.corp:80 -s "server-ip:8388" -k "my-secret"

# 同时运行多个转发实例
./proxy_ob forward -l :3306 -t 10.0.0.5:3306 -s "server-ip:8388" -k "key" &
./proxy_ob forward -l :6379 -t 10.0.0.5:6379 -s "server-ip:8388" -k "key" &
```

### reverse 子命令

将服务器端口映射回客户端网络（类似 SSH `-R` 远程端口转发）。客户端主动连接服务器建立隧道，服务器开放端口供外部访问，流量通过隧道回到客户端。

支持两种模式：
- **固定目标**：`-r 端口:目标地址:目标端口` — 每个连接映射到同一目标
- **通用代理**：`-r 端口` — 服务器暴露 SOCKS5/HTTP 代理，目标由用户动态指定

**绑定地址**（默认 `127.0.0.1` 仅本机）：
- `1080` → `127.0.0.1:1080`（仅本机）
- `:1080` → `0.0.0.0:1080`（所有接口）

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-r` | 反向规则（必填） | 无 |
| `-s` | 远端隧道服务器地址（必填） | 无 |
| `-k` | 加密密钥（必填） | 无 |
| `-P` | 入口代理 URL（连 server 时穿过，`http://` 或 `socks5://`） | 无 |
| `-E` | 出口代理 URL（连本地目标时穿过，`http://` 或 `socks5://`） | 无 |
| `-U` | 入口/出口代理凭证 `user:pass`（仅 HTTP Basic，`-P`/`-E` 共用） | 无 |
| `-v` | 详细调试日志 | 关闭 |
| `-d` | 后台 Daemon 模式 | 关闭 |
| `-c` | JSON 配置文件路径 | 无 |

`-r` 格式：

```
通用代理（仅本机）:   1080
通用代理（全接口）:   :1080
固定目标（仅本机）:   3306:10.0.0.5:3306
固定目标（全接口）:   :3306:10.0.0.5:3306
```

示例：

```bash
# 服务端（无需额外配置）
./proxy_ob server -l :8388 -k "key"

# 固定目标：服务器 :3306 → 客户端内网 10.0.0.5:3306
./proxy_ob reverse -r 3306:10.0.0.5:3306 -s server-ip:8388 -k "key"
mysql -h server-ip -P 3306

# 通用代理：服务器暴露 SOCKS5/HTTP 代理 → 客户端内网
./proxy_ob reverse -r 1080 -s server-ip:8388 -k "key"
curl --socks5 server-ip:1080 http://10.0.0.5:8080/status

# 通用代理（对外公开）
./proxy_ob reverse -r :1080 -s server-ip:8388 -k "key"
curl -x http://server-ip:1080 https://internal-api.corp
```

## 配置文件

可以通过 JSON 配置文件代替命令行参数。格式如下：

```json
{
  "listen": "127.0.0.1:1080",
  "server": "your-server-ip:8388",
  "key": "your-secret-key"
}
```

端口转发配置示例：

```json
{
  "listen": ":3306",
  "target": "10.0.0.5:3306",
  "server": "your-server-ip:8388",
  "key": "your-secret-key"
}
```

字段说明：

| 字段 | 说明 | client | server | forward | reverse |
|------|------|--------|--------|---------|---------|
| `listen` | 监听地址 | `:1080` | `:8388` | 必填 | 不适用 |
| `server` | 远端服务器地址 | 必填 | 不适用 | 必填 | 必填 |
| `key` | 加密密钥 | 必填 | 必填 | 必填 | 必填 |
| `target` | 转发目标地址 host:port | 不适用 | 不适用 | 必填 | 不适用 |
| `reverse` | 反向转发规则 | 不适用 | 不适用 | 不适用 | 必填 |
| `proxy` | 入口代理 URL | 可选 | 不适用 | 可选 | 可选 |
| `exit_proxy` | 出口代理 URL | 不适用 | 可选 | 不适用 | 可选 |
| `proxy_auth` | 代理凭证 `user:pass`（`proxy`/`exit_proxy` 共用） | 可选 | 可选 | 可选 | 可选 |
| `verbose` | 详细调试日志 | `false` | `false` | `false` | `false` |
| `daemon` | 后台 Daemon 模式 | `false` | `false` | `false` | `false` |

配置优先级：**命令行参数 > JSON 配置文件 > 默认值**

```bash
# 通过配置文件启动
./proxy_ob client -c config.json

# 命令行参数覆盖配置文件中的 listen
./proxy_ob client -c config.json -l :9090
```

项目中附带了一个示例配置文件 `config.example.json`，可以复制后修改使用。

## 密钥说明

Client 和 Server 必须使用相同的密钥。密钥支持两种输入方式：

**密码短语**：任意长度字符串，通过 SHA-256 派生为 32 字节密钥。

```bash
-k "my-password"
```

**Hex 密钥**：64 个十六进制字符，直接作为 32 字节密钥使用。

```bash
-k "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
```

推荐使用 `openssl` 生成安全的随机 hex 密钥：

```bash
openssl rand -hex 32
```

## 编译指南

```bash
# 编译当前平台
go build -o proxy_ob .

# 去除调试信息，减小体积
go build -ldflags="-s -w" -o proxy_ob .

# 交叉编译 Linux amd64
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o proxy_ob_linux .

# 交叉编译 Windows amd64
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o proxy_ob.exe .

# 交叉编译 macOS arm64
GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o proxy_ob_mac .

# 使用 Makefile 一次构建全部平台
make dist
```

或使用 Makefile：

```
make          # 编译当前平台
make dist     # 构建全部 4 平台到 dist/
make vet      # 静态检查
make clean    # 清理产物
```

## 项目结构

```
proxy_ob/
├── main.go              # 程序入口，子命令路由
├── Makefile             # 多平台构建脚本
├── go.mod               # Go 模块定义
├── config.example.json  # 配置文件示例
├── cmd/
│   ├── client.go        # 客户端模式 — SOCKS5/HTTP 代理监听 + 隧道转发
│   ├── forward.go       # 转发模式 — 本地端口转发到远程内网
│   ├── reverse.go       # 反向模式 — 服务器端口映射回客户端内网
│   ├── server.go        # 服务端模式 — 隧道监听 + 目标连接
│   ├── server_reverse.go# 服务端反向隧道处理
│   ├── daemon.go        # Daemon 模式共享逻辑（re-exec 后台）
│   ├── daemon_unix.go   # Unix: setsid 脱离终端
│   ├── daemon_windows.go# Windows: CREATE_NEW_PROCESS_GROUP 脱离控制台
│   └── log.go           # 日志 helper（infof + verbosef + dialTimeout）
└── internal/
    ├── config.go        # 配置解析（CLI 参数 + JSON 文件 + 密钥派生）
    ├── crypto.go        # ChaCha20-Poly1305 加密/解密 + HMAC 握手令牌
    ├── tunnel.go        # 隧道帧协议（编码/解码/握手）
    ├── upstream_proxy.go# 上游代理拨号（HTTP CONNECT + SOCKS5 client）
    ├── socks5.go        # SOCKS5 TCP CONNECT 协议实现
    └── http_proxy.go    # HTTP/HTTPS 代理协议解析（CONNECT + 普通 HTTP）
```

## 代理链

proxy_ob 支持在两个方向插入上游代理，组合成完整的代理链：

- **入口代理 `-P`**：client/forward/reverse 连接 server 时穿过（公司网络只能通过 corp proxy 出网）
- **出口代理 `-E`**：server 连接目标、reverse 连接本地目标时穿过（server 所在网络需要代理才能访问目标）

两个方向独立配置，可同时使用。`-U` 凭证被 `-P` 和 `-E` 共用（HTTP Basic 认证）。

```
                ┌── -P 入口代理 ──┐         ┌── -E 出口代理 ──┐
                │                 │         │                 │
应用 → client ──┼──→ [入口代理] ──┼──→ server ┼──→ [出口代理] ──┼──→ 目标
                │                 │         │                 │
            (client/forward       │      (server 模式       │
             /reverse 模式)        │       用 -E)             │
                                  │
                              加密隧道 (ChaCha20-Poly1305)
```

URL 格式：

| URL 格式 | 协议 | 说明 |
|---------|------|------|
| `http://host:port` | HTTP CONNECT | 默认端口 80，最常见（公司代理、squid） |
| `socks5://host:port` | SOCKS5 | 默认端口 1080，NO AUTH 模式 |

需要 Basic 认证的 HTTP 代理用 `-U user:pass` 单独传凭证（不走 URL 嵌入，避免特殊字符转义问题）。程序内部 base64 编码后发 `Proxy-Authorization: Basic` 头。

`-U` 格式约定：
- 冒号分隔，第一个冒号前是用户名，之后是密码（密码可含冒号、`@`、空格等任意字符）
- 用户名不能含冒号
- 仅对 HTTP 代理生效（SOCKS5 仅支持 NO AUTH）
- 同时设置 `-P` 和 `-E` 时，`-U` 凭证被两者共用

各模式的代理链支持：

| 模式 | `-P` 入口 | `-E` 出口 | 说明 |
|------|----------|----------|------|
| client | ✅ client→server | — | client 没有出口连接（目标是 SOCKS5 请求指定的） |
| forward | ✅ forward→server | — | 同上 |
| reverse | ✅ reverse→server | ✅ reverse→本地目标 | 双向代理链（罕见但支持） |
| server | — | ✅ server→target | server 没有入口（被动接受连接） |

```bash
# 入口代理：client 经过公司 corp proxy 连接公网 server
./proxy_ob client -s "server:8388" -k "key" -P http://corp-proxy.corp:8080
./proxy_ob client -s "server:8388" -k "key" -P http://corp-proxy.corp:8080 -U 'alice:p@ss:word'

# 出口代理：server 连接目标时穿过内网 squid
./proxy_ob server -k "key" -E http://10.0.0.1:3128
./proxy_ob server -k "key" -E http://10.0.0.1:3128 -U 'squid-user:pass'

# 完整代理链：client 入口代理 + server 出口代理
# (client 侧) ./proxy_ob client -s server:8388 -k key -P http://corp:8080
# (server 侧) ./proxy_ob server -k key -E http://internal-squid:3128

# 通过 JSON 配置
{
  "mode": "server",
  "key": "key",
  "exit_proxy": "http://10.0.0.1:3128",
  "proxy_auth": "squid-user:pass"
}
```

代理不参与加密隧道协议，仅做 TCP 转发，因此任何标准 HTTP/SOCKS5 代理都兼容（Squid、tinyproxy、mitmproxy、ssh -D 等）。

限制：
- SOCKS5 仅支持 NO AUTH（method 0x00），不支持用户名/密码认证
- 仅支持 `http://`（明文）和 `socks5://` 代理；不支持 `https://`（需要 TLS 拨号，本项目不引入额外依赖）
- HTTP CONNECT 的 Basic 认证凭证以 base64 明文传输（HTTP 协议本身限制），建议仅在可信内网使用

## 技术细节

### 加密算法

ChaCha20-Poly1305 (AEAD)。每次加密使用 12 字节随机 nonce，附加 16 字节认证标签。AEAD 同时提供加密和完整性校验，在非 AES 硬件加速平台上性能优秀。

### 隧道帧格式

```
[2字节长度 (big-endian)] [12字节nonce] [加密载荷] [16字节认证标签]
```

载荷明文结构（与 SOCKS5 地址编码一致）：

```
[1字节 atyp] [地址数据] [2字节端口 (big-endian)] [数据]
```

其中 atyp 取值：`0x01` = IPv4（4字节），`0x03` = 域名（1字节长度 + 域名），`0x04` = IPv6（16字节）。

### 握手认证

Client 发送 33 字节：`[0x01 版本号] [32字节 HMAC-SHA256(密钥, 密钥) 令牌]`。

Server 验证版本号和令牌，使用常量时间比较（`subtle.ConstantTimeCompare`）防止时序攻击。验证通过后回复 `[0x01, 0x00]`，失败回复 `[0x01, 0x01]`。

### SOCKS5 协议

仅支持 TCP CONNECT 命令（`0x01`），仅支持 NO AUTH 认证方式（`0x00`）。支持 IPv4、IPv6、域名三种地址类型。

### HTTP/HTTPS 代理协议

client 模式在同一端口自动检测 SOCKS5 和 HTTP 协议（首字节 `0x05` 为 SOCKS5，ASCII 字母为 HTTP）。

- **CONNECT 方法**：解析 `CONNECT host:port`，建立隧道后回复 `200 Connection established`，后续透明转发（适用于 HTTPS）
- **普通 HTTP 代理**：解析绝对 URI（如 `GET http://host/path`），提取目标 host:port，将请求行改写为相对路径后通过隧道转发，响应直接透传
- **keep-alive**：CONNECT 为隧道模式天然支持；普通 HTTP 每连接处理一次请求

### 并发模型

每个客户端连接分配独立 goroutine 处理。双向数据中继使用两个 goroutine：一个负责 SOCKS5 侧到隧道的加密写入，另一个负责隧道到 SOCKS5 侧的解密读取。任一方向结束即关闭整个连接。

端口转发模式使用相同的并发模型：本地 TCP 连接替代 SOCKS5 连接，其余逻辑一致。

## 使用场景

### 场景一：安全访问远程网络资源

在远程服务器上部署 proxy_ob server，本地通过加密隧道访问该网络中的资源。

```bash
# 远端服务器
./proxy_ob server -l :8388 -k "strong-passphrase"

# 本地
./proxy_ob client -s "203.0.113.10:8388" -k "strong-passphrase"

# 通过代理访问
curl --socks5 127.0.0.1:1080 http://internal-api.example.com/data
```

### 场景二：加密本地网络流量

在不受信任的网络环境中（如公共 WiFi），将流量加密传输到可信服务器。

```bash
# 家里的服务器
./proxy_ob server -l :8388 -k "home-key"

# 笔记本电脑
./proxy_ob client -s "home-ip:8388" -k "home-key"

# 浏览器设置 SOCKS5 代理为 127.0.0.1:1080
```

### 场景三：通过跳板机访问内网服务

跳板机运行 proxy_ob server，本地通过隧道访问内网中不可直达的服务。

```bash
# 跳板机（有内网访问权限）
./proxy_ob server -l :8388 -k "jump-key"

# 本地
./proxy_ob client -s "jump-host:8388" -k "jump-key"

# 访问内网数据库等
curl --socks5 127.0.0.1:1080 http://10.0.0.5:8080/status
```

### 场景四：端口转发访问内网数据库

将本地端口直接映射到远程内网服务的端口，无需 SOCKS5 客户端支持。适合数据库客户端、SSH 等不支持 SOCKS5 的应用。

```bash
# 跳板机（有内网访问权限）
./proxy_ob server -l :8388 -k "forward-key"

# 本地：映射本地 3306 到内网 MySQL
./proxy_ob forward -l :3306 -t 10.0.0.5:3306 -s jump-host:8388 -k "forward-key"

# 本地直接连接 MySQL
mysql -h 127.0.0.1 -P 3306 -u root -p
```

## 常见问题

**支持哪些平台？**

Linux amd64、Windows amd64、macOS arm64/amd64。Go 语言的交叉编译也支持其他架构。

**支持 UDP 吗？**

不支持。当前仅实现 SOCKS5 TCP CONNECT 代理和 TCP 端口转发。

**forward 和 client 有什么区别？**

`client` 模式启动 SOCKS5/HTTP 代理，每次连接的目标地址由代理客户端动态指定。`forward` 模式启动纯 TCP 端口转发，目标地址在启动时固定配置。forward 模式不需要客户端支持 SOCKS5 或 HTTP 代理协议。

**client 支持哪些代理协议？**

同一端口自动检测，无需配置切换：
- **SOCKS5**：标准 SOCKS5 TCP CONNECT
- **HTTPS (CONNECT)**：HTTP CONNECT 方法建立 TLS 隧道（浏览器 HTTPS 默认走这个）
- **HTTP**：普通 HTTP 代理，自动将绝对 URI 改写为相对路径转发

**可以同时运行多个 forward 实例吗？**

可以。每个 forward 实例监听不同的本地端口、映射到不同的远程目标。只需确保本地端口不冲突即可。

**reverse 和 forward 有什么区别？**

`forward` 是本地端口转发（SSH `-L`）：本地端口 → 隧道 → 服务器端连接目标。
`reverse` 是远程端口转发（SSH `-R`）：服务器端口 → 隧道 → 客户端连接内网目标。

reverse 模式适用于客户端在 NAT 后方、需要被外部主动连接的场景（如在家暴露内网服务到公网服务器）。

**reverse 的固定目标和通用代理有什么区别？**

`-r 3306:10.0.0.5:3306` 固定目标：服务器 :3306 只能连到客户端的 10.0.0.5:3306。
`-r 1080` 通用代理：服务器 :1080 暴露 SOCKS5/HTTP 代理，用户每次连接动态指定目标（如 `curl --socks5 server:1080 http://任意内网地址`）。

**如何生成安全的密钥？**

推荐使用 `openssl rand -hex 32` 生成 64 字符的 hex 密钥。密码短语也可以使用，但 hex 密钥的随机性更有保障。

**支持多个用户吗？**

不支持。所有连接共用同一个预共享密钥。如果需要多用户支持，可以在前面加一层反向代理或防火墙规则来控制访问。

**为什么选择 ChaCha20-Poly1305？**

AEAD 模式同时提供加密和完整性校验。ChaCha20 在没有 AES 硬件加速的平台上（如部分 ARM 设备）性能优于 AES-GCM，且不存在 nonce 误用的灾难性后果。

**如何在后台运行？**

使用内置 `-d` 参数（跨平台支持）。日志和 PID 文件固定落在 `~/.proxy_ob/`（家目录不可写时回退到系统临时目录），因此二进制装到 PATH 后可在任意工作目录调用 `-d`：

```bash
# 后台运行
proxy_ob server -d -k "my-key"

# 后台 + 详细日志
proxy_ob server -d -v -k "my-key"

# 停止
kill $(cat ~/.proxy_ob/proxy_ob.pid 2>/dev/null || pgrep -f "proxy_ob server")
```

或使用传统方式（日志输出就近）：

```bash
nohup proxy_ob server -l :8388 -k "my-key" > proxy.log 2>&1 &
```

**`-v` verbose 模式会记录什么？**

每条连接的源地址和目标地址（域名或 IP）：

```
client:  socks5 127.0.0.1:54321 -> httpbin.org:80
         http 127.0.0.1:54321 -> example.com:443 (connect=true)
server:  tunnel 1.2.3.4:54321 -> target 10.0.0.5:3306
forward: forward 127.0.0.1:54321 -> 10.0.0.5:3306
```

**连接不上，怎么排查？**

1. 检查 server 端口是否开放（防火墙/安全组）
2. 确认 client 和 server 使用相同的密钥
3. 查看 server 端日志是否有 "handshake failed" 错误
4. 用 `telnet server-ip 8388` 测试网络连通性

## 许可证

本项目仅供学习和个人使用。
