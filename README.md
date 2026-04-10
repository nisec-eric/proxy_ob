# proxy_ob

轻量级加密隧道代理。用 Go 语言编写，通过 ChaCha20-Poly1305 加密将本地 SOCKS5 请求安全转发到远端服务器。

## 功能特性

- 单可执行文件，支持 client / server 双模式运行
- SOCKS5 TCP CONNECT 代理协议（RFC 1928）
- ChaCha20-Poly1305 AEAD 加密隧道
- 预共享密钥认证（支持密码短语和 hex 密钥两种输入方式）
- 跨平台：Linux / Windows / macOS
- 命令行参数 + 可选 JSON 配置文件
- 优雅关闭（Ctrl+C）
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

数据流：

1. 应用程序发送 SOCKS5 请求到本地 1080 端口
2. Client 解析 SOCKS5 CONNECT 请求，提取目标地址
3. Client 建立到远端 Server 的 TCP 连接
4. 双方通过 HMAC-SHA256 密钥令牌进行握手认证
5. Client 将目标地址加密后发送给 Server
6. Server 解密目标地址，建立到目标的 TCP 连接
7. 双向数据通过 ChaCha20-Poly1305 加密隧道中继

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
proxy_ob <client|server|version> [flags]
```

### client 子命令

在本地启动 SOCKS5 代理，将流量通过加密隧道转发到远端服务器。

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-l` | 本地 SOCKS5 监听地址 | `:1080` |
| `-s` | 远端隧道服务器地址（必填） | 无 |
| `-k` | 加密密钥（必填） | 无 |
| `-c` | JSON 配置文件路径 | 无 |

示例：

```bash
./proxy_ob client -s "1.2.3.4:8388" -k "my-secret-password"
./proxy_ob client -s "1.2.3.4:8388" -k "0123456789abcdef...abcdef" -l :9090
```

### server 子命令

在远端服务器启动隧道监听，接收客户端连接并转发到目标地址。

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-l` | 隧道监听地址 | `:8388` |
| `-k` | 加密密钥（必填） | 无 |
| `-c` | JSON 配置文件路径 | 无 |

示例：

```bash
./proxy_ob server -l :8388 -k "my-secret-password"
./proxy_ob server -k "abcdef...0123456789" -l :9999
```

### version 子命令

打印版本号：

```bash
./proxy_ob version
# proxy_ob v0.1.0
```

## 配置文件

可以通过 JSON 配置文件代替命令行参数。格式如下：

```json
{
  "listen": ":1080",
  "server": "your-server-ip:8388",
  "key": "your-secret-key"
}
```

字段说明：

| 字段 | 说明 | client 默认值 | server 默认值 |
|------|------|---------------|---------------|
| `listen` | 监听地址 | `:1080` | `:8388` |
| `server` | 远端服务器地址（仅 client 模式需要） | 无 | 不适用 |
| `key` | 加密密钥 | 无 | 无 |

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
```

## 项目结构

```
proxy_ob/
├── main.go              # 程序入口，子命令路由
├── go.mod               # Go 模块定义
├── config.example.json  # 配置文件示例
├── cmd/
│   ├── client.go        # 客户端模式 — SOCKS5 监听 + 隧道转发
│   └── server.go        # 服务端模式 — 隧道监听 + 目标连接
└── internal/
    ├── config.go        # 配置解析（CLI 参数 + JSON 文件 + 密钥派生）
    ├── crypto.go        # ChaCha20-Poly1305 加密/解密 + HMAC 握手令牌
    ├── tunnel.go        # 隧道帧协议（编码/解码/握手）
    └── socks5.go        # SOCKS5 TCP CONNECT 协议实现
```

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

### 并发模型

每个客户端连接分配独立 goroutine 处理。双向数据中继使用两个 goroutine：一个负责 SOCKS5 侧到隧道的加密写入，另一个负责隧道到 SOCKS5 侧的解密读取。任一方向结束即关闭整个连接。

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

## 常见问题

**支持哪些平台？**

Linux amd64、Windows amd64、macOS arm64/amd64。Go 语言的交叉编译也支持其他架构。

**支持 UDP 吗？**

不支持。当前仅实现 SOCKS5 TCP CONNECT 代理。

**如何生成安全的密钥？**

推荐使用 `openssl rand -hex 32` 生成 64 字符的 hex 密钥。密码短语也可以使用，但 hex 密钥的随机性更有保障。

**支持多个用户吗？**

不支持。所有连接共用同一个预共享密钥。如果需要多用户支持，可以在前面加一层反向代理或防火墙规则来控制访问。

**为什么选择 ChaCha20-Poly1305？**

AEAD 模式同时提供加密和完整性校验。ChaCha20 在没有 AES 硬件加速的平台上（如部分 ARM 设备）性能优于 AES-GCM，且不存在 nonce 误用的灾难性后果。

**如何在后台运行？**

Linux 推荐使用 systemd 或 `nohup`：

```bash
nohup ./proxy_ob server -l :8388 -k "my-key" > proxy.log 2>&1 &
```

Windows 可以使用 `sc.exe` 注册为系统服务，或使用 NSSM 等工具。

**连接不上，怎么排查？**

1. 检查 server 端口是否开放（防火墙/安全组）
2. 确认 client 和 server 使用相同的密钥
3. 查看 server 端日志是否有 "handshake failed" 错误
4. 用 `telnet server-ip 8388` 测试网络连通性

## 许可证

本项目仅供学习和个人使用。
