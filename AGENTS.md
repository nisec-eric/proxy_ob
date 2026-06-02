# PROJECT KNOWLEDGE BASE

**Generated:** 2026-06-02
**Commit:** 55f6939
**Branch:** main

## OVERVIEW

加密隧道代理。Go 1.25, ChaCha20-Poly1305 AEAD, SOCKS5 TCP CONNECT + TCP 端口转发。单二进制 client/server/forward 三模式。唯一外部依赖 `golang.org/x/crypto`。

## STRUCTURE

```
proxy_ob/
├── main.go              # 入口路由（无业务逻辑）
├── cmd/                 # package cmd（非 main）— 运行模式实现
│   ├── client.go        # RunClient() — SOCKS5 监听 + 隧道中继
│   ├── forward.go       # RunForward() — TCP 端口转发 + 隧道中继
│   └── server.go        # RunServer() — 隧道监听 + 目标转发
├── internal/            # 共享协议库（Go internal 语义，外部不可导入）
│   ├── config.go        # CLI flags + JSON config + SHA-256 密钥派生
│   ├── crypto.go        # ChaCha20-Poly1305 加解密 + HMAC-SHA256 握手令牌
│   ├── tunnel.go        # 帧协议编解码 + 握手认证
│   └── socks5.go        # RFC 1928 SOCKS5 TCP CONNECT 子集
└── .github/workflows/
    └── build.yml        # 推 tag v* → 构建 4 平台 → GitHub Release
```

## WHERE TO LOOK

| 想做什么 | 看哪里 | 关键函数 |
|---------|--------|---------|
| 改代理协议 | `internal/socks5.go` | `Handshake`, `ReadRequest`, `SendReply` |
| 改加密方式 | `internal/crypto.go` | `Encrypt`, `Decrypt`, `HandshakeToken` |
| 改隧道帧格式 | `internal/tunnel.go` | `WriteFrame`, `ReadFrame`, `Frame` struct |
| 改配置/参数 | `internal/config.go` | `Parse`, `DeriveKey`, `Config` struct |
| 改客户端行为 | `cmd/client.go` | `RunClient`, `handleConnection`, `relay` |
| 改转发行为 | `cmd/forward.go` | `RunForward`, `handleForwardConnection`, `parseTargetAddr` |
| 改服务端行为 | `cmd/server.go` | `RunServer`, `handleServerConnection` |
| 改子命令路由 | `main.go` | `main()` |
| 改 CI/构建 | `.github/workflows/build.yml` | matrix strategy |

## CODE MAP

### internal（package internal — 7 个导出函数 + 2 个导出类型）

| 符号 | 类型 | 文件 | 作用 |
|------|------|------|------|
| `Config` | struct | config.go:13 | 配置（Mode, Listen, Server, Key, Target） |
| `Frame` | struct | tunnel.go:12 | 隧道帧（Atyp, Addr, Port, Data） |
| `Parse` | func | config.go:33 | 解析 CLI flags + JSON 配置（client/server/forward） |
| `DeriveKey` | func | config.go:128 | hex 64字符→直接密钥，否则 SHA-256 |
| `Encrypt` | func | crypto.go:14 | ChaCha20-Poly1305 加密，返回 nonce+密文+tag |
| `Decrypt` | func | crypto.go:35 | 解密 Encrypt 输出 |
| `HandshakeToken` | func | crypto.go:58 | HMAC-SHA256(key, key) → 32B 令牌 |
| `WriteFrame` | func | tunnel.go:21 | 序列化+加密帧，写入 conn |
| `ReadFrame` | func | tunnel.go:68 | 从 conn 读取+解密帧 |
| `ClientHandshake` | func | tunnel.go:150 | 客户端发送 HMAC 令牌 |
| `ServerHandshake` | func | tunnel.go:175 | 服务端验证令牌（常量时间比较） |
| `Handshake` | func | socks5.go:22 | SOCKS5 版本协商（仅 NO AUTH） |
| `ReadRequest` | func | socks5.go:46 | 解析 CONNECT 请求（IPv4/域名/IPv6） |
| `SendReply` | func | socks5.go:100 | 发送 SOCKS5 回复（10 字节固定格式） |

### cmd（package cmd — 3 个导出函数 + 2 个未导出函数）

| 符号 | 文件 | 作用 |
|------|------|------|
| `RunClient` | client.go:18 | SOCKS5 监听 → 隧道握手 → 双向中继 |
| `RunForward` | forward.go:15 | TCP 监听 → 隧道握手 → 发送预配置目标 → 双向中继 |
| `RunServer` | server.go:16 | 隧道监听 → 握手验证 → 连接目标 → 双向中继 |
| `relay` | client.go:135 | 双向中继（client/forward 共用） |
| `parseTargetAddr` | forward.go:65 | 解析 host:port → (atyp, addr, port) |

## CONVENTIONS

- **cmd/ 不是 package main** — 是 `package cmd`，导出 `RunClient()`/`RunServer()`/`RunForward()` 供 main.go 调用
- **模块名** `proxy_ob`（无 vanity URL）
- **错误处理** — 统一 `fmt.Errorf("context: %w", err)`，无自定义错误类型
- **每连接独立隧道** — 每个连接（SOCKS5 或 forward）创建一条新的 TCP 隧道到 server
- **relay 共用** — `relay()` 在 client.go 中定义，forward.go 直接复用（同 package cmd）
- **中继帧格式** — relay 帧用 `Atyp: 0x01, Addr: make([]byte, 4)` 哑值，Data 承载实际载荷
- **配置优先级** — CLI flags > JSON config > 默认值
- **forward 模式无默认 listen** — 需用户显式指定 `-l`

## ANTI-PATTERNS

- **禁止** 添加第三方依赖（`go.mod` 仅保留 `golang.org/x/crypto`）
- **禁止** 实现 UDP/BIND/多用户/连接池
- **禁止** `internal/` 包内使用 `log` 或 `fmt.Print` — 错误只返回，不打印
- **禁止** 修改帧格式而不同步更新 client、forward 和 server 的 relay 逻辑

## COMMANDS

```bash
go build -o proxy_ob .                           # 编译
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o proxy_ob_linux .  # 交叉编译
go vet ./...                                      # 静态检查
./proxy_ob server -l :8388 -k "key"              # 启动服务端
./proxy_ob client -s ip:8388 -k "key"            # 启动客户端
./proxy_ob forward -l :3306 -t 10.0.0.5:3306 -s ip:8388 -k "key"  # 端口转发
curl --socks5 127.0.0.1:1080 http://httpbin.org/ip  # 测试 SOCKS5
mysql -h 127.0.0.1 -P 3306                       # 测试端口转发
git tag v0.x.x && git push origin v0.x.x         # 触发 CI Release
```

## NOTES

- **版本号硬编码** 在 `main.go:10` — CI 的 `-ldflags="-s -w"` 未注入版本。如需自动版本，改用 `-ldflags="-X main.version=$TAG"`
- **日志不一致** — client/forward 用 `log.Printf`，server 混用 `log.Printf` + `fmt.Fprintf(os.Stderr)`
- **无测试** — 零 `_test.go` 文件
- **握手 33 字节** — `[0x01 版本] [32B HMAC-SHA256(key,key) 令牌]`，服务端用 `subtle.ConstantTimeCompare` 防时序攻击
- **Wire 帧上限** ~65KB（uint16 长度前缀），足够代理场景
- **forward 复用 server 逻辑** — 服务端不区分 SOCKS5 和 forward，仅看第一帧的目标地址
- **parseTargetAddr** — 支持 IPv4/IPv6/域名，自动判断 atyp
