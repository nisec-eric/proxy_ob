# PROJECT KNOWLEDGE BASE

**Generated:** 2026-06-22
**Commit:** d6394ea
**Branch:** main

## OVERVIEW

加密隧道代理。Go 1.25, ChaCha20-Poly1305 AEAD, SOCKS5 + HTTP/HTTPS 代理 + TCP 端口转发 + 反向端口转发 + 反向通用代理。单二进制 client/server/forward/reverse 四模式。唯一外部依赖 `golang.org/x/crypto`。

## STRUCTURE

```
proxy_ob/
├── main.go              # 入口路由（无业务逻辑）
├── Makefile             # 多平台构建脚本（make dist 构建全部平台）
├── cmd/                 # package cmd（非 main）— 运行模式实现
│   ├── client.go        # RunClient() — SOCKS5/HTTP 代理监听 + 自动协议检测 + 隧道中继
│   ├── forward.go       # RunForward() — TCP 端口转发 + 隧道中继
│   ├── reverse.go       # RunReverse() — 反向隧道客户端（控制连接 + 数据连接）
│   ├── server.go        # RunServer() — 隧道监听 + 目标转发 + Atyp 分发
│   ├── server_reverse.go# handleReverseRegistration() + handleReverseData() + 反通用代理
│   ├── daemon.go        # daemonize() + parseConfig() — 共享逻辑
│   ├── daemon_unix.go   # !windows — setsid 脱离终端
│   ├── daemon_windows.go# windows — CREATE_NEW_PROCESS_GROUP 脱离控制台
│   └── log.go           # infof() + verbosef() + dialTimeout 日志 helper
├── internal/            # 共享协议库（Go internal 语义，外部不可导入）
│   ├── config.go        # CLI flags + JSON config + SHA-256 密钥派生
│   ├── crypto.go        # ChaCha20-Poly1305 加解密 + HMAC-SHA256 握手令牌
│   ├── tunnel.go        # 帧协议编解码 + 握手认证
│   ├── socks5.go        # RFC 1928 SOCKS5 TCP CONNECT 子集
│   └── http_proxy.go    # HTTP/HTTPS 代理协议解析（CONNECT + 普通 HTTP）
└── .github/workflows/
    └── build.yml        # 推 tag v* → 构建 4 平台 → GitHub Release
```

## WHERE TO LOOK

| 想做什么 | 看哪里 | 关键函数 |
|---------|--------|---------|
| 改代理协议 | `internal/socks5.go` | `Handshake`, `ReadRequest`, `SendReply` |
| 改 HTTP 代理 | `internal/http_proxy.go` | `ReadHTTPProxyRequest`, `SendHTTPResponse` |
| 改加密方式 | `internal/crypto.go` | `Encrypt`, `Decrypt`, `HandshakeToken` |
| 改隧道帧格式 | `internal/tunnel.go` | `WriteFrame`, `ReadFrame`, `Frame` struct |
| 改配置/参数 | `internal/config.go` | `Parse`, `DeriveKey`, `Config` struct |
| 改客户端行为 | `cmd/client.go` | `RunClient`, `handleConnection`, `handleSOCKS5`, `handleHTTPProxy`, `relay` |
| 改协议自动检测 | `cmd/client.go` | `handleConnection` — Peek 首字节区分 SOCKS5/HTTP |
| 改转发行为 | `cmd/forward.go` | `RunForward`, `handleForwardConnection`, `parseTargetAddr` |
| 改反向隧道客户端 | `cmd/reverse.go` | `RunReverse`, `handleReverseDataConn`, `parseReverseSpec`, `resolveFrameTarget`, `generateSessionID` |
| 改反向隧道服务端 | `cmd/server_reverse.go` | `handleReverseRegistration`, `acceptReverseFixed`, `acceptReverseProxy`, `handleReverseProxyUserConn`, `handleReverseData` |
| 改服务端行为 | `cmd/server.go` | `RunServer`, `handleServerConnection`, `handleProxyTarget` |
| 改 Daemon 逻辑 | `cmd/daemon.go` + `cmd/daemon_unix.go` / `cmd/daemon_windows.go` | `daemonize`, `daemonSysProcAttr` |
| 改日志行为 | `cmd/log.go` | `infof`, `verbosef`, `initLogging` |
| 改子命令路由 | `main.go` | `main()` |
| 改 CI/构建 | `.github/workflows/build.yml` 或 `Makefile` | matrix strategy |

## CODE MAP

### internal（package internal）

| 符号 | 类型 | 文件 | 作用 |
|------|------|------|------|
| `Config` | struct | config.go | 配置（Mode, Listen, Server, Key, Target, Reverse, Verbose, Daemon） |
| `ErrHelp` | var | config.go | help 请求哨兵错误 |
| `Frame` | struct | tunnel.go | 隧道帧（Atyp, Addr, Port, Data） |
| `Parse` | func | config.go | 解析 CLI flags + JSON 配置（client/server/forward） |
| `DeriveKey` | func | config.go | hex 64字符→直接密钥，否则 SHA-256 |
| `Encrypt` | func | crypto.go | ChaCha20-Poly1305 加密，返回 nonce+密文+tag |
| `Decrypt` | func | crypto.go | 解密 Encrypt 输出 |
| `HandshakeToken` | func | crypto.go | HMAC-SHA256(key, key) → 32B 令牌 |
| `WriteFrame` | func | tunnel.go | 序列化+加密帧，写入 conn |
| `ReadFrame` | func | tunnel.go | 从 conn 读取+解密帧 |
| `ClientHandshake` | func | tunnel.go | 客户端发送 HMAC 令牌 |
| `ServerHandshake` | func | tunnel.go | 服务端验证令牌（常量时间比较） |
| `Handshake` | func | socks5.go | SOCKS5 版本协商（仅 NO AUTH） |
| `ReadRequest` | func | socks5.go | 解析 CONNECT 请求（IPv4/域名/IPv6） |
| `SendReply` | func | socks5.go | 发送 SOCKS5 回复（10 字节固定格式） |
| `ReadHTTPProxyRequest` | func | http_proxy.go | 解析 HTTP CONNECT/普通代理请求，返回目标+初始数据 |
| `SendHTTPResponse` | func | http_proxy.go | 发送 HTTP 响应（如 200 Connection established） |

### cmd（package cmd）

| 符号 | 文件 | 作用 |
|------|------|------|
| `RunClient` | client.go | SOCKS5/HTTP 代理监听 → 协议自动检测 → 隧道握手 → 双向中继 |
| `RunForward` | forward.go | TCP 监听 → 隧道握手 → 发送预配置目标 → 双向中继 |
| `RunReverse` | reverse.go | 控制连接注册 → 接收连接请求（固定/动态目标） → 发起数据连接 → 本地目标中继 |
| `RunServer` | server.go | 隧道监听 → 握手验证 → Atyp 分发 → 连接目标/反向处理 |
| `handleReverseRegistration` | server_reverse.go | Atyp=0x00: 解析 bind/target → 开固定或代理监听端口 |
| `acceptReverseFixed` | server_reverse.go | 固定目标模式：用户连入时发 Atyp=0x02 连接请求 |
| `acceptReverseProxy` | server_reverse.go | 通用代理模式：SOCKS5/HTTP 握手 + 发带目标地址的连接请求 |
| `handleReverseData` | server_reverse.go | Atyp=0x05: 匹配 session ID，发送 initialData，relay 用户连接和数据连接 |
| `handleProxyTarget` | server.go | Atyp=0x01/0x03/0x04: 正常代理/转发目标连接 |
| `handleConnection` | client.go | 入口 — Peek 首字节分发 SOCKS5/HTTP |
| `handleSOCKS5` | client.go | SOCKS5 握手 → 读取目标 → 隧道转发 |
| `handleHTTPProxy` | client.go | HTTP 解析 → CONNECT/普通代理处理 → 隧道转发 |
| `bufferedConn` | client.go | bufio.Reader + net.Conn 包装器（支持 Peek 后续读） |
| `hostToAddrBytes` | client.go | host 字符串 → (atyp, addr bytes) |
| `relay` | client.go | 双向中继（client/forward 共用） |
| `parseTargetAddr` | forward.go | 解析 host:port → (atyp, addr, port) |
| `parseConfig` | daemon.go | 统一配置解析 + daemon 初始化 + 日志初始化 |
| `daemonize` | daemon.go | re-exec 后台（去掉 -d，重定向到 proxy_ob.log） |
| `daemonSysProcAttr` | daemon_unix.go / daemon_windows.go | 平台特定进程属性 |
| `initLogging` | log.go | 设置 verbose 级别 |
| `infof` | log.go | 始终可见的日志 |
| `verbosef` | log.go | 仅 -v 时输出的详细日志 |

## CONVENTIONS

- **cmd/ 不是 package main** — 是 `package cmd`，导出 `RunClient()`/`RunServer()`/`RunForward()` 供 main.go 调用
- **模块名** `proxy_ob`（无 vanity URL）
- **错误处理** — 统一 `fmt.Errorf("context: %w", err)`，无自定义错误类型
- **每连接独立隧道** — 每个连接（SOCKS5、HTTP 或 forward）创建一条新的 TCP 隧道到 server
- **relay 共用** — `relay()` 在 client.go 中定义，forward.go 直接复用（同 package cmd）
- **协议自动检测** — `handleConnection` 通过 `bufio.Reader.Peek(1)` 读取首字节，`0x05` 为 SOCKS5，其余为 HTTP 代理
- **bufferedConn** — 包装 `bufio.Reader` + `net.Conn`，支持 Peek 后继续 Read，使现有 SOCKS5 代码无需修改
- **中继帧格式** — relay 帧用 `Atyp: 0x01, Addr: make([]byte, 4)` 哑值，Data 承载实际载荷
- **配置优先级** — CLI flags > JSON config > 默认值
- **forward 模式无默认 listen** — 需用户显式指定 `-l`
- **日志两级** — `infof()` 启动/关闭/错误，`verbosef()` 每连接详情（源→目标）
- **daemon 跨平台** — `daemon.go` 共享 re-exec 逻辑，`daemon_unix.go` / `daemon_windows.go` 通过 build tag 提供平台特定 `SysProcAttr`
- **parseConfig 入口** — 所有 RunXxx 通过 `parseConfig()` 统一处理 daemon + verbose 初始化
- **HTTP 代理改写** — 普通 HTTP 请求的绝对 URI 自动改写为相对路径，作为 Frame.Data 通过隧道首帧发送，server 端透传到目标
- **server 端协议无关** — server 不区分 client 发来的是 SOCKS5 还是 HTTP 代理请求，仅看第一帧的目标地址
- **反向隧道协议** — Atyp=0x00（注册）、Atyp=0x02（固定目标连接请求 server→client）、Atyp=0x01/0x03/0x04（通用代理连接请求，携带目标地址）、Atyp=0x05（反向数据 client→server）
- **反向隧道流程** — client 建立控制连接注册 → server 开监听端口 → 用户连入时 server 通过控制连接发 session ID → client 发起新数据连接携带 session ID → server 匹配后双向中继
- **反通用代理** — `-r 端口`（无目标）→ server 开 SOCKS5/HTTP 代理监听，目标由用户动态指定 → 连接请求帧用正常 Atyp（0x01/0x03/0x04）携带目标地址，session ID 放 Data
- **绑定地址约定** — `-r 1080` 默认 `127.0.0.1`（仅本机）；`-r :1080` 前缀 `:` 表示 `0.0.0.0`（全接口）；client 模式默认 `127.0.0.1:1080`
- **注册帧 Data 格式** — `bindAddr\ntargetAddr`，targetAddr 为空表示代理模式

## ANTI-PATTERNS

- **禁止** 添加第三方依赖（`go.mod` 仅保留 `golang.org/x/crypto`）
- **禁止** 实现 UDP/BIND/多用户/连接池
- **禁止** `internal/` 包内使用 `log` 或 `fmt.Print` — 错误只返回，不打印
- **禁止** 修改帧格式而不同步更新 client、forward 和 server 的 relay 逻辑

## COMMANDS

```bash
make                                              # 编译当前平台
make dist                                         # 构建全部 4 平台到 dist/
make vet                                          # 静态检查
make clean                                        # 清理
./proxy_ob server -l :8388 -k "key"              # 启动服务端
./proxy_ob server -d -k "key"                    # 后台 Daemon 模式
./proxy_ob server -d -v -k "key"                 # 后台 + 详细日志
./proxy_ob client -s ip:8388 -k "key"            # 启动客户端（SOCKS5 + HTTP 代理）
./proxy_ob client -v -s ip:8388 -k "key"         # 详细日志模式
./proxy_ob forward -l :3306 -t 10.0.0.5:3306 -s ip:8388 -k "key"  # 端口转发
./proxy_ob reverse -r 3306:10.0.0.5:3306 -s ip:8388 -k "key"       # 反向端口转发
curl --socks5 127.0.0.1:1080 http://httpbin.org/ip  # 测试 SOCKS5
curl -x http://127.0.0.1:1080 https://httpbin.org/ip  # 测试 HTTP/HTTPS 代理
mysql -h 127.0.0.1 -P 3306                       # 测试端口转发
git tag v0.x.x && git push origin v0.x.x         # 触发 CI Release
```

## NOTES

- **版本号硬编码** 在 `main.go:10` — CI 的 `-ldflags="-s -w"` 未注入版本。如需自动版本，改用 `-ldflags="-X main.version=$TAG"`
- **日志统一** — 全部通过 `infof()`/`verbosef()` 输出，不再混用 `fmt.Fprintf(os.Stderr)`
- **无测试** — 零 `_test.go` 文件
- **握手 33 字节** — `[0x01 版本] [32B HMAC-SHA256(key,key) 令牌]`，服务端用 `subtle.ConstantTimeCompare` 防时序攻击
- **Wire 帧上限** ~65KB（uint16 长度前缀），足够代理场景
- **forward 复用 server 逻辑** — 服务端不区分 SOCKS5、HTTP 代理和 forward，仅看第一帧的目标地址
- **parseTargetAddr** — 支持 IPv4/IPv6/域名，自动判断 atyp
- **Daemon re-exec** — 父进程去掉 `-d` 启动子进程，输出重定向到 `proxy_ob.log`，子进程正常退出父进程
- **Build tags** — `daemon_unix.go` 使用 `//go:build !windows`，`daemon_windows.go` 使用 `//go:build windows`，CI 交叉编译自动正确处理
- **HTTP 代理 keep-alive 限制** — CONNECT 隧道天然支持持久连接；普通 HTTP 代理每连接处理一次请求（非 keep-alive）
- **协议自动检测原理** — SOCKS5 首字节固定 `0x05`（版本号），HTTP 方法首字节为 ASCII 字母（C/G/P 等），通过 `bufio.Reader.Peek(1)` 无消费读取区分
