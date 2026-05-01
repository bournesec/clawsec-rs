# ClawSec Monitor v3.0

AI 代理流量检测桌面工具 — 监控 HTTP/HTTPS 出站流量和 SSH 连接，检测 AI API 密钥泄露、命令注入等安全威胁。

## 功能特性

- **HTTP/HTTPS 代理** — 拦截出站流量，支持 MITM 解密 HTTPS 内容
- **SSH 连接监控** — 轮询检测活跃 SSH 会话
- **威胁扫描引擎** — 基于正则模式匹配，检测以下威胁：
  - 数据外泄：AI API 密钥、AWS 密钥、PEM 私钥、SSH 密钥、敏感文件路径、.env 文件
  - 命令注入：管道执行、shell 调用、反弹 shell、危险删除、SSH 密钥注入
- **桌面 GUI** — Tauri v2 原生窗口，Svelte 5 前端，深色/浅色主题切换
- **CLI 工具** — 独立命令行，支持 start / stop / status / threats 子命令
- **实时监控** — 威胁事件实时推送，自动去重

## 技术栈

| 层 | 技术 |
|----|------|
| 核心库 | Rust（`clawsec-core`）— tokio 异步运行时、rustls TLS、rcgen CA 证书生成 |
| CLI | Rust — clap 命令行解析 |
| 桌面壳 | Tauri v2 |
| 前端 | Svelte 5 (runes) + TypeScript + Vite 6 + Tailwind CSS v4 |
| 包管理 | pnpm（前端）、Cargo（Rust） |

## 项目结构

```
clawsec-rs/
├── clawsec-core/           # 核心 Rust 库（无 UI 依赖）
│   └── src/
│       ├── lib.rs           # Monitor 主结构体、状态管理
│       ├── config.rs        # 配置加载与默认值
│       ├── ca.rs            # MITM CA 证书生成
│       ├── pid.rs           # PID 文件单实例锁
│       ├── ssh_watcher.rs   # SSH 连接轮询监控
│       ├── proxy/           # HTTP/HTTPS 代理实现
│       ├── scanner/         # 威胁模式扫描引擎
│       └── threat/          # 威胁事件模型与 JSONL 日志
├── src/                     # CLI 入口
│   └── main.rs              # clap 子命令：start / stop / status / threats
├── src-tauri/               # Tauri 桌面壳
│   └── src/lib.rs           # 8 个 IPC command 桥接前端与 core
├── frontend/                # Svelte 5 前端
│   └── src/
│       ├── App.svelte       # 主布局 + 页面路由
│       └── lib/components/  # 仪表盘 / 实时监控 / 威胁列表 / 设置
└── Cargo.toml               # Workspace 根配置
```

## 环境要求

- **Rust** — 1.75+（edition 2021）
- **Node.js** — 18+
- **pnpm** — 8+
- **Tauri CLI** — `cargo install tauri-cli`（或通过 pnpm：`pnpm tauri`）
- **系统依赖** — macOS 自带 WebKit；Linux 需安装 `libwebkit2gtk-4.1-dev` 等 Tauri 依赖

## 快速开始

```bash
# 克隆仓库
git clone <repo-url> && cd clawsec-rs

# 安装前端依赖
cd frontend && pnpm install && cd ..

# 启动开发模式（自动构建 Rust + 启动前端 dev server）
cargo tauri dev
```

应用启动后默认窗口 1200×800，最小 800×600。

## 命令参考

<!-- AUTO-GENERATED -->

### 开发命令

| 命令 | 说明 |
|------|------|
| `cargo tauri dev` | 启动 Tauri 开发模式（热重载前端 + Rust 后端） |
| `cd frontend && pnpm dev` | 仅启动前端 Vite dev server（端口 1420） |
| `cd frontend && pnpm build` | 构建前端生产包 |
| `cargo build` | 仅构建 Rust workspace |
| `cargo build --release` | 构建 Rust release 版本 |
| `cargo tauri build` | 打包桌面应用安装包 |

### CLI 命令

```bash
# 前台启动监控
clawsec start [--config path/to/config.json] [--no-mitm]

# 停止监控
clawsec stop

# 查看状态与最近威胁
clawsec status

# 导出威胁 JSON
clawsec threats [--limit 10]
```

### 故障排除

```bash
# 端口 1420 被占用时
lsof -ti:1420 | xargs kill -9; cargo tauri dev
```

<!-- /AUTO-GENERATED -->

## 配置说明

配置文件路径：`/tmp/clawsec/config.json`（JSON 格式，所有字段可选，缺省使用默认值）。

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `http_proxy_port` | `8888` | HTTP 代理监听端口 |
| `gateway_local_port` | `18790` | 网关代理本地端口 |
| `gateway_target_port` | `18789` | 网关代理目标端口 |
| `log_dir` | `/tmp/clawsec` | 日志和数据文件目录 |
| `log_level` | `INFO` | 日志级别（ERROR / WARN / INFO / DEBUG / TRACE） |
| `max_scan_bytes` | `65536` | 每次请求最大扫描字节数 |
| `ssh_poll_interval` | `10` | SSH 连接轮询间隔（秒） |
| `dedup_window_secs` | `60` | 威胁去重时间窗口（秒） |
| `enable_http_proxy` | `true` | 启用 HTTP 代理 |
| `enable_gateway_proxy` | `true` | 启用网关代理 |
| `enable_ssh_watcher` | `true` | 启用 SSH 监控 |
| `enable_mitm` | `true` | 启用 MITM HTTPS 解密 |

## 数据文件

所有运行时数据存储在 `/tmp/clawsec/`：

| 文件 | 格式 | 说明 |
|------|------|------|
| `config.json` | JSON | 运行配置 |
| `threats.jsonl` | JSONL | 威胁日志（每行一条 JSON） |
| `monitor.pid` | 文本 | PID 文件（单实例锁） |
| `ca.key` | PEM | MITM CA 私钥 |
| `ca.crt` | PEM | MITM CA 证书 |

## 架构设计

```
┌─────────────┐     ┌─────────────┐
│   CLI 入口   │     │  Tauri GUI   │
│  (clap)     │     │  (Svelte 5)  │
└──────┬──────┘     └──────┬──────┘
       │    invoke()       │
       └────────┬──────────┘
                │
       ┌────────▼────────┐
       │  clawsec-core   │
       │                 │
       │  ┌───────────┐  │
       │  │  Monitor   │  │
       │  └─────┬─────┘  │
       │        │         │
       │  ┌─────┼─────┐  │
       │  │     │     │  │
       │  ▼     ▼     ▼  │
       │ Proxy  SSH  CA   │
       │  │   Watcher │   │
       │  ▼           │   │
       │ Scanner ─────┘   │
       │  │               │
       │  ▼               │
       │ ThreatLog        │
       │ (JSONL)          │
       └─────────────────┘
```

核心原则：**所有业务逻辑在 `clawsec-core` 中，CLI 和 Tauri GUI 都是它的消费者。**

## 前端页面

| 页面 | 路由标识 | 功能 |
|------|----------|------|
| 仪表盘 | `dashboard` | 运行状态、进程 ID、威胁总数、启停控制 |
| 实时监控 | `live` | 实时威胁事件流，可暂停/清除 |
| 威胁列表 | `threats` | 全量威胁表格，按时间/类型/来源/级别排列 |
| 设置 | `config` | 代理端口、监控参数、日志级别、功能组件开关 |

UI 语言为汉语（专业术语除外），支持深色/浅色/跟随系统三种主题模式。
