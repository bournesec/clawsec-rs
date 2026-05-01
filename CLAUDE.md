# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目概述

ClawSec Monitor v3.0 — AI 代理流量检测桌面工具。监控 HTTP/HTTPS 出站流量和 SSH 连接，检测 AI API 密钥泄露、命令注入等威胁。

- **后端**：Rust workspace（`clawsec-core` 库 + CLI 二进制 + Tauri 二进制）
- **前端**：Svelte 5 (runes) + TypeScript + Vite 6 + Tailwind CSS v4
- **桌面壳**：Tauri v2
- **包管理**：pnpm（前端）

## 常用命令

```bash
# 启动 Tauri 开发模式
cargo tauri dev

# 构建前端
cd frontend && pnpm build

# 构建 Rust workspace
cargo build

# 清理端口后重启（端口冲突时）
lsof -ti:1420 | xargs kill -9; cargo tauri dev
```

### 测试

```bash
# 运行全部测试（74 个，65 core + 7 CLI + 2 Tauri lib）
cargo test --workspace

# 运行单个测试
cargo test -p clawsec-core test_name

# 覆盖率报告（需先安装 cargo-llvm-cov）
cargo llvm-cov --workspace --summary-only

# 覆盖率 HTML 报告
cargo llvm-cov --workspace --html
```

当前覆盖率 ~64%（目标 80%）。测试集中在 `clawsec-core`（ca、config、pid、proxy/http、scanner、ssh_watcher、threat）。`src-tauri/src/lib.rs` 的 Tauri command 因依赖 `tauri::State` 运行时未在单元测试中覆盖。

## 架构分层

```
Cargo workspace (根 Cargo.toml)
├── clawsec-core/    → 纯 Rust 库：Monitor、代理、扫描器、CA、威胁日志（无 UI 依赖）
│   └── src/         → lib.rs + 7 个子模块，每个含 #[cfg(test)] 单元测试
├── src/             → CLI 二进制 "clawsec"（clap derive）
├── src-tauri/       → Tauri 桌面壳二进制 "clawsec-tauri"
│   └── src/lib.rs   → 8 个 #[tauri::command] IPC 桥接
└── frontend/        → Svelte 5 前端（独立 pnpm 项目，Vite 构建）
```

关键原则：**核心逻辑在 clawsec-core 中，CLI 和 Tauri GUI 都是它的消费者。** 不要在 Tauri command 里写业务逻辑。

测试分布在源码文件中（`#[cfg(test)] mod tests`），遵循 Rust 惯例。没有独立的 `tests/` 集成测试目录。

## 前端页面路由

`App.svelte` 用 `$state` 做内联条件渲染，无 router 库。页面标识：`dashboard` / `live` / `threats` / `config`。

每个页面组件通过 `invoke("command_name", { args })` 调用 Tauri command，都实现了 loading / error / empty 三种状态处理。

**分页模式**：Threats 和 LiveMonitor 都使用 Svelte 5 `$derived` rune 做客户端分页：
```ts
const PAGE_SIZE = 10;
let currentPage = $state(1);
let totalPages = $derived(Math.max(1, Math.ceil(threats.length / PAGE_SIZE)));
let pagedThreats = $derived(threats.slice((currentPage - 1) * PAGE_SIZE, currentPage * PAGE_SIZE));
```
分页控件：首页 / 上一页 / 第 X/Y 页 / 下一页 / 末页，边界自动禁用。

**UI 语言：全部使用汉语，专业术语（HTTP、SSH、MITM、PID 等）除外。** 侧边栏导航：仪表盘 / 实时监控 / 威胁列表 / 设置。

## Tauri Commands（src-tauri/src/lib.rs）

| 命令 | 说明 |
|------|------|
| `get_status` | 运行状态、PID、威胁总数 |
| `start_monitor` | 启动 Monitor（初始化 CA + 代理 + SSH 监控） |
| `stop_monitor` | 停止 Monitor |
| `get_threats` | 获取威胁列表（limit 参数，前端翻页用 `limit: 500` 全量拉取后客户端分页，每页 10 条） |
| `get_recent_threats` | 增量威胁（since_count）用于实时更新 |
| `get_config` | 读取配置 |
| `save_config` | 保存配置 |
| `get_config_path` | 配置文件路径 |

数据文件路径（硬编码在 `/tmp/clawsec/`）：
- `config.json` — 配置文件
- `threats.jsonl` — 威胁日志（JSONL 格式，每行一条）
- `monitor.pid` — PID 文件（单实例锁）
- `ca.key` / `ca.crt` — MITM CA 证书

## 主题系统

`frontend/src/lib/theme.svelte.ts` 中的 `ThemeManager` 类（Svelte 5 `$state` rune）：
- 三种模式：`system` / `light` / `dark`，`cycle()` 循环切换
- `localStorage` key: `clawsec-theme` 持久化用户偏好
- 操作 `<html data-theme="dark|light">` 属性控制主题
- `system` 模式监听 `prefers-color-scheme`
- 导出单例 `export const theme`

所有颜色使用 CSS 自定义属性（OKLCH 色彩空间），定义在 `app.css` 中，分 `[data-theme="dark"]`（默认）和 `[data-theme="light"]` 两组。

## 威胁数据模型

前端从 `get_threats` 获取的 JSON 对象对应 `clawsec-core/src/threat/mod.rs` 的 `Threat` 结构体：

| 字段 | 说明 |
|------|------|
| `direction` | `"outbound"` / `"inbound"` |
| `protocol` | `"http"` / `"ssh"` |
| `threat_type` | `"EXFIL"` / `"INJECTION"` / `"SSH_CONNECT"` |
| `pattern` | 检测标签（`ai_api_key`, `pipe_to_shell`, `ssh_key_file` 等），见 `scanner/patterns.rs` |
| `snippet` | 匹配文本片段（前后各 50 字符上下文，最长 200 字符） |
| `raw_payload` | 完整扫描文本（请求行+请求头+请求体，最长 `max_scan_bytes`，默认 65536），详情弹窗展示此字段 |
| `source` | 来源地址 |
| `dest` | 目标地址 |
| `timestamp` | RFC 3339 时间戳 |

**注意：`Threat` 没有 `severity` 字段。** 等级由前端根据 `pattern` + `threat_type` 推导：

| 等级 | 中文 | 匹配条件 |
|------|------|----------|
| critical | 严重 | `ai_api_key`, `private_key_pem`, `aws_access_key`, `reverse_shell`, `destructive_rm`, `shell_exec`, `ssh_key_inject` |
| high | 高危 | `ssh_connect`, `pipe_to_shell`, `unix_sensitive` |
| medium | 中危 | `ssh_key_file`, `dotenv_file`, `ssh_pubkey` |
| low | 低危 | 其他 |

## Payload 高亮

`frontend/src/lib/highlight.ts` 提供攻击载荷高亮工具函数：

- `escapeHtml(s)` — HTML 转义，防止 XSS
- `highlightPayload(snippet, pattern)` — 根据 pattern 选择正则表达式，仅对匹配到的攻击片段包裹 `<mark>` 标签（红底高亮），其余文本保持原样
- `PAYLOAD_RE` 字典 — 12 个 JS 正则，**需与后端 `clawsec-core/src/scanner/patterns.rs` 保持同步**

在 Svelte 中使用 `{@html highlightPayload(text, pattern)}` 渲染。两个组件（Threats、LiveMonitor）的列表预览和详情弹窗均使用此函数。

## 详情弹窗

Threats 和 LiveMonitor 每条记录有「详情」按钮，点击弹出模态窗口：

- 状态：`let selectedThreat = $state<Record<string, unknown> | null>(null);`
- 弹窗结构：固定定位 overlay（点击关闭） + 居中卡片（`width: min(720px, 90vw)`，`max-height: 85vh` 滚动）
- 展示全部字段（时间、类型、等级、协议、方向、来源、目标、威胁类型）+ 完整 `raw_payload`（红底高亮攻击片段）
- `fullPayload()` 函数优先读 `raw_payload`，回退到 `snippet`（兼容旧威胁数据）

## 前端布局约束（重要）

项目已全面使用流体响应式布局，Tauri WebKit webview 的渲染行为与标准浏览器有差异，修改时需遵守以下规则：

1. **每个页面组件的根 `<div>` 必须设置 `min-width: 0; overflow-x: hidden;`** — 否则 `white-space: nowrap` 的子元素会撑开容器导致横向滚动条
2. 每层 flex 子元素需要 `min-width: 0` 才能正确收缩
3. **表格必须使用 `table-layout: fixed`** — `auto` 会导致列宽按内容计算，长文本撑破容器
4. **flex 容器内的子卡片必须显式设置 `width: 100%`** — WebKit 中 `align-items: stretch`（默认值）在某些嵌套 flex 场景下不可靠
5. **App.svelte 外层 `<div class="flex h-screen">` 需要 `width: -webkit-fill-available;`** — 否则 WebKit 可能无法正确计算可用宽度
6. 卡片网格使用 `display: flex; flex-wrap: wrap;` + `flex: 1 1 Npx` 做自适应横排（CSS grid 在 Tauri WebKit 中不可靠，已弃用）
7. 内边距使用 `clamp(12px, 2vw, 24px)` 做连续缩放
8. 侧边栏用 `@media (max-width: 899px)` 收缩为图标模式（56px），带 `transition: width` 动画
9. **不要使用 `flex-basis: auto`**，改用 `flex: 1 1 0%` — `auto` 以内容宽度为基准会撑开容器

## CLI 命令

CLI 二进制 `clawsec`（clap derive，定义在 `src/main.rs`）：

| 子命令 | 说明 |
|--------|------|
| `clawsec start [--config cf.json] [--no-mitm]` | 前台启动 Monitor |
| `clawsec stop` | 发送 SIGTERM 停止 Monitor |
| `clawsec status` | 查看运行状态和最近威胁 |
| `clawsec threats [--limit 10]` | 导出威胁 JSON |

CLI 和 Tauri GUI 都通过 `clawsec-core` 的 `Monitor` 结构体操作。CLI 的 `cmd_start` 是 Monitor 生命周期的完整参考实现（init → start → Ctrl-C → stop）。

## 测试约束

- **PID 文件**：`Monitor::init()` 写入全局 `/tmp/clawsec/monitor.pid`，同一进程内只能调用一次。单元测试中避免直接调用 `init()`，改为通过 `Monitor::new()` 和独立函数测试。
- **Tracing 订阅器**：`setup_logging()` 设置全局 subscriber，只能调用一次。不要在单元测试中调用。
- **测试隔离**：使用 `tempfile::TempDir` 创建隔离目录（参考 `pid.rs` 和 `config.rs` 的测试模式）。
- **异步测试**：使用 `#[tokio::test]` 标注需要运行时的测试函数。

## Tauri 窗口配置

- 默认：1200×800，最小：800×600，可调整大小
- 开发模式 Vite 端口：1420
- `beforeDevCommand` 自动启动 `pnpm dev`
- 前端编译产物路径：`frontend/dist/`

## 已知安全风险

上一轮安全审查发现 3 CRITICAL + 5 HIGH 问题，均未修复：

| ID | 级别 | 文件 | 问题 |
|----|------|------|------|
| C-1 | CRITICAL | `pid.rs` / `config.rs` | 数据目录硬编码 `/tmp/clawsec/`，应迁移至 `~/Library/Application Support/com.clawsec.monitor/` |
| C-2 | CRITICAL | `ca.rs` | `/tmp` 下 CA 私钥存在 symlink 攻击风险 |
| C-3 | CRITICAL | `tauri.conf.json` | CSP 未配置（`"csp": null`），XSS 防护缺失 |

修改涉及这些文件的代码时注意相关风险。
