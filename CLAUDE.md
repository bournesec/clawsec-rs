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

**UI 语言：全部使用汉语，专业术语（HTTP、SSH、MITM、PID 等）除外。** 侧边栏导航：仪表盘 / 实时监控 / 威胁列表 / 设置。

## Tauri Commands（src-tauri/src/lib.rs）

| 命令 | 说明 |
|------|------|
| `get_status` | 运行状态、PID、威胁总数 |
| `start_monitor` | 启动 Monitor（初始化 CA + 代理 + SSH 监控） |
| `stop_monitor` | 停止 Monitor |
| `get_threats` | 获取威胁列表（limit 参数，默认 50） |
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

## 前端布局约束（重要）

项目已全面使用流体响应式布局，修改时需遵守以下规则：

1. **每个页面组件的根 `<div>` 必须设置 `min-width: 0; overflow-x: hidden;`** — 否则 `white-space: nowrap` 的子元素会撑开容器导致横向滚动条
2. 每层 flex 子元素需要 `min-width: 0` 才能正确收缩
3. 卡片网格使用 `display: flex; flex-wrap: wrap;` + `flex: 1 1 Npx` 做自适应横排（CSS grid `auto-fit`/`auto-fill` 在 Tauri WebKit webview 中不可靠，已弃用）
4. 内边距使用 `clamp(12px, 2vw, 24px)` 做连续缩放
5. 侧边栏用 `@media (max-width: 899px)` 收缩为图标模式（56px），带 `transition: width` 动画
6. **不要使用 `flex-basis: auto`**，改用 `flex: 1 1 0%` — `auto` 以内容宽度为基准会撑开容器

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
