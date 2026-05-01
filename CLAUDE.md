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
# 启动 Tauri 开发模式（唯一需要记住的命令）
cargo tauri dev

# 单独构建前端
cd frontend && pnpm build

# 单独构建 Rust
cargo build

# 清理端口后重启（端口冲突时）
lsof -ti:1420 | xargs kill -9; cargo tauri dev
```

没有 lint 或 test 脚本配置（项目暂无测试套件）。

## 架构分层

```
clawsec-core/    → 纯 Rust 库：Monitor、代理、扫描器、CA、威胁日志（无 UI 依赖）
src-tauri/       → Tauri 壳：8 个 command 桥接前端 ↔ core，AppState = Arc<Mutex<Option<Monitor>>>
src/main.rs      → CLI 入口（clap derive）：start / stop / status / threats 四个子命令
frontend/        → Svelte 5 前端：4 个页面 + 侧边栏 + 主题系统
```

关键原则：**核心逻辑在 clawsec-core 中，CLI 和 Tauri GUI 都是它的消费者。** 不要在 Tauri command 里写业务逻辑。

## 前端页面路由

`App.svelte` 用 `$state` 做内联条件渲染，无 router 库。页面标识：`dashboard` / `live` / `threats` / `config`。

每个页面组件通过 `invoke("command_name", { args })` 调用 Tauri command，都实现了 loading / error / empty 三种状态处理。

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
3. 卡片使用 `repeat(auto-fill, minmax(Npx, 1fr))` 做自适应网格
4. 内边距使用 `clamp(12px, 2vw, 24px)` 做连续缩放
5. 侧边栏用 `@media (max-width: 899px)` 收缩为图标模式（56px），带 `transition: width` 动画

## Tauri 窗口配置

- 默认：1200×800，最小：800×600，可调整大小
- 开发模式 Vite 端口：1420
- `beforeDevCommand` 自动启动 `pnpm dev`
- 前端编译产物路径：`frontend/dist/`
