<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { onMount } from "svelte";
  import ThemeToggle from "./ThemeToggle.svelte";

  let {
    current,
    onNavigate,
  }: {
    current: string;
    onNavigate: (page: string) => void;
  } = $props();

  let isRunning = $state(false);
  let polling = $state(true);

  async function checkStatus() {
    try {
      const status = (await invoke("get_status")) as { running: boolean };
      isRunning = status.running;
    } catch {
      isRunning = false;
    }
    if (polling) {
      setTimeout(checkStatus, 3000);
    }
  }

  onMount(() => {
    checkStatus();
    return () => {
      polling = false;
    };
  });
</script>

<aside class="sidebar flex flex-col flex-shrink-0" style="width: 220px; background: var(--color-sidebar-bg); border-right: 1px solid var(--color-sidebar-border);">
  <!-- Brand -->
  <div class="brand-area" style="padding: 20px 16px 16px; border-bottom: 1px solid var(--color-sidebar-border);">
    <div style="display: flex; align-items: center; gap: 10px;">
      <div style="width: 28px; height: 28px; border-radius: 8px; background: var(--color-accent); display: flex; align-items: center; justify-content: center; color: white; font-size: 13px; font-weight: 700; font-family: var(--font-mono); flex-shrink: 0;">C</div>
      <div class="brand-text">
        <h1 style="font-size: 13px; font-weight: 700; letter-spacing: 0.1em; color: var(--color-text); margin: 0; font-family: var(--font-mono);">CLAWSEC</h1>
        <p style="font-size: 10px; color: var(--color-text-muted); margin: 1px 0 0; font-family: var(--font-mono);">Monitor v3.0</p>
      </div>
    </div>
  </div>

  <!-- Navigation -->
  <nav style="flex: 1; padding: 8px; display: flex; flex-direction: column; gap: 2px;">
    <button
      class="nav-item {current === 'dashboard' ? 'active' : ''}"
      onclick={() => onNavigate("dashboard")}
    >
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink: 0;"><rect x="3" y="3" width="7" height="9" /><rect x="14" y="3" width="7" height="5" /><rect x="14" y="12" width="7" height="9" /><rect x="3" y="16" width="7" height="5" /></svg>
      <span>仪表盘</span>
    </button>
    <button
      class="nav-item {current === 'live' ? 'active' : ''}"
      onclick={() => onNavigate("live")}
    >
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink: 0;"><polygon points="5 3 19 12 5 21 5 3" /></svg>
      <span>实时监控</span>
    </button>
    <button
      class="nav-item {current === 'threats' ? 'active' : ''}"
      onclick={() => onNavigate("threats")}
    >
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink: 0;"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" /><line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" /></svg>
      <span>威胁列表</span>
    </button>

    <div style="flex: 1;"></div>

    <!-- Settings Separator -->
    <div style="height: 1px; background: var(--color-sidebar-border); margin: 4px 0;"></div>

    <button
      class="nav-item {current === 'config' ? 'active' : ''}"
      onclick={() => onNavigate("config")}
    >
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink: 0;"><circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z" /></svg>
      <span>设置</span>
    </button>
  </nav>

  <!-- Footer -->
  <div style="padding: 12px 16px; border-top: 1px solid var(--color-sidebar-border); display: flex; align-items: center; justify-content: space-between;">
    <div class="flex items-center gap-2">
      <span class="status-dot {isRunning ? 'running' : 'stopped'}"></span>
      <span class="footer-status-text text-tertiary" style="font-size: 11px;">{isRunning ? '运行中' : '已停止'}</span>
    </div>
    <ThemeToggle />
  </div>
</aside>

<style>
  .nav-item {
    display: flex;
    align-items: center;
    gap: 10px;
    width: 100%;
    padding: 8px 12px;
    border: none;
    border-radius: var(--radius-md);
    background: transparent;
    color: var(--color-text-tertiary);
    font-size: 13px;
    font-family: var(--font-sans);
    cursor: pointer;
    transition: all var(--duration-fast) var(--ease-out);
    text-align: left;
  }
  .nav-item:hover {
    background: var(--color-bg-hover);
    color: var(--color-text-secondary);
  }
  .nav-item.active {
    background: var(--color-accent-muted);
    color: var(--color-accent);
  }
  .nav-item svg {
    opacity: 0.7;
  }
  .nav-item.active svg {
    opacity: 1;
  }

  .sidebar {
    transition: width var(--duration-normal) var(--ease-out);
  }

  /* ── Responsive: collapse to icon-only at narrow widths ── */
  @media (max-width: 899px) {
    .sidebar {
      width: 56px !important;
    }
    .brand-area {
      padding: 12px 8px !important;
      justify-content: center;
    }
    .brand-text {
      display: none;
    }
    .footer-status-text {
      display: none;
    }
    .nav-item {
      justify-content: center;
      padding: 8px;
    }
    .nav-item span {
      display: none;
    }
  }
</style>
