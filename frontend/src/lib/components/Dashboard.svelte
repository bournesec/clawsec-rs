<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { onMount } from "svelte";

  interface Status {
    running: boolean;
    pid: number | null;
    total_threats: number;
  }

  let status = $state<Status | null>(null);
  let loading = $state(true);
  let error = $state("");
  let polling = $state(true);

  async function refresh() {
    try {
      status = await invoke("get_status");
      error = "";
    } catch (e) {
      error = String(e);
    }
    loading = false;
    if (polling) setTimeout(refresh, 3000);
  }

  async function handleStart() {
    try {
      await invoke("start_monitor");
      await refresh();
    } catch (e) {
      error = String(e);
    }
  }

  async function handleStop() {
    try {
      await invoke("stop_monitor");
      await refresh();
    } catch (e) {
      error = String(e);
    }
  }

  onMount(() => {
    refresh();
    return () => {
      polling = false;
    };
  });
</script>

<div style="width: 100%;">
  <!-- Page header -->
  <div style="margin-bottom: 24px;">
    <h2 style="font-size: 18px; font-weight: 600; color: var(--color-text); margin: 0;">仪表盘</h2>
    <p style="font-size: 13px; color: var(--color-text-tertiary); margin: 4px 0 0;">监控概览与系统状态</p>
  </div>

  <!-- Error -->
  {#if error}
    <div class="card" style="margin-bottom: 16px; padding: 12px 16px; background: var(--color-danger-soft); border-color: var(--color-danger);">
      <p style="color: var(--color-danger); font-size: 13px; font-family: var(--font-mono); margin: 0;">{error}</p>
    </div>
  {/if}

  <!-- Loading -->
  {#if loading}
    <div class="card" style="padding: 32px;">
      <p style="color: var(--color-text-tertiary); font-size: 13px; margin: 0;">正在加载状态...</p>
    </div>

  {:else if status}
    <!-- Metric cards -->
    <div style="display: flex; flex-wrap: wrap; gap: 16px; margin-bottom: 24px; width: 100%;">
      <!-- Status -->
      <div class="card" style="flex: 1 1 220px; min-width: 200px; padding: 20px;">
        <p style="font-size: 11px; color: var(--color-text-muted); text-transform: uppercase; letter-spacing: 0.05em; margin: 0 0 12px; font-weight: 500;">状态</p>
        <div style="display: flex; align-items: center; gap: 10px;">
          <span class="status-dot" class:running={status.running} class:stopped={!status.running}></span>
          <span style="font-size: 15px; font-weight: 500; color: {status.running ? 'var(--color-success)' : 'var(--color-text-tertiary)'};">
            {status.running ? '运行中' : '已停止'}
          </span>
        </div>
      </div>

      <!-- PID -->
      <div class="card" style="flex: 1 1 220px; min-width: 200px; padding: 20px;">
        <p style="font-size: 11px; color: var(--color-text-muted); text-transform: uppercase; letter-spacing: 0.05em; margin: 0 0 12px; font-weight: 500;">进程 ID</p>
        <p style="font-size: 15px; font-family: var(--font-mono); color: var(--color-text); margin: 0;">{status.pid ?? '\u2014'}</p>
      </div>

      <!-- Total Threats -->
      <div class="card" style="flex: 1 1 220px; min-width: 200px; padding: 20px;">
        <p style="font-size: 11px; color: var(--color-text-muted); text-transform: uppercase; letter-spacing: 0.05em; margin: 0 0 12px; font-weight: 500;">威胁总数</p>
        <p style="font-size: 24px; font-weight: 600; color: var(--color-text); margin: 0; font-variant-numeric: tabular-nums;">{status.total_threats}</p>
      </div>
    </div>

    <!-- Controls -->
    <div class="card" style="padding: 20px;">
      <p style="font-size: 11px; color: var(--color-text-muted); text-transform: uppercase; letter-spacing: 0.05em; margin: 0 0 16px; font-weight: 500;">操控</p>
      <div style="display: flex; gap: 10px;">
        <button
          class="btn-primary"
          disabled={status.running}
          onclick={handleStart}
        >
          启动监控
        </button>
        <button
          class="btn-danger"
          disabled={!status.running}
          onclick={handleStop}
        >
          停止监控
        </button>
      </div>
    </div>

    <p style="margin-top: 16px; font-size: 11px; color: var(--color-text-muted);">每 3 秒自动刷新</p>
  {/if}
</div>
