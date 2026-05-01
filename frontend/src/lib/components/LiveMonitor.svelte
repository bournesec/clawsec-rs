<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { onMount } from "svelte";

  let threats = $state<Record<string, unknown>[]>([]);
  let visibleThreats = $state<Record<string, unknown>[]>([]);
  let loading = $state(true);
  let error = $state("");
  let polling = $state(true);
  let paused = $state(false);
  let newCount = $state(0);
  let latestTimestamp = $state(0);

  const MAX_VISIBLE = 200;

  async function refresh() {
    try {
      const fresh = (await invoke("get_threats", { limit: 50 })) as Record<string, unknown>[];
      error = "";

      if (threats.length > 0 && fresh.length > threats.length) {
        const newThreats = fresh.slice(0, fresh.length - threats.length);
        newCount += newThreats.length;
        for (const t of newThreats) {
          const ts = new Date(String(t.timestamp ?? 0)).getTime();
          if (ts > latestTimestamp) latestTimestamp = ts;
        }
      }

      threats = fresh;

      if (!paused) {
        visibleThreats = [...threats].reverse().slice(0, MAX_VISIBLE);
        newCount = 0;
      }
    } catch (e) {
      error = String(e);
    }
    loading = false;
    if (polling) setTimeout(refresh, paused ? 3000 : 2000);
  }

  function togglePause() {
    paused = !paused;
    if (!paused) {
      visibleThreats = [...threats].reverse().slice(0, MAX_VISIBLE);
      newCount = 0;
    }
  }

  function clearFeed() {
    visibleThreats = [];
    threats = [];
    newCount = 0;
  }

  function severityLine(s: unknown): string {
    switch ((String(s ?? "")).toLowerCase()) {
      case "critical": return "line-critical";
      case "high":     return "line-high";
      case "medium":   return "line-medium";
      case "low":      return "line-low";
      default:         return "line-info";
    }
  }

  function severityDotColor(s: unknown): string {
    switch ((String(s ?? "")).toLowerCase()) {
      case "critical": return "var(--color-danger)";
      case "high":     return "var(--color-warning)";
      case "medium":   return "oklch(72% 0.15 85)";
      case "low":      return "var(--color-text-muted)";
      default:         return "var(--color-text-tertiary)";
    }
  }

  function formatTime(ts: unknown): string {
    if (!ts) return "";
    try {
      return new Date(ts as string).toLocaleTimeString();
    } catch { return String(ts); }
  }

  function typeLabel(t: Record<string, unknown>): string {
    return String(t.type ?? t.threat_type ?? t.kind ?? "detection");
  }

  function sourceLabel(t: Record<string, unknown>): string {
    return String(t.source ?? t.src ?? t.host ?? t.ip ?? "");
  }

  function detailText(t: Record<string, unknown>): string {
    return String(t.details ?? t.description ?? t.message ?? JSON.stringify(t));
  }

  onMount(() => {
    refresh();
    return () => { polling = false; };
  });
</script>

<!-- min-width:0 + overflow:hidden 确保子元素不会撑开容器宽度 -->
<div style="width: 100%; min-width: 0; overflow-x: hidden;">
  <!-- Header -->
  <div class="monitor-header" style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px; gap: 8px;">
    <div style="min-width: 0;">
      <h2 style="font-size: 18px; font-weight: 600; color: var(--color-text); margin: 0;">实时监控</h2>
      <p style="font-size: 13px; color: var(--color-text-tertiary); margin: 4px 0 0;">实时威胁检测流</p>
    </div>
    <div style="display: flex; gap: 8px; flex-shrink: 0;">
      <button
        class="btn-secondary"
        style="{paused ? 'background: var(--color-warning-soft); color: var(--color-warning); border-color: var(--color-warning);' : ''}"
        onclick={togglePause}
      >
        {paused ? `继续 (${newCount} 条新)` : "暂停"}
      </button>
      <button class="btn-secondary" onclick={clearFeed}>清除</button>
    </div>
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
      <p style="color: var(--color-text-tertiary); font-size: 13px; margin: 0;">正在加载威胁流...</p>
    </div>

  {:else if visibleThreats.length === 0}
    <div class="card" style="padding: 48px 32px; text-align: center;">
      <p style="color: var(--color-text-tertiary); font-size: 13px; margin: 0;">暂未检测到威胁。</p>
      <p style="color: var(--color-text-muted); font-size: 12px; margin: 8px 0 0;">启动监控并生成流量以查看实时检测。</p>
    </div>

  {:else}
    <!-- Threat feed — min-width:0 防止内容撑开 -->
    <div style="display: flex; flex-direction: column; gap: 8px; width: 100%; min-width: 0;">
      {#each visibleThreats as t}
        <div class="card {severityLine(t.severity)}" style="width: 100%; box-sizing: border-box; min-width: 0; overflow: hidden; padding: 12px 16px; border-left-width: 3px;">
          <div style="display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; min-width: 0; overflow: hidden;">
            <div style="display: flex; align-items: center; gap: 8px; min-width: 0; flex: 1 1 0%;">
              <span style="width: 8px; height: 8px; border-radius: 50%; background: {severityDotColor(t.severity)}; flex-shrink: 0;"></span>
              <span style="font-size: 13px; font-weight: 500; color: var(--color-text); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; min-width: 0;">{typeLabel(t)}</span>
              {#if sourceLabel(t)}
                <span style="font-size: 12px; color: var(--color-text-tertiary); font-family: var(--font-mono); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; min-width: 0;">{sourceLabel(t)}</span>
              {/if}
            </div>
            <div style="display: flex; align-items: center; gap: 8px; flex-shrink: 0;">
              <span class="badge {severityLine(t.severity).replace('line-', 'badge-')}" style="text-transform: capitalize;">
                {String(t.severity ?? "info")}
              </span>
              <span style="font-size: 11px; color: var(--color-text-muted); font-family: var(--font-mono); white-space: nowrap;">{formatTime(t.timestamp)}</span>
            </div>
          </div>
          <p style="font-size: 12px; color: var(--color-text-tertiary); margin: 8px 0 0 16px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">{detailText(t)}</p>
        </div>
      {/each}
    </div>

    <div style="display: flex; align-items: center; justify-content: space-between; margin-top: 12px;">
      <span style="font-size: 11px; color: var(--color-text-muted);">显示 {visibleThreats.length} 条威胁</span>
      <span style="font-size: 11px; color: var(--color-text-muted);">{paused ? "已暂停" : "每 2 秒自动刷新"}</span>
    </div>
  {/if}
</div>

<style>
  /* ── Responsive: stack header at narrow widths ── */
  @media (max-width: 899px) {
    .monitor-header {
      flex-direction: column;
      align-items: flex-start;
      gap: 12px;
    }
  }
</style>
