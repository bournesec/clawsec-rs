<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { onMount } from "svelte";

  let threats = $state<Record<string, unknown>[]>([]);
  let loading = $state(true);
  let error = $state("");
  let polling = $state(true);

  async function refresh() {
    try {
      threats = await invoke("get_threats", { limit: 100 });
      error = "";
    } catch (e) {
      error = String(e);
    }
    loading = false;
    if (polling) setTimeout(refresh, 3000);
  }

  onMount(() => {
    refresh();
    return () => { polling = false; };
  });

  function formatTime(raw: unknown): string {
    if (!raw) return "\u2014";
    try { return new Date(raw as string).toLocaleString(); }
    catch { return String(raw); }
  }

  function badgeClass(severity: unknown): string {
    switch ((String(severity ?? "")).toLowerCase()) {
      case "critical": return "badge-critical";
      case "high":     return "badge-high";
      case "medium":   return "badge-medium";
      case "low":      return "badge-low";
      default:         return "badge-low";
    }
  }

  function displayType(t: Record<string, unknown>): string {
    return String(t.type ?? t.threat_type ?? t.kind ?? "\u2014");
  }

  function displaySource(t: Record<string, unknown>): string {
    return String(t.source ?? t.src ?? t.host ?? t.ip ?? "\u2014");
  }
</script>

<div style="width: 100%; min-width: 0; overflow-x: hidden;">
  <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px; gap: 8px;">
    <div style="min-width: 0;">
      <h2 style="font-size: 18px; font-weight: 600; color: var(--color-text); margin: 0;">威胁列表</h2>
      <p style="font-size: 13px; color: var(--color-text-tertiary); margin: 4px 0 0;">所有已检测到的威胁</p>
    </div>
    {#if !loading}
      <span style="font-size: 12px; color: var(--color-text-muted);">{threats.length} 条威胁</span>
    {/if}
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
      <p style="color: var(--color-text-tertiary); font-size: 13px; margin: 0;">正在加载威胁数据...</p>
    </div>

  {:else if threats.length === 0}
    <div class="card" style="padding: 48px 32px; text-align: center;">
      <p style="color: var(--color-text-tertiary); font-size: 13px; margin: 0;">暂未检测到威胁。</p>
      <p style="color: var(--color-text-muted); font-size: 12px; margin: 8px 0 0;">启动监控以开始检测威胁。</p>
    </div>

  {:else}
    <!-- Table -->
    <div class="card" style="overflow: hidden; width: 100%; min-width: 0;">
      <div style="overflow-x: auto; width: 100%; min-width: 0;">
        <table style="width: 100%; table-layout: fixed; border-collapse: collapse; font-size: 13px;">
          <thead>
            <tr style="border-bottom: 1px solid var(--color-border);">
              <th style="padding: 10px 12px; text-align: left; font-weight: 500; font-size: 11px; color: var(--color-text-muted); text-transform: uppercase; letter-spacing: 0.05em; white-space: nowrap; width: 18%;">时间</th>
              <th style="padding: 10px 12px; text-align: left; font-weight: 500; font-size: 11px; color: var(--color-text-muted); text-transform: uppercase; letter-spacing: 0.05em; white-space: nowrap; width: 12%;">类型</th>
              <th class="col-source" style="padding: 10px 12px; text-align: left; font-weight: 500; font-size: 11px; color: var(--color-text-muted); text-transform: uppercase; letter-spacing: 0.05em; white-space: nowrap; max-width: 25%;">来源</th>
              <th style="padding: 10px 12px; text-align: left; font-weight: 500; font-size: 11px; color: var(--color-text-muted); text-transform: uppercase; letter-spacing: 0.05em; white-space: nowrap; width: 10%;">级别</th>
              <th style="padding: 10px 12px; text-align: left; font-weight: 500; font-size: 11px; color: var(--color-text-muted); text-transform: uppercase; letter-spacing: 0.05em;">详情</th>
            </tr>
          </thead>
          <tbody>
            {#each threats as t}
              <tr style="border-bottom: 1px solid var(--color-border-light); transition: background var(--duration-fast) var(--ease-out);">
                <td style="padding: 10px 12px; color: var(--color-text-tertiary); font-family: var(--font-mono); font-size: 12px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">
                  {formatTime(t.timestamp)}
                </td>
                <td style="padding: 10px 12px; color: var(--color-text); font-weight: 500; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">
                  {displayType(t)}
                </td>
                <td class="col-source" style="padding: 10px 12px; color: var(--color-text-tertiary); font-family: var(--font-mono); font-size: 12px; max-width: 200px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">
                  {displaySource(t)}
                </td>
                <td style="padding: 10px 12px;">
                  <span class="badge {badgeClass(t.severity)}" style="text-transform: capitalize;">
                    {String(t.severity ?? "unknown")}
                  </span>
                </td>
                <td style="padding: 10px 12px; color: var(--color-text-tertiary); font-size: 12px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;" title={JSON.stringify(t)}>
                  {String(t.details ?? t.description ?? t.message ?? "")}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    </div>

    <p style="margin-top: 12px; font-size: 11px; color: var(--color-text-muted);">每 3 秒自动刷新</p>
  {/if}
</div>

<style>
  /* ── Responsive: hide Source column at narrow widths ── */
  @media (max-width: 899px) {
    .col-source {
      display: none;
    }
  }
</style>
