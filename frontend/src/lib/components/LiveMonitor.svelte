<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { onMount } from "svelte";
  import { highlightPayload } from "../highlight";

  let threats = $state<Record<string, unknown>[]>([]);
  let loading = $state(true);
  let error = $state("");
  let polling = $state(true);
  let paused = $state(false);
  let newCount = $state(0);
  let latestTimestamp = $state(0);
  let currentPage = $state(1);
  let selectedThreat = $state<Record<string, unknown> | null>(null);

  const PAGE_SIZE = 10;

  let totalPages = $derived(Math.max(1, Math.ceil(threats.length / PAGE_SIZE)));
  let pagedThreats = $derived(
    [...threats].reverse().slice((currentPage - 1) * PAGE_SIZE, currentPage * PAGE_SIZE),
  );

  async function refresh() {
    try {
      const fresh = (await invoke("get_threats", { limit: 500 })) as Record<string, unknown>[];
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

      if (!paused && newCount > 0) {
        currentPage = 1;
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
      currentPage = 1;
      newCount = 0;
    }
  }

  function clearFeed() {
    threats = [];
    newCount = 0;
    currentPage = 1;
  }

  function goToPage(page: number) {
    if (page >= 1 && page <= totalPages) currentPage = page;
  }

  function deriveSeverity(t: Record<string, unknown>): string {
    // Use explicit severity if present
    const explicit = String(t.severity ?? "").toLowerCase();
    if (["critical", "high", "medium", "low"].includes(explicit)) return explicit;

    const pattern = String(t.pattern ?? "").toLowerCase();
    const threatType = String(t.threat_type ?? t.type ?? "").toLowerCase();

    // Critical: API keys, private keys, destructive commands
    if (["ai_api_key", "private_key_pem", "aws_access_key"].includes(pattern)) return "critical";
    if (["reverse_shell", "destructive_rm", "shell_exec", "ssh_key_inject"].includes(pattern)) return "critical";

    // High: SSH connect, pipe to shell, sensitive files
    if (threatType === "ssh_connect") return "high";
    if (["pipe_to_shell", "unix_sensitive"].includes(pattern)) return "high";

    // Medium: file access patterns
    if (["ssh_key_file", "dotenv_file", "ssh_pubkey"].includes(pattern)) return "medium";

    return "low";
  }

  function severityLine(s: unknown): string {
    const sev = String(s ?? "").toLowerCase();
    switch (sev) {
      case "critical": return "line-critical";
      case "high":     return "line-high";
      case "medium":   return "line-medium";
      case "low":      return "line-low";
      default:         return "line-info";
    }
  }

  function severityDotColor(s: unknown): string {
    switch (String(s ?? "").toLowerCase()) {
      case "critical": return "var(--color-danger)";
      case "high":     return "var(--color-warning)";
      case "medium":   return "oklch(72% 0.15 85)";
      case "low":      return "var(--color-text-muted)";
      default:         return "var(--color-text-tertiary)";
    }
  }

  function severityLabel(sev: string): string {
    switch (sev) {
      case "critical": return "严重";
      case "high":     return "高危";
      case "medium":   return "中危";
      case "low":      return "低危";
      default:         return "信息";
    }
  }

  function formatTime(ts: unknown): string {
    if (!ts) return "";
    try {
      return new Date(ts as string).toLocaleTimeString();
    } catch { return String(ts); }
  }

  function typeLabel(t: Record<string, unknown>): string {
    const pattern = String(t.pattern ?? "");
    if (pattern) return pattern;
    return String(t.threat_type ?? t.type ?? t.kind ?? "detection");
  }

  function sourceLabel(t: Record<string, unknown>): string {
    return String(t.source ?? t.src ?? t.host ?? t.ip ?? "");
  }

  function destLabel(t: Record<string, unknown>): string {
    return String(t.dest ?? t.destination ?? "");
  }

  function protoLabel(t: Record<string, unknown>): string {
    return String(t.protocol ?? "").toUpperCase();
  }

  function directionLabel(t: Record<string, unknown>): string {
    const d = String(t.direction ?? "");
    return d === "outbound" ? "出站" : d === "inbound" ? "入站" : d;
  }

  function detailText(t: Record<string, unknown>): string {
    return String(t.snippet ?? t.details ?? t.description ?? t.message ?? "");
  }

  function fullPayload(t: Record<string, unknown>): string {
    return String(t.raw_payload ?? t.snippet ?? t.details ?? t.message ?? "");
  }

  onMount(() => {
    refresh();
    return () => { polling = false; };
  });
</script>

<div style="width: 100%; min-width: 0; overflow-x: hidden;">
  <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px; gap: 8px;">
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

  {:else if threats.length === 0}
    <div class="card" style="padding: 48px 32px; text-align: center;">
      <p style="color: var(--color-text-tertiary); font-size: 13px; margin: 0;">暂未检测到威胁。</p>
      <p style="color: var(--color-text-muted); font-size: 12px; margin: 8px 0 0;">启动监控并生成流量以查看实时检测。</p>
    </div>

  {:else}
    <!-- Threat feed — 外层 card 确保宽度约束，与威胁列表保持一致 -->
    <div class="card" style="overflow: hidden; width: 100%; min-width: 0;">
      <div style="width: 100%; min-width: 0;">
        {#each pagedThreats as t}
          {@const sev = deriveSeverity(t)}
          <div class="{severityLine(sev)}" style="width: 100%; box-sizing: border-box; min-width: 0; overflow: hidden; padding: 12px 16px; border: 1px solid var(--color-border-light); border-left-width: 3px; border-radius: var(--radius-md); margin-bottom: 8px;">
            <div style="display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; min-width: 0;">
              <div style="display: flex; align-items: flex-start; gap: 8px; min-width: 0; flex: 1 1 0%;">
                <span style="width: 8px; height: 8px; border-radius: 50%; background: {severityDotColor(sev)}; flex-shrink: 0; margin-top: 4px;"></span>
                <div style="min-width: 0; flex: 1 1 0%;">
                  <div style="display: flex; align-items: center; gap: 6px; min-width: 0;">
                    <span style="font-size: 13px; font-weight: 500; color: var(--color-text); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; min-width: 0;">{typeLabel(t)}</span>
                    <span style="font-size: 11px; color: var(--color-accent); font-family: var(--font-mono); white-space: nowrap; flex-shrink: 0;">{protoLabel(t)}</span>
                    <span style="font-size: 11px; color: var(--color-text-muted); white-space: nowrap; flex-shrink: 0;">{directionLabel(t)}</span>
                  </div>
                  <div style="display: flex; gap: 8px; margin-top: 2px; min-width: 0;">
                    {#if sourceLabel(t)}
                      <span style="font-size: 12px; color: var(--color-text-tertiary); font-family: var(--font-mono); word-break: break-all;">{sourceLabel(t)}</span>
                    {/if}
                    {#if destLabel(t)}
                      <span style="font-size: 12px; color: var(--color-text-muted); font-family: var(--font-mono); white-space: nowrap;">→ {destLabel(t)}</span>
                    {/if}
                  </div>
                </div>
              </div>
              <div style="display: flex; align-items: center; gap: 8px; flex-shrink: 0;">
                <span class="badge {severityLine(sev).replace('line-', 'badge-')}">
                  {severityLabel(sev)}
                </span>
                <span style="font-size: 11px; color: var(--color-text-muted); font-family: var(--font-mono); white-space: nowrap;">{formatTime(t.timestamp)}</span>
                <button
                  class="btn-secondary"
                  style="padding: 2px 8px; font-size: 11px;"
                  onclick={() => { selectedThreat = t; }}
                >详情</button>
              </div>
            </div>
            {#if detailText(t)}
              <pre style="font-size: 12px; color: var(--color-text-tertiary); margin: 8px 0 0 16px; word-break: break-all; white-space: pre-wrap; line-height: 1.5; max-height: 120px; overflow-y: auto; background: var(--color-bg); border-radius: var(--radius-sm); padding: 8px 12px; font-family: var(--font-mono); border: 1px solid var(--color-border-light);">{@html highlightPayload(detailText(t), String(t.pattern ?? ""))}</pre>
            {/if}
          </div>
        {/each}
      </div>
    </div>

    <!-- Pagination + Status -->
    <div style="display: flex; align-items: center; justify-content: space-between; margin-top: 12px; gap: 8px; flex-wrap: wrap;">
      <span style="font-size: 11px; color: var(--color-text-muted);">共 {threats.length} 条威胁</span>

      <div style="display: flex; align-items: center; gap: 4px;">
        <button
          class="btn-secondary"
          style="padding: 4px 10px; font-size: 12px;"
          disabled={currentPage <= 1}
          onclick={() => goToPage(1)}
        >首页</button>
        <button
          class="btn-secondary"
          style="padding: 4px 10px; font-size: 12px;"
          disabled={currentPage <= 1}
          onclick={() => goToPage(currentPage - 1)}
        >上一页</button>
        <span style="font-size: 12px; color: var(--color-text-tertiary); padding: 0 8px; white-space: nowrap;">
          第 {currentPage} / {totalPages} 页
        </span>
        <button
          class="btn-secondary"
          style="padding: 4px 10px; font-size: 12px;"
          disabled={currentPage >= totalPages}
          onclick={() => goToPage(currentPage + 1)}
        >下一页</button>
        <button
          class="btn-secondary"
          style="padding: 4px 10px; font-size: 12px;"
          disabled={currentPage >= totalPages}
          onclick={() => goToPage(totalPages)}
        >末页</button>
      </div>

      <span style="font-size: 11px; color: var(--color-text-muted);">{paused ? "已暂停" : "每 2 秒自动刷新"}</span>
    </div>
  {/if}
</div>

<!-- Detail Modal -->
{#if selectedThreat}
  {@const sev = deriveSeverity(selectedThreat)}
  {@const pat = String(selectedThreat.pattern ?? "")}
  {@const detail = fullPayload(selectedThreat)}
  <!-- svelte-ignore a11y_click_events_have_key_events -->
  <!-- svelte-ignore a11y_no_static_element_interactions -->
  <div
    class="modal-backdrop"
    style="position: fixed; inset: 0; z-index: 1000; display: flex; align-items: center; justify-content: center; background: rgba(0,0,0,0.5);"
    onclick={() => { selectedThreat = null; }}
  >
    <!-- svelte-ignore a11y_click_events_have_key_events -->
    <!-- svelte-ignore a11y_no_static_element_interactions -->
    <div
      class="card modal-content"
      style="width: min(720px, 90vw); max-height: 85vh; overflow-y: auto; padding: 24px; position: relative;"
      onclick={(e) => { e.stopPropagation(); }}
    >
      <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 20px;">
        <h3 style="font-size: 16px; font-weight: 600; color: var(--color-text); margin: 0;">威胁详情</h3>
        <button
          class="btn-secondary"
          style="padding: 4px 12px; font-size: 12px;"
          onclick={() => { selectedThreat = null; }}
        >关闭</button>
      </div>

      <div style="display: grid; grid-template-columns: 80px 1fr; gap: 10px 16px; font-size: 13px; margin-bottom: 20px;">
        <span style="color: var(--color-text-muted);">时间</span>
        <span style="color: var(--color-text); font-family: var(--font-mono); font-size: 12px;">{new Date(String(selectedThreat.timestamp ?? "")).toLocaleString()}</span>

        <span style="color: var(--color-text-muted);">类型</span>
        <span style="color: var(--color-text);">{typeLabel(selectedThreat)}</span>

        <span style="color: var(--color-text-muted);">等级</span>
        <span class="badge {severityLine(sev).replace('line-', 'badge-')}">{severityLabel(sev)}</span>

        <span style="color: var(--color-text-muted);">协议</span>
        <span style="color: var(--color-text);">{protoLabel(selectedThreat)}</span>

        <span style="color: var(--color-text-muted);">方向</span>
        <span style="color: var(--color-text);">{directionLabel(selectedThreat)}</span>

        <span style="color: var(--color-text-muted);">来源</span>
        <span style="color: var(--color-text); font-family: var(--font-mono); font-size: 12px; word-break: break-all;">{sourceLabel(selectedThreat) || "\u2014"}</span>

        <span style="color: var(--color-text-muted);">目标</span>
        <span style="color: var(--color-text); font-family: var(--font-mono); font-size: 12px; word-break: break-all;">{destLabel(selectedThreat) || "\u2014"}</span>

        <span style="color: var(--color-text-muted);">威胁类型</span>
        <span style="color: var(--color-text);">{String(selectedThreat.threat_type ?? "\u2014")}</span>
      </div>

      <div style="margin-bottom: 8px;">
        <span style="font-size: 12px; font-weight: 500; color: var(--color-text-muted);">攻击载荷</span>
      </div>
      <pre style="margin: 0; word-break: break-all; overflow-wrap: break-word; white-space: pre-wrap; line-height: 1.6; font-size: 13px; color: var(--color-text); background: var(--color-bg); border-radius: var(--radius-md); padding: 16px; font-family: var(--font-mono); border: 1px solid var(--color-border); max-height: 400px; overflow-y: auto;">{@html highlightPayload(detail, pat)}</pre>
    </div>
  </div>
{/if}
