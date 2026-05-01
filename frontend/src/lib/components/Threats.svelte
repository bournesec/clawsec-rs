<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { onMount } from "svelte";
  import { highlightPayload } from "../highlight";

  let threats = $state<Record<string, unknown>[]>([]);
  let loading = $state(true);
  let error = $state("");
  let polling = $state(true);
  let currentPage = $state(1);
  let selectedThreat = $state<Record<string, unknown> | null>(null);

const PAGE_SIZE = 10;

  let totalPages = $derived(Math.max(1, Math.ceil(threats.length / PAGE_SIZE)));
  let pagedThreats = $derived(
    threats.slice((currentPage - 1) * PAGE_SIZE, currentPage * PAGE_SIZE),
  );

  async function refresh() {
    try {
      threats = await invoke("get_threats", { limit: 500 });
      error = "";
    } catch (e) {
      error = String(e);
    }
    loading = false;
    if (polling) setTimeout(refresh, 3000);
  }

  function goToPage(page: number) {
    if (page >= 1 && page <= totalPages) currentPage = page;
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

  function deriveSeverity(t: Record<string, unknown>): string {
    const explicit = String(t.severity ?? "").toLowerCase();
    if (["critical", "high", "medium", "low"].includes(explicit)) return explicit;

    const pattern = String(t.pattern ?? "").toLowerCase();
    const threatType = String(t.threat_type ?? t.type ?? "").toLowerCase();

    if (["ai_api_key", "private_key_pem", "aws_access_key"].includes(pattern)) return "critical";
    if (["reverse_shell", "destructive_rm", "shell_exec", "ssh_key_inject"].includes(pattern)) return "critical";

    if (threatType === "ssh_connect") return "high";
    if (["pipe_to_shell", "unix_sensitive"].includes(pattern)) return "high";

    if (["ssh_key_file", "dotenv_file", "ssh_pubkey"].includes(pattern)) return "medium";

    return "low";
  }

  function badgeClass(severity: string): string {
    switch (severity) {
      case "critical": return "badge-critical";
      case "high":     return "badge-high";
      case "medium":   return "badge-medium";
      case "low":      return "badge-low";
      default:         return "badge-low";
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

  function displayType(t: Record<string, unknown>): string {
    const pattern = String(t.pattern ?? "");
    if (pattern) return pattern;
    return String(t.threat_type ?? t.type ?? t.kind ?? "\u2014");
  }

  function displaySource(t: Record<string, unknown>): string {
    return String(t.source ?? t.src ?? t.host ?? t.ip ?? "\u2014");
  }

  function displayDest(t: Record<string, unknown>): string {
    return String(t.dest ?? t.destination ?? "\u2014");
  }

  function displayDetail(t: Record<string, unknown>): string {
    const snippet = String(t.snippet ?? "");
    if (snippet) return snippet;
    return String(t.details ?? t.description ?? t.message ?? "");
  }

  function fullPayload(t: Record<string, unknown>): string {
    return String(t.raw_payload ?? t.snippet ?? t.details ?? t.message ?? "");
  }
</script>

<div style="width: 100%; min-width: 0; overflow-x: hidden;">
  <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px; gap: 8px;">
    <div style="min-width: 0;">
      <h2 style="font-size: 18px; font-weight: 600; color: var(--color-text); margin: 0;">威胁列表</h2>
      <p style="font-size: 13px; color: var(--color-text-tertiary); margin: 4px 0 0;">所有已检测到的威胁</p>
    </div>
    {#if !loading}
      <span style="font-size: 12px; color: var(--color-text-muted); white-space: nowrap;">共 {threats.length} 条威胁</span>
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
              <th style="padding: 10px 12px; text-align: left; font-weight: 500; font-size: 11px; color: var(--color-text-muted); text-transform: uppercase; letter-spacing: 0.05em; white-space: nowrap; width: 16%;">时间</th>
              <th style="padding: 10px 12px; text-align: left; font-weight: 500; font-size: 11px; color: var(--color-text-muted); text-transform: uppercase; letter-spacing: 0.05em; white-space: nowrap; width: 13%;">类型</th>
              <th class="col-source" style="padding: 10px 12px; text-align: left; font-weight: 500; font-size: 11px; color: var(--color-text-muted); text-transform: uppercase; letter-spacing: 0.05em; white-space: nowrap; width: 22%;">来源</th>
              <th style="padding: 10px 12px; text-align: left; font-weight: 500; font-size: 11px; color: var(--color-text-muted); text-transform: uppercase; letter-spacing: 0.05em; white-space: nowrap; width: 8%;">级别</th>
              <th style="padding: 10px 12px; text-align: left; font-weight: 500; font-size: 11px; color: var(--color-text-muted); text-transform: uppercase; letter-spacing: 0.05em; white-space: nowrap;">详情</th>
            </tr>
          </thead>
          <tbody>
            {#each pagedThreats as t}
              {@const sev = deriveSeverity(t)}
              <tr style="border-bottom: 1px solid var(--color-border-light); transition: background var(--duration-fast) var(--ease-out);">
                <td style="padding: 10px 12px; color: var(--color-text-tertiary); font-family: var(--font-mono); font-size: 12px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">
                  {formatTime(t.timestamp)}
                </td>
                <td style="padding: 10px 12px; color: var(--color-text); font-weight: 500; overflow: hidden; text-overflow: ellipsis;">
                  {displayType(t)}
                </td>
                <td class="col-source" style="padding: 10px 12px; color: var(--color-text-tertiary); font-family: var(--font-mono); font-size: 12px; word-break: break-all; overflow-wrap: break-word;">
                  <div>{displaySource(t)}</div>
                  {#if displayDest(t) !== "\u2014"}
                    <div style="color: var(--color-text-muted); font-size: 11px;">→ {displayDest(t)}</div>
                  {/if}
                </td>
                <td style="padding: 10px 12px;">
                  <span class="badge {badgeClass(sev)}">
                    {severityLabel(sev)}
                  </span>
                </td>
                <td style="padding: 10px 12px; font-size: 12px; overflow: hidden;">
                  <pre style="margin: 0; word-break: break-all; overflow-wrap: break-word; white-space: pre-wrap; line-height: 1.5; font-size: 12px; color: var(--color-text-tertiary); background: var(--color-bg); border-radius: var(--radius-sm); padding: 6px 10px; font-family: var(--font-mono); border: 1px solid var(--color-border-light);">{@html highlightPayload(displayDetail(t), String(t.pattern ?? ""))}</pre>
                  <button
                    class="btn-secondary"
                    style="padding: 2px 8px; font-size: 11px; margin-top: 6px;"
                    onclick={() => { selectedThreat = t; }}
                  >详情</button>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    </div>

    <!-- Pagination + Status -->
    <div style="display: flex; align-items: center; justify-content: space-between; margin-top: 12px; gap: 8px; flex-wrap: wrap;">
      <span style="font-size: 11px; color: var(--color-text-muted);">每 3 秒自动刷新</span>

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
        <span style="color: var(--color-text);">{displayType(selectedThreat)}</span>

        <span style="color: var(--color-text-muted);">等级</span>
        <span class="badge {badgeClass(sev)}">{severityLabel(sev)}</span>

        <span style="color: var(--color-text-muted);">协议</span>
        <span style="color: var(--color-text);">{String(selectedThreat.protocol ?? "\u2014").toUpperCase()}</span>

        <span style="color: var(--color-text-muted);">方向</span>
        <span style="color: var(--color-text);">{String(selectedThreat.direction ?? "") === "outbound" ? "出站" : String(selectedThreat.direction ?? "") === "inbound" ? "入站" : String(selectedThreat.direction ?? "\u2014")}</span>

        <span style="color: var(--color-text-muted);">来源</span>
        <span style="color: var(--color-text); font-family: var(--font-mono); font-size: 12px; word-break: break-all;">{displaySource(selectedThreat)}</span>

        <span style="color: var(--color-text-muted);">目标</span>
        <span style="color: var(--color-text); font-family: var(--font-mono); font-size: 12px; word-break: break-all;">{displayDest(selectedThreat)}</span>

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

<style>
  @media (max-width: 899px) {
    .col-source {
      display: none;
    }
  }
</style>
