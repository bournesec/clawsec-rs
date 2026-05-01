<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { onMount } from "svelte";

  interface ConfigData {
    http_proxy_port: number;
    gateway_local_port: number;
    gateway_target_port: number;
    log_dir: string;
    log_level: string;
    max_scan_bytes: number;
    ssh_poll_interval: number;
    dedup_window_secs: number;
    enable_http_proxy: boolean;
    enable_gateway_proxy: boolean;
    enable_ssh_watcher: boolean;
    enable_mitm: boolean;
  }

  let config = $state<ConfigData | null>(null);
  let loading = $state(true);
  let error = $state("");
  let saved = $state(false);
  let configPath = $state("");

  let httpProxyPort = $state(10808);
  let logLevel = $state("INFO");
  let maxScanBytes = $state(65536);
  let sshPollInterval = $state(10);
  let dedupWindow = $state(60);
  let enableHttpProxy = $state(true);
  let enableGatewayProxy = $state(true);
  let enableSshWatcher = $state(true);
  let enableMitm = $state(true);

  async function loadConfig() {
    try {
      config = await invoke("get_config");
      configPath = await invoke("get_config_path");
      httpProxyPort = config.http_proxy_port;
      logLevel = config.log_level;
      maxScanBytes = config.max_scan_bytes;
      sshPollInterval = config.ssh_poll_interval;
      dedupWindow = config.dedup_window_secs;
      enableHttpProxy = config.enable_http_proxy;
      enableGatewayProxy = config.enable_gateway_proxy;
      enableSshWatcher = config.enable_ssh_watcher;
      enableMitm = config.enable_mitm;
      error = "";
    } catch (e) {
      error = String(e);
    }
    loading = false;
  }

  async function handleSave() {
    try {
      const updated: ConfigData = {
        http_proxy_port: httpProxyPort,
        gateway_local_port: config?.gateway_local_port ?? 18790,
        gateway_target_port: config?.gateway_target_port ?? 18789,
        log_dir: config?.log_dir ?? "/tmp/clawsec",
        log_level: logLevel,
        max_scan_bytes: maxScanBytes,
        ssh_poll_interval: sshPollInterval,
        dedup_window_secs: dedupWindow,
        enable_http_proxy: enableHttpProxy,
        enable_gateway_proxy: enableGatewayProxy,
        enable_ssh_watcher: enableSshWatcher,
        enable_mitm: enableMitm,
      };
      await invoke("save_config", { config: updated });
      config = updated;
      saved = true;
      error = "";
      setTimeout(() => { saved = false; }, 3000);
    } catch (e) {
      error = String(e);
    }
  }

  async function handleReset() {
    try {
      const defaults: ConfigData = {
        http_proxy_port: 10808,
        gateway_local_port: 18790,
        gateway_target_port: 18789,
        log_dir: "/tmp/clawsec",
        log_level: "INFO",
        max_scan_bytes: 65536,
        ssh_poll_interval: 10,
        dedup_window_secs: 60,
        enable_http_proxy: true,
        enable_gateway_proxy: true,
        enable_ssh_watcher: true,
        enable_mitm: true,
      };
      await invoke("save_config", { config: defaults });
      await loadConfig();
      error = "";
    } catch (e) {
      error = String(e);
    }
  }

  onMount(() => {
    loadConfig();
  });
</script>

<div style="width: 100%; min-width: 0; overflow-x: hidden;">
  <div style="margin-bottom: 16px; min-width: 0;">
    <h2 style="font-size: 18px; font-weight: 600; color: var(--color-text); margin: 0;">设置</h2>
    <p style="font-size: 13px; color: var(--color-text-tertiary); margin: 4px 0 0; font-family: var(--font-mono); overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">{configPath || "加载中..."}</p>
  </div>

  {#if error}
    <div style="margin-bottom: 16px; padding: 12px 16px; background: var(--color-danger-soft); border: 1px solid var(--color-danger); border-radius: var(--radius-lg);">
      <p style="color: var(--color-danger); font-size: 13px; font-family: var(--font-mono); margin: 0;">{error}</p>
    </div>
  {/if}

  {#if saved}
    <div style="margin-bottom: 16px; padding: 12px 16px; background: var(--color-success-soft); border: 1px solid var(--color-success); border-radius: var(--radius-lg);">
      <p style="color: var(--color-success); font-size: 13px; font-family: var(--font-mono); margin: 0;">配置已保存成功。</p>
    </div>
  {/if}

  {#if loading}
    <div class="card" style="padding: 32px;">
      <p style="color: var(--color-text-tertiary); font-size: 13px; margin: 0;">正在加载配置...</p>
    </div>
  {:else}
    <div style="display: flex; flex-wrap: wrap; gap: 16px; width: 100%; min-width: 0;">

      <div class="card" style="flex: 1 1 280px; min-width: 0; padding: 20px;">
        <h3 style="font-size: 13px; font-weight: 500; color: var(--color-text-secondary); margin: 0 0 12px;">代理设置</h3>
        <div style="display: flex; flex-direction: column; gap: 12px;">
          <label style="display: block;">
            <span style="font-size: 11px; color: var(--color-text-muted); display: block; margin-bottom: 6px;">HTTP 代理端口</span>
            <input type="number" bind:value={httpProxyPort}
              style="width: 100%; background: var(--color-bg); border: 1px solid var(--color-border); border-radius: var(--radius-md); padding: 8px 12px; font-size: 13px; color: var(--color-text); font-family: var(--font-mono); outline: none; box-sizing: border-box;" />
          </label>
          <label style="display: block;">
            <span style="font-size: 11px; color: var(--color-text-muted); display: block; margin-bottom: 6px;">最大扫描字节数</span>
            <input type="number" bind:value={maxScanBytes}
              style="width: 100%; background: var(--color-bg); border: 1px solid var(--color-border); border-radius: var(--radius-md); padding: 8px 12px; font-size: 13px; color: var(--color-text); font-family: var(--font-mono); outline: none; box-sizing: border-box;" />
          </label>
        </div>
      </div>

      <div class="card" style="flex: 1 1 280px; min-width: 0; padding: 20px;">
        <h3 style="font-size: 13px; font-weight: 500; color: var(--color-text-secondary); margin: 0 0 12px;">监控参数</h3>
        <div style="display: flex; flex-direction: column; gap: 12px;">
          <label style="display: block;">
            <span style="font-size: 11px; color: var(--color-text-muted); display: block; margin-bottom: 6px;">SSH 轮询间隔（秒）</span>
            <input type="number" bind:value={sshPollInterval}
              style="width: 100%; background: var(--color-bg); border: 1px solid var(--color-border); border-radius: var(--radius-md); padding: 8px 12px; font-size: 13px; color: var(--color-text); font-family: var(--font-mono); outline: none; box-sizing: border-box;" />
          </label>
          <label style="display: block;">
            <span style="font-size: 11px; color: var(--color-text-muted); display: block; margin-bottom: 6px;">去重窗口（秒）</span>
            <input type="number" bind:value={dedupWindow}
              style="width: 100%; background: var(--color-bg); border: 1px solid var(--color-border); border-radius: var(--radius-md); padding: 8px 12px; font-size: 13px; color: var(--color-text); font-family: var(--font-mono); outline: none; box-sizing: border-box;" />
          </label>
        </div>
      </div>

      <div class="card" style="flex: 1 1 200px; min-width: 0; padding: 20px;">
        <h3 style="font-size: 13px; font-weight: 500; color: var(--color-text-secondary); margin: 0 0 12px;">日志</h3>
        <label style="display: block;">
          <span style="font-size: 11px; color: var(--color-text-muted); display: block; margin-bottom: 6px;">日志级别</span>
          <select bind:value={logLevel}
            style="width: 100%; background: var(--color-bg); border: 1px solid var(--color-border); border-radius: var(--radius-md); padding: 8px 12px; font-size: 13px; color: var(--color-text); font-family: var(--font-mono); outline: none; box-sizing: border-box;">
            <option value="ERROR">ERROR</option>
            <option value="WARN">WARN</option>
            <option value="INFO">INFO</option>
            <option value="DEBUG">DEBUG</option>
            <option value="TRACE">TRACE</option>
          </select>
        </label>
      </div>

      <div class="card" style="flex: 1 1 240px; min-width: 0; padding: 20px;">
        <h3 style="font-size: 13px; font-weight: 500; color: var(--color-text-secondary); margin: 0 0 12px;">功能组件</h3>
        <div style="display: flex; flex-direction: column; gap: 10px;">
          <label style="display: flex; align-items: center; gap: 10px; cursor: pointer;">
            <input type="checkbox" bind:checked={enableHttpProxy} style="width: 16px; height: 16px; accent-color: var(--color-accent);" />
            <span style="font-size: 13px; color: var(--color-text-secondary);">HTTP 代理</span>
          </label>
          <label style="display: flex; align-items: center; gap: 10px; cursor: pointer;">
            <input type="checkbox" bind:checked={enableGatewayProxy} style="width: 16px; height: 16px; accent-color: var(--color-accent);" />
            <span style="font-size: 13px; color: var(--color-text-secondary);">网关代理</span>
          </label>
          <label style="display: flex; align-items: center; gap: 10px; cursor: pointer;">
            <input type="checkbox" bind:checked={enableSshWatcher} style="width: 16px; height: 16px; accent-color: var(--color-accent);" />
            <span style="font-size: 13px; color: var(--color-text-secondary);">SSH 监听</span>
          </label>
          <label style="display: flex; align-items: center; gap: 10px; cursor: pointer;">
            <input type="checkbox" bind:checked={enableMitm} style="width: 16px; height: 16px; accent-color: var(--color-accent);" />
            <span style="font-size: 13px; color: var(--color-text-secondary);">MITM 解密</span>
          </label>
        </div>
      </div>

    </div>

    <div style="display: flex; align-items: center; gap: 10px; margin-top: 16px;">
      <button class="btn-primary" onclick={handleSave}>保存配置</button>
      <button class="btn-secondary" onclick={handleReset}>恢复默认</button>
    </div>
  {/if}
</div>
