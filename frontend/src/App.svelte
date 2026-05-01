<script lang="ts">
  import { onMount } from "svelte";
  import { theme } from "./lib/theme.svelte";
  import Sidebar from "./lib/components/Sidebar.svelte";
  import Dashboard from "./lib/components/Dashboard.svelte";
  import LiveMonitor from "./lib/components/LiveMonitor.svelte";
  import Threats from "./lib/components/Threats.svelte";
  import Config from "./lib/components/Config.svelte";

  let currentPage = $state("dashboard");

  onMount(() => {
    // Listen for OS-level theme changes
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    const handler = () => {
      if (theme.mode === "system") {
        theme.setMode("system"); // re-resolve
      }
    };
    mq.addEventListener("change", handler);
    return () => mq.removeEventListener("change", handler);
  });
</script>

<div class="flex h-screen">
  <Sidebar current={currentPage} onNavigate={(page: string) => (currentPage = page)} />
  <main class="flex-1 overflow-y-auto bg-surface" style="padding: clamp(12px, 2vw, 24px); min-width: 0; overflow-x: hidden;">
    {#if currentPage === "dashboard"}
      <Dashboard />
    {:else if currentPage === "live"}
      <LiveMonitor />
    {:else if currentPage === "threats"}
      <Threats />
    {:else if currentPage === "config"}
      <Config />
    {/if}
  </main>
</div>
