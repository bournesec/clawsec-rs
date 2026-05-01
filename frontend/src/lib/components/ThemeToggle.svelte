<script lang="ts">
  import { theme } from "../theme.svelte";

  function cycle() {
    // Brief transition class for smooth animation
    document.documentElement.classList.add("theme-transitioning");
    theme.cycle();
    setTimeout(() => {
      document.documentElement.classList.remove("theme-transitioning");
    }, 400);
  }
</script>

<button
  class="theme-toggle"
  onclick={cycle}
  title="Switch theme (current: {theme.label})"
  aria-label="Toggle theme"
>
  {#if theme.mode === "dark"}
    <!-- Moon -->
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
    </svg>
  {:else if theme.mode === "light"}
    <!-- Sun -->
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <circle cx="12" cy="12" r="5" />
      <line x1="12" y1="1" x2="12" y2="3" />
      <line x1="12" y1="21" x2="12" y2="23" />
      <line x1="4.22" y1="4.22" x2="5.64" y2="5.64" />
      <line x1="18.36" y1="18.36" x2="19.78" y2="19.78" />
      <line x1="1" y1="12" x2="3" y2="12" />
      <line x1="21" y1="12" x2="23" y2="12" />
      <line x1="4.22" y1="19.78" x2="5.64" y2="18.36" />
      <line x1="18.36" y1="5.64" x2="19.78" y2="4.22" />
    </svg>
  {:else}
    <!-- System: monitor icon -->
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <rect x="2" y="3" width="20" height="14" rx="2" ry="2" />
      <line x1="8" y1="21" x2="16" y2="21" />
      <line x1="12" y1="17" x2="12" y2="21" />
    </svg>
  {/if}
</button>

<style>
  .theme-toggle {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 32px;
    height: 32px;
    border-radius: var(--radius-md);
    border: 1px solid var(--color-border);
    background: var(--color-bg-hover);
    color: var(--color-text-tertiary);
    cursor: pointer;
    transition: all var(--duration-fast) var(--ease-out);
  }
  .theme-toggle:hover {
    background: var(--color-bg-elevated);
    color: var(--color-text-secondary);
    border-color: var(--color-border-accent);
  }
</style>
