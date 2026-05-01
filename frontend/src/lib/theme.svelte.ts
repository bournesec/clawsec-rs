type ThemeMode = "system" | "light" | "dark";

class ThemeManager {
  mode = $state<ThemeMode>("system");
  resolved = $state<"light" | "dark">("dark");

  constructor() {
    // Load saved preference
    try {
      const saved = localStorage.getItem("clawsec-theme") as ThemeMode | null;
      if (saved === "light" || saved === "dark" || saved === "system") {
        this.mode = saved;
      }
    } catch { /* localStorage may be unavailable */ }
    this.apply();
  }

  private apply() {
    // Resolve effective theme
    if (this.mode === "system") {
      this.resolved = window.matchMedia("(prefers-color-scheme: dark)").matches
        ? "dark"
        : "light";
    } else {
      this.resolved = this.mode;
    }
    // Set on DOM
    document.documentElement.setAttribute("data-theme", this.resolved);
    // Persist
    try {
      localStorage.setItem("clawsec-theme", this.mode);
    } catch { /* ignore */ }
  }

  setMode(mode: ThemeMode) {
    this.mode = mode;
    this.apply();
  }

  cycle() {
    if (this.mode === "system") {
      this.setMode("light");
    } else if (this.mode === "light") {
      this.setMode("dark");
    } else {
      this.setMode("system");
    }
  }

  /** Label for the current mode — useful for display */
  get label(): string {
    switch (this.mode) {
      case "system": return `System (${this.resolved})`;
      case "light":  return "Light";
      case "dark":   return "Dark";
    }
  }
}

export const theme = new ThemeManager();
