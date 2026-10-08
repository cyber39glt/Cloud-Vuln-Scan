// Light / dark theme. Dark is the default; the choice is remembered per browser.
// Storage can be unavailable (private windows, blocked site data): the theme then
// simply falls back to dark.

import { useCallback, useState } from "react";

export type Theme = "dark" | "light";
const KEY = "cvs-theme";

export function storedTheme(): Theme {
  try {
    return localStorage.getItem(KEY) === "light" ? "light" : "dark";
  } catch {
    return "dark";
  }
}

export function applyTheme(theme: Theme): void {
  document.documentElement.dataset.theme = theme;
}

export function useTheme(): [Theme, () => void] {
  const [theme, setTheme] = useState<Theme>(storedTheme);
  const toggle = useCallback(() => {
    setTheme((current) => {
      const next: Theme = current === "dark" ? "light" : "dark";
      applyTheme(next);
      try {
        localStorage.setItem(KEY, next);
      } catch {
        // Not remembered; still applied for this visit.
      }
      return next;
    });
  }, []);
  return [theme, toggle];
}
