import { useTheme } from "../theme";
import { MoonIcon, SunIcon, XLogo } from "./icons";

export const X_HANDLE = "cyber39glt";
export const X_URL = `https://x.com/${X_HANDLE}`;

/** The shield logo plus the product name. */
export function Brand({ name = "CloudSecura", product, large = false }: { name?: string; product?: string; large?: boolean }) {
  return (
    <div className={`brand ${large ? "brand-large" : ""}`}>
      <svg className="brand-mark" viewBox="0 0 40 40" aria-hidden="true">
        <defs>
          <linearGradient id="brand-g" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0" stopColor="#2dd4bf" />
            <stop offset="1" stopColor="#3e8ef0" />
          </linearGradient>
        </defs>
        <rect width="40" height="40" rx="10" fill="url(#brand-g)" />
        <path d="M20 8.5 11 12v7c0 5.6 3.8 10 9 11.5 5.2-1.5 9-5.9 9-11.5v-7z" fill="#04201c" opacity="0.88" />
        <path d="m15.8 19.8 3 3 5.6-6" fill="none" stroke="#5eead4" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
      <span className="brand-text">
        <span className="brand-name">{name}</span>
        {product && <span className="brand-product">{product}</span>}
      </span>
    </div>
  );
}

export function ThemeToggle({ small = false }: { small?: boolean }) {
  const [theme, toggle] = useTheme();
  const next = theme === "dark" ? "light" : "dark";
  return (
    <button
      type="button"
      className={`btn btn-ghost ${small ? "btn-icon" : ""}`}
      onClick={toggle}
      aria-label={`Switch to ${next} theme`}
      title={`Switch to ${next} theme`}
    >
      {theme === "dark" ? <SunIcon /> : <MoonIcon />}
      {!small && <span>{theme === "dark" ? "Light" : "Dark"}</span>}
    </button>
  );
}

/** Link to the author's X profile. */
export function Handle() {
  return (
    <a className="handle" href={X_URL} target="_blank" rel="noopener noreferrer">
      <XLogo />@{X_HANDLE}
    </a>
  );
}

export function SiteFooter() {
  return (
    <footer className="footer">
      <span>Read-only cloud security assessments. This platform never changes client environments.</span>
      <span>
        Built by <Handle />
      </span>
    </footer>
  );
}
