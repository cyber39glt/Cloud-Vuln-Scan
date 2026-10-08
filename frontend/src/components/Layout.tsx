import { useEffect, useState, type ReactNode } from "react";
import { NavLink, useLocation } from "react-router-dom";
import { useAuth } from "../auth";
import { Brand, SiteFooter, ThemeToggle } from "./brand";
import { AuditIcon, ClientsIcon, DashboardIcon, LogoutIcon, MenuIcon, UsersIcon } from "./icons";

function initials(name: string): string {
  const parts = name.trim().split(/\s+/);
  const first = parts[0]?.[0] ?? "";
  const last = parts.length > 1 ? (parts[parts.length - 1]?.[0] ?? "") : "";
  return (first + last).toUpperCase() || "?";
}

export function Layout({ children }: { children: ReactNode }) {
  const { me, logout } = useAuth();
  const [menuOpen, setMenuOpen] = useState(false);
  const location = useLocation();

  // Close the mobile menu after navigating.
  useEffect(() => setMenuOpen(false), [location.pathname]);

  if (!me) return null;
  const admin = me.role === "admin";
  return (
    <div className={`app ${menuOpen ? "menu-open" : ""}`}>
      <aside className="sidebar" aria-label="Main navigation">
        <Brand name={me.consultancy} product="CloudSecura" />
        <nav className="nav">
          <span className="nav-section">Assess</span>
          <NavLink to="/" end>
            <DashboardIcon />
            Dashboard
          </NavLink>
          <NavLink to="/clients">
            <ClientsIcon />
            Clients
          </NavLink>
          {admin && (
            <>
              <span className="nav-section">Administration</span>
              <NavLink to="/admin/users">
                <UsersIcon />
                Users
              </NavLink>
              <NavLink to="/admin/audit">
                <AuditIcon />
                Audit log
              </NavLink>
            </>
          )}
        </nav>
        <div className="sidebar-foot">
          <NavLink to="/account" className="user-card" title={me.email}>
            <span className="avatar" aria-hidden="true">
              {initials(me.display_name)}
            </span>
            <span className="user-name">
              <strong>{me.display_name}</strong>
              <span className="role">{admin ? "Admin" : "Consultant"}</span>
            </span>
          </NavLink>
          <div className="sidebar-actions">
            <ThemeToggle />
            <button className="btn btn-ghost" onClick={() => void logout()}>
              <LogoutIcon />
              Log out
            </button>
          </div>
        </div>
      </aside>
      <div className="main">
        <div className="mobile-bar">
          <Brand name={me.consultancy} />
          <button className="btn btn-ghost btn-icon" aria-label="Open menu" aria-expanded={menuOpen} onClick={() => setMenuOpen(!menuOpen)}>
            <MenuIcon />
          </button>
        </div>
        <div className="main-inner">
          <main className="content">{children}</main>
        </div>
        <SiteFooter />
      </div>
    </div>
  );
}
