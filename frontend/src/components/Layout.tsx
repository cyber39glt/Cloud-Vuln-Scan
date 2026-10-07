import type { ReactNode } from "react";
import { NavLink } from "react-router-dom";
import { useAuth } from "../auth";

export function Layout({ children }: { children: ReactNode }) {
  const { me, logout } = useAuth();
  if (!me) return null;
  const admin = me.role === "admin";
  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <img src="/favicon.svg" alt="" width={24} height={24} />
          <span>{me.consultancy}</span>
          <span className="brand-product">Cloud Vuln Scan</span>
        </div>
        <nav className="nav">
          <NavLink to="/" end>
            Overview
          </NavLink>
          <NavLink to="/clients">Clients</NavLink>
          {admin && <NavLink to="/admin/users">Users</NavLink>}
          {admin && <NavLink to="/admin/audit">Audit log</NavLink>}
        </nav>
        <div className="user">
          <NavLink to="/account" className="user-name" title={me.email}>
            {me.display_name}
            <span className="role">{admin ? "Admin" : "Consultant"}</span>
          </NavLink>
          <button className="btn btn-small" onClick={() => void logout()}>
            Log out
          </button>
        </div>
      </header>
      <main className="content">{children}</main>
      <footer className="footer muted">
        Read-only assessments: this platform never changes client environments.
      </footer>
    </div>
  );
}
