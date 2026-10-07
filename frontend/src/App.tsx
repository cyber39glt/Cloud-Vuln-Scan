import { Navigate, Route, Routes } from "react-router-dom";
import { useAuth } from "./auth";
import { Layout } from "./components/Layout";
import { Loading } from "./components/ui";
import { AccountPage } from "./pages/Account";
import { AssessmentPage } from "./pages/Assessment";
import { AuditLogPage } from "./pages/AuditLog";
import { ForcedPasswordChangePage } from "./pages/ChangePassword";
import { ClientPage } from "./pages/Client";
import { ClientsPage } from "./pages/Clients";
import { LoginPage } from "./pages/Login";
import { OverviewPage } from "./pages/Overview";
import { ReportPage } from "./pages/Report";
import { UsersPage } from "./pages/Users";

export function App() {
  const { me } = useAuth();

  if (me === undefined) {
    return (
      <div className="auth-shell">
        <Loading />
      </div>
    );
  }
  if (me === null) return <LoginPage />;
  if (me.must_change_password) return <ForcedPasswordChangePage />;

  const admin = me.role === "admin";
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<OverviewPage />} />
        <Route path="/clients" element={<ClientsPage />} />
        <Route path="/clients/:clientId" element={<ClientPage />} />
        <Route path="/clients/:clientId/assessments/:assessmentId" element={<AssessmentPage />} />
        <Route path="/clients/:clientId/scans/:scanId" element={<ReportPage />} />
        <Route path="/account" element={<AccountPage />} />
        {admin && <Route path="/admin/users" element={<UsersPage />} />}
        {admin && <Route path="/admin/audit" element={<AuditLogPage />} />}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Layout>
  );
}
