import { BrowserRouter, Route, Routes } from "react-router-dom";
import { Layout } from "../components/Layout";
import { AuditLogsPage } from "../features/admin/AuditLogsPage";
import { SettingsPage } from "../features/admin/SettingsPage";
import { ForgotPasswordPage } from "../features/auth/ForgotPasswordPage";
import { LoginPage } from "../features/auth/LoginPage";
import { ResetPasswordPage } from "../features/auth/ResetPasswordPage";
import { SetupPage } from "../features/auth/SetupPage";
import { Dashboard } from "../routes/Dashboard";
import { ModulePage } from "../routes/ModulePage";
import { NotFound } from "../routes/NotFound";
import { AuthProvider } from "./auth-context";
import { CapabilitiesProvider } from "./capabilities-context";
import { MODULES } from "./modules";
import { PublicOnly, RequireAuth } from "./RequireAuth";

/** Modules with a dedicated page; the rest show their capability status until built. */
const PAGES: Record<string, () => React.JSX.Element> = {
  "/settings": SettingsPage,
  "/audit-logs": AuditLogsPage,
};

export function AppRoutes() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="/login" element={<PublicOnly><LoginPage /></PublicOnly>} />
        <Route path="/forgot-password" element={<PublicOnly><ForgotPasswordPage /></PublicOnly>} />
        <Route path="/reset-password" element={<ResetPasswordPage />} />
        <Route path="/setup" element={<RequireAuth allowPending><SetupPage /></RequireAuth>} />
        <Route
          element={
            <RequireAuth>
              <CapabilitiesProvider>
                <Layout />
              </CapabilitiesProvider>
            </RequireAuth>
          }
        >
          <Route index element={<Dashboard />} />
          {MODULES.filter((m) => m.path !== "/").map((m) => {
            const Page = PAGES[m.path];
            return <Route key={m.path} path={m.path} element={Page ? <Page /> : <ModulePage module={m} />} />;
          })}
          <Route path="*" element={<NotFound />} />
        </Route>
      </Routes>
    </AuthProvider>
  );
}

export function App() {
  return (
    <BrowserRouter>
      <AppRoutes />
    </BrowserRouter>
  );
}
