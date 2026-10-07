import { BrowserRouter, Route, Routes } from "react-router-dom";
import { Layout } from "../components/Layout";
import { Dashboard } from "../routes/Dashboard";
import { ModulePage } from "../routes/ModulePage";
import { NotFound } from "../routes/NotFound";
import { CapabilitiesProvider } from "./capabilities-context";
import { MODULES } from "./modules";

export function AppRoutes() {
  return (
    <CapabilitiesProvider>
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<Dashboard />} />
          {MODULES.filter((m) => m.path !== "/").map((m) => (
            <Route key={m.path} path={m.path} element={<ModulePage module={m} />} />
          ))}
          <Route path="*" element={<NotFound />} />
        </Route>
      </Routes>
    </CapabilitiesProvider>
  );
}

export function App() {
  return (
    <BrowserRouter>
      <AppRoutes />
    </BrowserRouter>
  );
}
