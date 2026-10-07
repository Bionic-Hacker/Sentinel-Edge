import { createContext, useContext, type ReactNode } from "react";
import { getCapabilities } from "../lib/api/platform";
import type { Capability } from "../lib/types";
import { useApi, type ApiState } from "../lib/useApi";

const CapabilitiesContext = createContext<ApiState<Capability[]>>({ state: "loading" });

export function CapabilitiesProvider({ children }: { children: ReactNode }) {
  const state = useApi(getCapabilities);
  return <CapabilitiesContext.Provider value={state}>{children}</CapabilitiesContext.Provider>;
}

export const useCapabilities = () => useContext(CapabilitiesContext);
