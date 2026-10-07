import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import * as authApi from "../lib/api/auth";
import { endSession, onSessionChange, refreshSession, startSession } from "../lib/auth/session";
import type { UserProfile } from "../lib/types";

export type AuthState =
  | { status: "loading" }
  | { status: "anonymous" }
  | { status: "authenticated"; user: UserProfile };

export type LoginResult = { kind: "done" } | { kind: "mfa"; challengeToken: string };

interface AuthContextValue {
  state: AuthState;
  login: (email: string, password: string) => Promise<LoginResult>;
  verifyMfa: (challengeToken: string, code: string) => Promise<void>;
  logout: () => Promise<void>;
  reloadUser: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>({ status: "loading" });

  useEffect(() => {
    const unsubscribe = onSessionChange((user) =>
      setState(user ? { status: "authenticated", user } : { status: "anonymous" }),
    );
    // Silent sign-in: the HttpOnly refresh cookie restores the session after a reload.
    refreshSession().catch(() => setState({ status: "anonymous" }));
    return unsubscribe;
  }, []);

  const login = useCallback(async (email: string, password: string): Promise<LoginResult> => {
    const response = await authApi.login(email, password);
    if (response.status === "mfa_required") {
      return { kind: "mfa", challengeToken: response.challenge_token };
    }
    startSession(response);
    return { kind: "done" };
  }, []);

  const verifyMfa = useCallback(async (challengeToken: string, code: string) => {
    startSession(await authApi.verifyMfa(challengeToken, code));
  }, []);

  const logout = useCallback(async () => {
    try {
      await authApi.logout();
    } finally {
      endSession(); // clear local state even if the server call failed
    }
  }, []);

  const reloadUser = useCallback(async () => {
    const user = await authApi.fetchMe();
    setState({ status: "authenticated", user });
  }, []);

  const value = useMemo(
    () => ({ state, login, verifyMfa, logout, reloadUser }),
    [state, login, verifyMfa, logout, reloadUser],
  );
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const value = useContext(AuthContext);
  if (!value) throw new Error("useAuth must be used inside AuthProvider");
  return value;
}

/** The signed-in user. Only call inside a route guarded by RequireAuth. */
export function useCurrentUser(): UserProfile {
  const { state } = useAuth();
  if (state.status !== "authenticated") throw new Error("useCurrentUser outside RequireAuth");
  return state.user;
}
