import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import * as authApi from "../lib/api/auth";
import { endSession, onSessionChange, refreshSession, startSession } from "../lib/auth/session";
import { applyTheme } from "../lib/theme";
import type { Theme, UserProfile } from "../lib/types";

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
  /** Switch the signed-in user's theme now, and save it with their account. */
  setTheme: (theme: Theme) => Promise<void>;
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

  // The page wears the signed-in user's theme; signed out (the sign-in page) it is light.
  const theme = state.status === "authenticated" ? state.user.theme : "light";
  useEffect(() => applyTheme(theme), [theme]);

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

  const setTheme = useCallback(async (next: Theme) => {
    // Switch at once, then save; if saving fails, switch back and let the caller say so.
    const withTheme = (t: Theme) => (s: AuthState): AuthState =>
      s.status === "authenticated" ? { status: "authenticated", user: { ...s.user, theme: t } } : s;
    const previous: Theme = next === "dark" ? "light" : "dark";
    setState(withTheme(next));
    try {
      const user = await authApi.saveTheme(next);
      setState((s) => (s.status === "authenticated" ? { status: "authenticated", user } : s));
    } catch (error) {
      setState(withTheme(previous));
      throw error;
    }
  }, []);

  const value = useMemo(
    () => ({ state, login, verifyMfa, logout, reloadUser, setTheme }),
    [state, login, verifyMfa, logout, reloadUser, setTheme],
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
