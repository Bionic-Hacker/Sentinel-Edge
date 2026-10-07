import type { AuthenticatedResponse, MfaRequiredResponse } from "../types";
import { apiRequest } from "./client";
import {
  isAuthenticated,
  isEnrollmentStart,
  isLoginResponse,
  isRecoveryCodes,
  isUserProfile,
} from "./validators";

const anon = { authenticated: false } as const;

export const login = (email: string, password: string) =>
  apiRequest<AuthenticatedResponse | MfaRequiredResponse>("/api/v1/auth/login", isLoginResponse, {
    ...anon,
    method: "POST",
    body: { email, password },
  });

export const verifyMfa = (challengeToken: string, code: string) =>
  apiRequest("/api/v1/auth/mfa/verify", isAuthenticated, {
    ...anon,
    method: "POST",
    body: { challenge_token: challengeToken, code },
  });

export const logout = () => apiRequest("/api/v1/auth/logout", null, { method: "POST" });

export const fetchMe = () => apiRequest("/api/v1/auth/me", isUserProfile);

export const changePassword = (currentPassword: string, newPassword: string) =>
  apiRequest("/api/v1/auth/password/change", null, {
    method: "POST",
    body: { current_password: currentPassword, new_password: newPassword },
  });

export const startMfaEnrollment = () =>
  apiRequest("/api/v1/auth/mfa/enroll", isEnrollmentStart, { method: "POST" });

export const confirmMfaEnrollment = (code: string) =>
  apiRequest("/api/v1/auth/mfa/enroll/confirm", isRecoveryCodes, {
    method: "POST",
    body: { code },
  });

export const requestPasswordReset = (email: string) =>
  apiRequest("/api/v1/auth/password/forgot", null, { ...anon, method: "POST", body: { email } });

export const resetPassword = (token: string, newPassword: string) =>
  apiRequest("/api/v1/auth/password/reset", null, {
    ...anon,
    method: "POST",
    body: { token, new_password: newPassword },
  });
