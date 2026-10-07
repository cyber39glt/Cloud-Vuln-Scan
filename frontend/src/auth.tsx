import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { api, ApiError, onSessionEnded } from "./api";
import type { Me } from "./types";

interface AuthState {
  /** undefined while loading; null when not logged in. */
  me: Me | null | undefined;
  refresh: () => Promise<void>;
  logout: () => Promise<void>;
  /** Set when the session ended on its own (timeout), to explain the login page. */
  sessionExpired: boolean;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [me, setMe] = useState<Me | null | undefined>(undefined);
  const [sessionExpired, setSessionExpired] = useState(false);

  const refresh = useCallback(async () => {
    try {
      setMe(await api.get<Me>("/auth/me"));
      setSessionExpired(false);
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) setMe(null);
      else throw error;
    }
  }, []);

  const logout = useCallback(async () => {
    try {
      await api.post("/auth/logout");
    } finally {
      setMe(null);
    }
  }, []);

  useEffect(() => {
    void refresh();
    return onSessionEnded(() => {
      setSessionExpired(true);
      setMe(null);
    });
  }, [refresh]);

  return (
    <AuthContext.Provider value={{ me, refresh, logout, sessionExpired }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthState {
  const state = useContext(AuthContext);
  if (!state) throw new Error("useAuth must be used inside AuthProvider");
  return state;
}
