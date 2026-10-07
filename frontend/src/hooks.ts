import { useCallback, useEffect, useState } from "react";
import { api, ApiError } from "./api";

export interface Loaded<T> {
  data: T | undefined;
  error: string | null;
  notFound: boolean;
  loading: boolean;
  reload: () => Promise<void>;
}

/** GET a path and keep the result, with loading and error state. */
export function useApi<T>(path: string | null): Loaded<T> {
  const [data, setData] = useState<T>();
  const [error, setError] = useState<string | null>(null);
  const [notFound, setNotFound] = useState(false);
  const [loading, setLoading] = useState(path !== null);

  const reload = useCallback(async () => {
    if (path === null) return;
    setLoading(true);
    try {
      setData(await api.get<T>(path));
      setError(null);
      setNotFound(false);
    } catch (e) {
      setNotFound(e instanceof ApiError && e.status === 404);
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [path]);

  useEffect(() => {
    void reload();
  }, [reload]);

  return { data, error, notFound, loading, reload };
}

/** Run an action (e.g. a form submit), tracking busy and error state. */
export function useAction() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const run = useCallback(async <T,>(action: () => Promise<T>): Promise<T | undefined> => {
    setBusy(true);
    setError(null);
    try {
      return await action();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      return undefined;
    } finally {
      setBusy(false);
    }
  }, []);
  return { busy, error, setError, run };
}
