import { useEffect, useState } from "react";
import { ApiError } from "./api/client";

export type ApiState<T> =
  | { state: "loading" }
  | { state: "ready"; data: T }
  | { state: "error"; error: ApiError };

export function useApi<T>(load: (signal: AbortSignal) => Promise<T>): ApiState<T> {
  const [result, setResult] = useState<ApiState<T>>({ state: "loading" });

  useEffect(() => {
    const controller = new AbortController();
    load(controller.signal)
      .then((data) => setResult({ state: "ready", data }))
      .catch((error: unknown) => {
        if (controller.signal.aborted) return;
        setResult({
          state: "error",
          error:
            error instanceof ApiError
              ? error
              : new ApiError(0, "unexpected", "Unexpected client error", null),
        });
      });
    return () => controller.abort();
  }, [load]);

  return result;
}
