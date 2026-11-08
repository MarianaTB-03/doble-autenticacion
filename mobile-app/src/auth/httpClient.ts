import { API_URL } from "../config";
import {
  clearSession, getAccessToken, getElevatedToken, loadRefreshToken,
  setAccessToken, setElevatedToken,
} from "./tokenStore";

let refreshPromise: Promise<string> | null = null;
let onSessionExpired: () => void = () => {};
export const setSessionExpiredHandler = (fn: () => void) => { onSessionExpired = fn; };

async function doRefresh(): Promise<string> {
  const refresh = await loadRefreshToken();
  if (!refresh) throw new Error("no_refresh");
  const r = await fetch(`${API_URL}/auth/refresh`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ refresh_token: refresh }),
  });
  if (!r.ok) throw new Error("refresh_rejected");
  const data = await r.json();
  setAccessToken(data.access_token);
  return data.access_token as string;
}

// Cola silenciosa: todas las peticiones concurrentes comparten UNA sola promesa de refresh
function refreshOnce(): Promise<string> {
  if (!refreshPromise) {
    refreshPromise = doRefresh().finally(() => { refreshPromise = null; });
  }
  return refreshPromise;
}

export async function restoreSession(): Promise<boolean> {
  try {
    await refreshOnce();
    return true;
  } catch (e) {
    if (e instanceof Error && e.message === "refresh_rejected") await clearSession();
    return false;
  }
}

type Opts = { elevated?: boolean };

export async function apiFetch(
  path: string,
  init: RequestInit = {},
  opts: Opts = {},
  retried = false
): Promise<Response> {
  const accessUsed = getAccessToken();
  const token = opts.elevated ? getElevatedToken() ?? accessUsed : accessUsed;

  const res = await fetch(`${API_URL}${path}`, {
    ...init,
    headers: { ...(init.headers as Record<string, string>), Authorization: `Bearer ${token ?? ""}` },
  });

  if (res.status === 401 && !retried) {
    if (opts.elevated) setElevatedToken(null);

    // Otra petición ya renovó el token mientras esta estaba en vuelo: reintentar sin renovar de nuevo
    if (getAccessToken() !== accessUsed) {
      return apiFetch(path, init, opts, true);
    }

    try {
      await refreshOnce();
    } catch (e) {
      const rejected = e instanceof Error && (e.message === "refresh_rejected" || e.message === "no_refresh");
      if (rejected) {
        await clearSession();
        onSessionExpired(); // vuelve a la pantalla de login
      }
      throw e;
    }
    return apiFetch(path, init, opts, true);
  }
  return res;
}