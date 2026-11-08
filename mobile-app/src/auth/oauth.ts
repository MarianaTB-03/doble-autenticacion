import * as WebBrowser from "expo-web-browser";
import * as Linking from "expo-linking";
import { API_URL, FORCE_EXPO_GO } from "../config";
import { createPkcePair, randomState } from "./pkce";
import { saveRefreshToken, setAccessToken } from "./tokenStore";

function getRedirectUri(): string {
  if (FORCE_EXPO_GO) {
    // Expo Go solo entiende exp://. Se usa la IP del PC y el puerto de Metro.
    const host = new URL(API_URL).hostname;
    return `exp://${host}:8081/--/callback`;
  }
  return Linking.createURL("callback"); // development build: unisabana-auth://callback
}

export async function loginWithOAuth(): Promise<void> {
  const { verifier, challenge } = await createPkcePair();
  const state = randomState();
  const redirectUri = getRedirectUri();

  const pairs: [string, string][] = [
    ["client_id", "mobile-app"],
    ["redirect_uri", redirectUri],
    ["state", state],
    ["code_challenge", challenge],
    ["code_challenge_method", "S256"],
  ];
  const query = pairs.map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join("&");

  // Navegador seguro del sistema (NO WebView)
  const result = await WebBrowser.openAuthSessionAsync(
    `${API_URL}/oauth/authorize?${query}`,
    redirectUri
  );
  if (result.type !== "success") throw new Error("Inicio de sesión cancelado");

  const { queryParams } = Linking.parse(result.url);
  if (queryParams?.state !== state) throw new Error("State inválido: posible ataque CSRF");

  const code = queryParams?.code;
  if (typeof code !== "string") throw new Error("No llegó el authorization code");

  const r = await fetch(`${API_URL}/auth/oauth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ code, code_verifier: verifier }),
  });
  if (!r.ok) throw new Error("Falló el intercambio del code");
  const data = await r.json();

  setAccessToken(data.access_token);
  await saveRefreshToken(data.refresh_token);
}