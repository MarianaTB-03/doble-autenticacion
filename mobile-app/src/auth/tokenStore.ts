import * as SecureStore from "expo-secure-store";

const REFRESH_KEY = "refresh_token";

// Solo en memoria RAM (se pierden al cerrar la app)
let accessToken: string | null = null;
let elevatedToken: string | null = null;

export const getAccessToken = () => accessToken;
export const setAccessToken = (t: string | null) => { accessToken = t; };
export const getElevatedToken = () => elevatedToken;
export const setElevatedToken = (t: string | null) => { elevatedToken = t; };

// Persistido en Keychain / Keystore
export const saveRefreshToken = (t: string) => SecureStore.setItemAsync(REFRESH_KEY, t);
export const loadRefreshToken = () => SecureStore.getItemAsync(REFRESH_KEY);

export async function clearSession(): Promise<void> {
  accessToken = null;
  elevatedToken = null;
  await SecureStore.deleteItemAsync(REFRESH_KEY);
}