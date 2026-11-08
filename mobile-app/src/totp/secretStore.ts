import * as SecureStore from "expo-secure-store";

const KEY = "totp_secret";
export const saveSecret = (s: string) => SecureStore.setItemAsync(KEY, s);
export const loadSecret = () => SecureStore.getItemAsync(KEY);