import { useState } from "react";
import { View, Text, Button, StyleSheet } from "react-native";
import { loginWithOAuth } from "../auth/oauth";
import { apiFetch } from "../auth/httpClient";
import { clearSession } from "../auth/tokenStore";

type Props = { loggedIn: boolean; onLogin: () => void; onLogout: () => void };

export default function LoginScreen({ loggedIn, onLogin, onLogout }: Props) {
  const [msg, setMsg] = useState("");

  const login = async () => {
    try {
      await loginWithOAuth();
      onLogin();
      setMsg("Sesión iniciada. Refresh token guardado en SecureStore.");
    } catch (e) {
      setMsg(e instanceof Error ? e.message : "Error");
    }
  };

  const concurrent = async () => {
    try {
      const rs = await Promise.all([1, 2, 3].map(() => apiFetch("/api/ping")));
      setMsg(`3 peticiones concurrentes -> ${rs.map((r) => r.status).join(", ")}`);
    } catch (e) {
      setMsg(e instanceof Error ? e.message : "Error");
    }
  };

  const logout = async () => { await clearSession(); onLogout(); setMsg("Sesión cerrada"); };

  return (
    <View style={s.c}>
      <Text style={s.title}>{loggedIn ? "Sesión activa" : "Bienvenido"}</Text>
      {!loggedIn && <Button title="Iniciar sesión" onPress={login} />}
      {loggedIn && <Button title="Probar 3 peticiones concurrentes" onPress={concurrent} />}
      {loggedIn && <Button title="Cerrar sesión" color="#b91c1c" onPress={logout} />}
      <Text style={s.msg}>{msg}</Text>
    </View>
  );
}

const s = StyleSheet.create({
  c: { flex: 1, justifyContent: "center", padding: 24, gap: 14 },
  title: { fontSize: 24, fontWeight: "600", textAlign: "center" },
  msg: { textAlign: "center", color: "#444" },
});