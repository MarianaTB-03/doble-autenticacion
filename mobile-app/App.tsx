import { useEffect, useState } from "react";
import { View, Text, Pressable, StyleSheet, StatusBar } from "react-native";
import LoginScreen from "./src/screens/LoginScreen";
import AuthenticatorScreen from "./src/screens/AuthenticatorScreen";
import BovedaScreen from "./src/screens/BovedaScreen";
import { restoreSession, setSessionExpiredHandler } from "./src/auth/httpClient";
import { totp } from "./src/totp/totp";
totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 59000).then(console.log);
type Tab = "login" | "auth" | "vault";

export default function App() {
  const [tab, setTab] = useState<Tab>("login");
  const [loggedIn, setLoggedIn] = useState(false);
  const [booting, setBooting] = useState(true);

  useEffect(() => {
    setSessionExpiredHandler(() => { setLoggedIn(false); setTab("login"); });
    restoreSession().then(setLoggedIn).finally(() => setBooting(false));
  }, []);

  if (booting) return <View style={s.root}><Text>Cargando…</Text></View>;

  return (
    <View style={s.root}>
      <StatusBar barStyle="dark-content" />
      <View style={{ flex: 1 }}>
        {tab === "login" && <LoginScreen loggedIn={loggedIn} onLogin={() => setLoggedIn(true)} onLogout={() => setLoggedIn(false)} />}
        {tab === "auth" && <AuthenticatorScreen />}
        {tab === "vault" && <BovedaScreen loggedIn={loggedIn} />}
      </View>
      <View style={s.tabs}>
        {(["login", "auth", "vault"] as Tab[]).map((t) => (
          <Pressable key={t} style={[s.tab, tab === t && s.active]} onPress={() => setTab(t)}>
            <Text>{t === "login" ? "Sesión" : t === "auth" ? "Authenticator" : "Bóveda"}</Text>
          </Pressable>
        ))}
      </View>
    </View>
  );
}

const s = StyleSheet.create({
  root: { flex: 1, paddingTop: 48, backgroundColor: "white" },
  tabs: { flexDirection: "row", borderTopWidth: 1, borderColor: "#ddd", paddingBottom: 16 },
  tab: { flex: 1, padding: 16, alignItems: "center" },
  active: { backgroundColor: "#e0e7ff" },
});