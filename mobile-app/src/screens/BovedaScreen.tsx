import { useState } from "react";
import { View, Text, Button, Modal, TextInput, StyleSheet } from "react-native";
import { apiFetch } from "../auth/httpClient";
import { verifyMfa } from "../auth/mfa";
import { setElevatedToken } from "../auth/tokenStore";
import { loadSecret } from "../totp/secretStore";
import { totp } from "../totp/totp";

export default function BovedaScreen({ loggedIn }: { loggedIn: boolean }) {
  const [data, setData] = useState("");
  const [msg, setMsg] = useState("");
  const [modal, setModal] = useState(false);
  const [stepUp, setStepUp] = useState("");
  const [code, setCode] = useState("");

  const load = async () => {
    setMsg("");
    try {
      const r = await apiFetch("/api/boveda-critica", {}, { elevated: true });
      if (r.status === 403) {
        const d = await r.json();
        if (d.error === "mfa_required") { setStepUp(d.step_up_token); setCode(""); setModal(true); return; }
      }
      if (r.ok) { const d = await r.json(); setData(d.secreto); }
      else setMsg(`Error ${r.status}`);
    } catch (e) {
      setMsg(e instanceof Error ? e.message : "Error de red");
    }
  };

  const submit = async () => {
    const res = await verifyMfa(stepUp, code);
    if (res.status === 409) { setMsg("Replay Attack Detected: ese código ya fue usado"); setModal(false); return; }
    if (res.status === 401) { setMsg("Código incorrecto o step-up vencido"); setModal(false); return; }
    if (res.elevatedToken) {
      setElevatedToken(res.elevatedToken);
      setModal(false);
      load();
    }
  };

  const autofill = async () => {
    const secret = await loadSecret();
    if (secret) setCode(await totp(secret));
  };

  if (!loggedIn) return <View style={s.c}><Text>Inicia sesión primero.</Text></View>;

  return (
    <View style={s.c}>
      <Text style={s.title}>Bóveda Crítica</Text>
      <Button title="Abrir bóveda" onPress={load} />
      {data ? <Text style={s.ok}>{data}</Text> : null}
      {msg ? <Text style={s.err}>{msg}</Text> : null}

      <Modal visible={modal} transparent animationType="slide" onRequestClose={() => setModal(false)}>
        <View style={s.backdrop}>
          <View style={s.card}>
            <Text style={s.title}>Verificación en dos pasos</Text>
            <TextInput style={s.input} value={code} onChangeText={setCode} keyboardType="number-pad"
              maxLength={6} placeholder="000000" />
            <Button title="Verificar" onPress={submit} />
            <Button title="Usar código de mi Authenticator" onPress={autofill} />
            <Button title="Cancelar" color="#777" onPress={() => setModal(false)} />
          </View>
        </View>
      </Modal>
    </View>
  );
}

const s = StyleSheet.create({
  c: { flex: 1, justifyContent: "center", padding: 24, gap: 14 },
  title: { fontSize: 22, fontWeight: "600", textAlign: "center" },
  ok: { color: "#15803d", textAlign: "center", fontSize: 16 },
  err: { color: "#b91c1c", textAlign: "center" },
  backdrop: { flex: 1, justifyContent: "center", backgroundColor: "#0008", padding: 24 },
  card: { backgroundColor: "white", borderRadius: 12, padding: 20, gap: 12 },
  input: { borderWidth: 1, borderColor: "#aaa", borderRadius: 8, padding: 12, fontSize: 28, textAlign: "center", letterSpacing: 8 },
});