import { useEffect, useState } from "react";
import { View, Text, TextInput, Button, StyleSheet, Platform, Alert } from "react-native";
import { CameraView, useCameraPermissions } from "expo-camera";
import { totp } from "../totp/totp";
import { parseOtpauth } from "../totp/otpauth";
import { loadSecret, saveSecret } from "../totp/secretStore";

const BASE32 = /^[A-Z2-7]+=*$/;

export default function AuthenticatorScreen() {
  const [secret, setSecret] = useState("");
  const [draft, setDraft] = useState("");
  const [code, setCode] = useState("------");
  const [remaining, setRemaining] = useState(30);
  const [scanning, setScanning] = useState(false);
  const [permission, requestPermission] = useCameraPermissions();

  useEffect(() => {
    loadSecret().then((s) => { if (s) { setSecret(s); setDraft(s); } });
  }, []);

  useEffect(() => {
    if (!secret) { setCode("------"); return; }
    let lastT = -1;
    let cancelled = false;
    const tick = async () => {
      const now = Date.now();
      const T = Math.floor(now / 30000);
      setRemaining(30 - ((now / 1000) % 30));
      if (T !== lastT) {
        lastT = T;
        try {
          const c = await totp(secret, now);
          if (!cancelled) setCode(c);
        } catch {
          if (!cancelled) setCode("ERROR");
        }
      }
    };
    tick();
    const id = setInterval(tick, 250);
    return () => { cancelled = true; clearInterval(id); };
  }, [secret]);

  const applySecret = async (raw: string) => {
    const clean = raw.toUpperCase().replace(/\s/g, "");
    if (!BASE32.test(clean)) { Alert.alert("Semilla inválida", "Debe ser Base32 (A-Z y 2-7)."); return; }
    await saveSecret(clean);
    setSecret(clean);
    setDraft(clean);
  };

  const onScan = ({ data }: { data: string }) => {
    setScanning(false);
    const parsed = parseOtpauth(data);
    if (!parsed) { Alert.alert("QR no válido", "No es un código otpauth://totp"); return; }
    applySecret(parsed.secret);
  };

  const startScan = async () => {
    if (!permission?.granted) {
      const p = await requestPermission();
      if (!p.granted) return;
    }
    setScanning(true);
  };

  if (scanning) {
    return (
      <View style={{ flex: 1 }}>
        <CameraView style={{ flex: 1 }} barcodeScannerSettings={{ barcodeTypes: ["qr"] }} onBarcodeScanned={onScan} />
        <Button title="Cancelar" onPress={() => setScanning(false)} />
      </View>
    );
  }

  return (
    <View style={s.c}>
      <Text style={[s.code, remaining <= 5 && { color: "#dc2626" }]}>{code.slice(0, 3)} {code.slice(3)}</Text>
      <View style={s.bar}>
        <View style={[s.fill, { width: `${(remaining / 30) * 100}%` }, remaining <= 5 && { backgroundColor: "#dc2626" }]} />
      </View>
      <Text>{Math.ceil(remaining)} s</Text>
      <TextInput style={s.input} value={draft} onChangeText={setDraft} autoCapitalize="characters"
        autoCorrect={false} placeholder="Pega la semilla Base32" />
      <Button title="Guardar semilla" onPress={() => applySecret(draft)} />
      <Button title="Escanear QR" onPress={startScan} />
    </View>
  );
}

const s = StyleSheet.create({
  c: { flex: 1, alignItems: "center", justifyContent: "center", padding: 24, gap: 14 },
  code: { fontSize: 56, letterSpacing: 6, fontFamily: Platform.OS === "ios" ? "Courier" : "monospace" },
  bar: { width: "100%", height: 10, backgroundColor: "#ddd", borderRadius: 5, overflow: "hidden" },
  fill: { height: 10, backgroundColor: "#2563eb" },
  input: { width: "100%", borderWidth: 1, borderColor: "#aaa", borderRadius: 8, padding: 12 },
});