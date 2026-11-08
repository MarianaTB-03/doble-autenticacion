import * as Crypto from "expo-crypto";

const sha1 = async (d: Uint8Array): Promise<Uint8Array> =>
  new Uint8Array(
    await Crypto.digest(Crypto.CryptoDigestAlgorithm.SHA1, new Uint8Array(d))
  );

// HMAC-SHA1 construido a mano sobre SHA-1 (expo-crypto no ofrece HMAC)
async function hmacSha1(key: Uint8Array, msg: Uint8Array): Promise<Uint8Array> {
  let k = key;
  if (k.length > 64) k = await sha1(k);
  const block = new Uint8Array(64);
  block.set(k);
  const ipad = block.map((b) => b ^ 0x36);
  const opad = block.map((b) => b ^ 0x5c);
  const inner = await sha1(new Uint8Array([...ipad, ...msg]));
  return sha1(new Uint8Array([...opad, ...inner]));
}

export function base32Decode(input: string): Uint8Array {
  const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = input.toUpperCase().replace(/\s/g, "").replace(/=+$/, "");
  let bits = 0;
  let val = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const i = A.indexOf(ch);
    if (i < 0) throw new Error("Semilla Base32 inválida");
    val = (val << 5) | i;
    bits += 5;
    if (bits >= 8) {
      out.push((val >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

// RFC 6238: T = floor(unix / 30), HMAC-SHA1 y truncamiento dinámico a 6 dígitos
export async function totp(secretB32: string, nowMs: number = Date.now()): Promise<string> {
  const T = Math.floor(nowMs / 1000 / 30);
  const msg = new Uint8Array(8);
  new DataView(msg.buffer).setUint32(4, T); // entero de 64 bits Big-Endian
  const h = await hmacSha1(base32Decode(secretB32), msg);
  const o = h[19] & 0x0f;
  const bin = ((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return String(bin % 1_000_000).padStart(6, "0");
}