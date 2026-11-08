export function parseOtpauth(uri: string): { secret: string; issuer?: string } | null {
  if (!uri.startsWith("otpauth://totp/")) return null;
  const query = uri.split("?")[1];
  if (!query) return null;
  const params: Record<string, string> = {};
  for (const pair of query.split("&")) {
    const [k, v = ""] = pair.split("=");
    params[decodeURIComponent(k)] = decodeURIComponent(v);
  }
  if (!params.secret) return null;
  return { secret: params.secret, issuer: params.issuer };
}