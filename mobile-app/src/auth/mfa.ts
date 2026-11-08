import { API_URL } from "../config";

export async function verifyMfa(stepUpToken: string, code: string) {
  const r = await fetch(`${API_URL}/auth/mfa/verify`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ step_up_token: stepUpToken, code }),
  });
  const body = await r.json().catch(() => ({}));
  return { status: r.status, elevatedToken: body.elevated_token as string | undefined };
}