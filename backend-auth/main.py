import base64
import hashlib
import hmac
import html
import json
import os
import secrets
import struct
import time
from typing import Optional
from urllib.parse import urlencode

import jwt
from fastapi import FastAPI, Form, Header, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

app = FastAPI(title="Backend Auth Lab")

JWT_SECRET = os.getenv("JWT_SECRET", "clave-de-laboratorio-de-al-menos-32-caracteres-ok")
ALGO = "HS256"
ACCESS_TTL = int(os.getenv("ACCESS_TTL", "300"))  # 5 min (pon 20 para probar el refresh)
REFRESH_TTL = 30 * 24 * 3600                       # 30 días
STEP_UP_TTL = 300
ELEVATED_TTL = 600                                 # 10 min
CODE_TTL = 120
REPLAY_TTL = 90

USERS = {
    "estudiante": {"password": "1234", "totp_secret": "JBSWY3DPEHPK3PXP"},
}
ALLOWED_REDIRECTS = ("unisabana-auth://", "exp://", "exps://")

auth_codes: dict[str, dict] = {}
refresh_tokens: dict[str, dict] = {}
used_totp: dict[tuple[str, str], float] = {}


# ---------- utilidades ----------
def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def make_jwt(sub: str, token_type: str, ttl: int, mfa: bool = False) -> str:
    now = int(time.time())
    payload = {"sub": sub, "type": token_type, "mfa_verified": mfa, "iat": now, "exp": now + ttl}
    return jwt.encode(payload, JWT_SECRET, algorithm=ALGO)


def decode_jwt(token: str, expected_type: str) -> dict:
    try:
        claims = jwt.decode(token, JWT_SECRET, algorithms=[ALGO])
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Token inválido o expirado")
    if claims.get("type") != expected_type:
        raise HTTPException(status_code=401, detail="Tipo de token incorrecto")
    return claims


def bearer_claims(authorization: Optional[str]) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Falta el token")
    return decode_jwt(authorization[7:], "access")


# ---------- TOTP (RFC 6238) ----------
def totp(secret_b32: str, counter: int) -> str:
    key = base64.b32decode(secret_b32.upper() + "=" * (-len(secret_b32) % 8))
    h = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    o = h[19] & 0x0F
    n = struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF
    return f"{n % 1_000_000:06d}"


def verify_totp(user: str, secret: str, code: str) -> str:
    now = time.time()
    for k in [k for k, exp in used_totp.items() if exp < now]:
        del used_totp[k]
    c = int(now // 30)
    valid = any(hmac.compare_digest(totp(secret, c + d), code) for d in (-1, 0, 1))
    if not valid:
        return "invalid"
    if (user, code) in used_totp:
        return "replay"
    used_totp[(user, code)] = now + REPLAY_TTL
    return "ok"


# ---------- OAuth 2.0 + PKCE ----------
def render_login(params: dict, error: str = "") -> str:
    hidden = "".join(
        f'<input type="hidden" name="{k}" value="{html.escape(v)}">' for k, v in params.items()
    )
    return f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Login</title>
<style>body{{font-family:sans-serif;max-width:360px;margin:40px auto;padding:0 16px}}
input,button{{width:100%;padding:12px;margin:8px 0;font-size:16px;box-sizing:border-box}}</style></head>
<body><h2>UniSabana Login</h2>{error}
<form method="post" action="/oauth/authorize">{hidden}
<input name="username" placeholder="Usuario" autocapitalize="none" autocorrect="off" spellcheck="false" autocomplete="username">
<input name="password" type="password" placeholder="Contraseña" autocapitalize="none" autocorrect="off" spellcheck="false" autocomplete="current-password">
<button type="submit">Entrar</button></form></body></html>"""


def check_params(redirect_uri: str, method: str) -> None:
    if method != "S256":
        raise HTTPException(400, "Solo se soporta code_challenge_method=S256")
    if not redirect_uri.startswith(ALLOWED_REDIRECTS):
        raise HTTPException(400, "redirect_uri no permitido")


@app.get("/oauth/authorize", response_class=HTMLResponse)
def authorize_page(client_id: str, redirect_uri: str, state: str,
                   code_challenge: str, code_challenge_method: str = "S256"):
    check_params(redirect_uri, code_challenge_method)
    return render_login({
        "client_id": client_id, "redirect_uri": redirect_uri, "state": state,
        "code_challenge": code_challenge, "code_challenge_method": code_challenge_method,
    })


@app.post("/oauth/authorize")
def authorize_submit(client_id: str = Form(...), redirect_uri: str = Form(...),
                     state: str = Form(...), code_challenge: str = Form(...),
                     code_challenge_method: str = Form("S256"),
                     username: str = Form(...), password: str = Form(...)):
    check_params(redirect_uri, code_challenge_method)
    username = username.strip().lower()
    password = password.strip()
    params = {"client_id": client_id, "redirect_uri": redirect_uri, "state": state,
              "code_challenge": code_challenge, "code_challenge_method": code_challenge_method}
    user = USERS.get(username)
    if not user or not hmac.compare_digest(user["password"].encode(), password.encode()):
        return HTMLResponse(render_login(params, "<p style='color:red'>Credenciales incorrectas</p>"),
                            status_code=401)

    code = secrets.token_urlsafe(32)
    auth_codes[code] = {"user": username, "challenge": code_challenge,
                        "exp": time.time() + CODE_TTL}
    sep = "&" if "?" in redirect_uri else "?"
    target = f"{redirect_uri}{sep}{urlencode({'code': code, 'state': state})}"
    scheme, rest = target.split("://", 1)
    intent = f"intent://{rest}#Intent;scheme={scheme};package=host.exp.exponent;end"
    return HTMLResponse(f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Volver a la app</title>
<style>body{{font-family:sans-serif;text-align:center;margin-top:60px}}
a{{display:inline-block;padding:14px 28px;background:#2563eb;color:#fff;border-radius:8px;
text-decoration:none;font-size:18px}}</style></head>
<body><h2>Login correcto</h2>
<p>Si no vuelves solo a la app, toca el botón:</p>
<a href="{html.escape(target)}">Volver a la app</a>
<p><a href="{html.escape(intent)}">Abrir en Expo Go (Android)</a></p>
<script>setTimeout(function(){{ window.location.href = {json.dumps(target)}; }}, 300);</script>
</body></html>""")


class TokenRequest(BaseModel):
    code: str
    code_verifier: str


@app.post("/auth/oauth/token")
def token(body: TokenRequest):
    data = auth_codes.pop(body.code, None)  # el code es de un solo uso
    if not data or data["exp"] < time.time():
        raise HTTPException(400, "invalid_grant")
    challenge = b64url(hashlib.sha256(body.code_verifier.encode()).digest())
    if not hmac.compare_digest(challenge, data["challenge"]):
        raise HTTPException(400, "PKCE inválido: code_verifier no coincide")
    user = data["user"]
    refresh_token = secrets.token_urlsafe(48)
    refresh_tokens[refresh_token] = {"user": user, "exp": time.time() + REFRESH_TTL}
    return {"access_token": make_jwt(user, "access", ACCESS_TTL),
            "refresh_token": refresh_token, "expires_in": ACCESS_TTL, "token_type": "Bearer"}


class RefreshRequest(BaseModel):
    refresh_token: str


@app.post("/auth/refresh")
def refresh(body: RefreshRequest):
    print(">>> REFRESH solicitado")  # debe aparecer UNA sola vez por tanda de 401
    data = refresh_tokens.get(body.refresh_token)
    if not data or data["exp"] < time.time():
        raise HTTPException(401, "Refresh token vencido o revocado")
    return {"access_token": make_jwt(data["user"], "access", ACCESS_TTL), "expires_in": ACCESS_TTL}


# ---------- Step-up ----------
@app.get("/api/ping")
def ping(authorization: Optional[str] = Header(None)):
    bearer_claims(authorization)
    return {"ok": True}


@app.get("/api/boveda-critica")
def boveda(authorization: Optional[str] = Header(None)):
    claims = bearer_claims(authorization)
    if not claims.get("mfa_verified"):
        return JSONResponse(status_code=403, content={
            "error": "mfa_required",
            "step_up_token": make_jwt(claims["sub"], "step_up", STEP_UP_TTL),
        })
    return {"usuario": claims["sub"], "secreto": "Bóveda abierta: datos ultra confidenciales"}


class VerifyRequest(BaseModel):
    step_up_token: str
    code: str


@app.post("/auth/mfa/verify")
def mfa_verify(body: VerifyRequest):
    claims = decode_jwt(body.step_up_token, "step_up")
    user = claims["sub"]
    result = verify_totp(user, USERS[user]["totp_secret"], body.code.strip())
    if result == "invalid":
        raise HTTPException(401, "Código TOTP incorrecto")
    if result == "replay":
        raise HTTPException(409, "Replay Attack Detected")
    return {"elevated_token": make_jwt(user, "access", ELEVATED_TTL, mfa=True)}


# ---------- QR para configurar la semilla ----------
@app.get("/mfa/setup", response_class=HTMLResponse)
def mfa_setup():
    secret = USERS["estudiante"]["totp_secret"]
    uri = f"otpauth://totp/UniSabana:estudiante@unisabana.edu.co?secret={secret}&issuer=UniSabana"
    return f"""<html><body style="font-family:sans-serif;text-align:center">
<h3>Escanea con tu app y con Google Authenticator</h3><div id="qr" style="display:inline-block"></div>
<p>{uri}</p>
<script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
<script>new QRCode(document.getElementById('qr'), "{uri}");</script></body></html>"""