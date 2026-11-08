# Laboratorio de Seguridad Móvil: OAuth 2.0 + PKCE, Authenticator TOTP y Step-Up 2FA

**Curso:** Desarrollo Móvil (React Native) · **Universidad de La Sabana** · Sesión 14
**Estudiante**

App móvil en Expo (React Native + TypeScript estricto) con un backend ligero en FastAPI. Implementa, sin librerías "caja negra":

1. Flujo **OAuth 2.0 con PKCE (RFC 7636)** usando el navegador del sistema (sin WebView) y validación de `state` anti-CSRF.
2. **Almacenamiento seguro**: `access_token` solo en memoria, `refresh_token` en SecureStore (Keychain / Keystore) y **Silent Refresh Queue** para peticiones concurrentes con 401.
3. **Authenticator propio (RFC 6238)**: HMAC-SHA1 + truncamiento dinámico escritos desde cero, funcional en Modo Avión.
4. **Step-Up Authentication** para la bóveda crítica y **caché Anti-Replay** en el backend.

## Estructura del repositorio

```
/mobile-app     App Expo (React Native + TypeScript)
  src/auth      PKCE, OAuth, tokens, cliente HTTP con cola de refresh, MFA
  src/totp      Base32, HMAC-SHA1, TOTP, parser otpauth://, almacén de semilla
  src/screens   Sesión, Authenticator, Bóveda
/backend-auth   Backend FastAPI (main.py, requirements.txt)
README.md
```

## Requisitos

- Node.js 18 o superior y npm
- Python 3.10 o superior
- Expo Go (Android/iOS) en el celular, o un development build
- El PC y el celular en la **misma red Wi-Fi**

## 1. Ejecutar el backend

```powershell
cd backend-auth
python -m venv .venv
.venv\Scripts\Activate.ps1        # Mac/Linux: source .venv/bin/activate
pip install -r requirements.txt
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

Si PowerShell bloquea la activación: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned`.

Comprobar: abrir `http://IP_DEL_PC:8000/docs` en el navegador del PC y del celular. Si el celular no abre la página, permitir el puerto 8000 en el firewall de Windows (PowerShell como administrador):

```powershell
New-NetFirewallRule -DisplayName "Lab 8000" -Direction Inbound -Protocol TCP -LocalPort 8000 -Action Allow -Profile Any
```

### Variables de entorno (opcionales)

| Variable      | Por defecto        | Descripción                                                              |
|---------------|--------------------|--------------------------------------------------------------------------|
| `JWT_SECRET`  | clave de laboratorio | Clave de firma de los JWT (mínimo 32 caracteres). Cambiar fuera del laboratorio. |
| `ACCESS_TTL`  | `300`              | Vida del access token en segundos. Usar `20` para demostrar el refresh.  |

Ejemplo (PowerShell):

```powershell
$env:JWT_SECRET="una-clave-larga-de-al-menos-32-caracteres"
$env:ACCESS_TTL="20"
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

### Datos de prueba

- Usuario: `estudiante` · Contraseña: `1234`
- Semilla TOTP: `JBSWY3DPEHPK3PXP`
- QR de la semilla: `http://IP_DEL_PC:8000/mfa/setup` (abrir en el PC y escanear con la app)

El backend guarda tokens y códigos usados **en memoria**: al reiniciarlo hay que volver a iniciar sesión.

## 2. Ejecutar la app móvil

1. Obtener la IP del PC con `ipconfig` (IPv4 del adaptador Wi-Fi).
2. Editar `mobile-app/src/config.ts` y poner esa IP en `API_URL`:
   ```ts
   export const API_URL = process.env.EXPO_PUBLIC_API_URL ?? "http://192.168.X.X:8000";
   ```
3. Instalar y arrancar:
   ```powershell
   cd mobile-app
   npm install
   npx expo start -c
   ```
4. Escanear el QR de la terminal con Expo Go.

### Redirect del deep link

- **Expo Go:** no registra esquemas propios, por lo que el callback usa `exp://IP:8081/--/callback` (`FORCE_EXPO_GO = true` en `config.ts`).
- **Development build:** poner `FORCE_EXPO_GO = false` para usar el esquema propio `unisabana-auth://callback`, declarado en `app.json`.

## Pruebas de aceptación

| # | Prueba | Cómo verla |
|---|--------|-----------|
| 1 | OAuth + PKCE con navegador del sistema | Pestaña **Sesión → Iniciar sesión**. Se abre el navegador, se ingresa `estudiante` / `1234` y se vuelve a la app. |
| 2 | Paridad con Google Authenticator | Escanear el mismo QR en la app y en Google Authenticator: mismos 6 dígitos. |
| 3 | Cálculo offline | Activar Modo Avión y esperar el cambio de código en la pestaña **Authenticator**. |
| 4 | Step-Up y bóveda | Pestaña **Bóveda → Abrir bóveda** → 403 `mfa_required` → modal 2FA → acceso. |
| 5 | Anti-Replay | Reutilizar el mismo código en la misma ventana: `409 Replay Attack Detected`. |
| + | Silent Refresh Queue | Con `ACCESS_TTL=20`, esperar 25 s y pulsar **Probar 3 peticiones concurrentes**: tres 401, un solo `>>> REFRESH solicitado` en el backend y tres 200. |

## Decisiones de seguridad

- `code_verifier` de 86 caracteres URL-safe y `code_challenge` = SHA-256 en Base64URL sin relleno; el backend verifica `SHA256(code_verifier) == code_challenge` y el `code` es de un solo uso.
- `state` aleatorio por intento; si no coincide, la app aborta el intercambio.
- No hay `client_secret` en la app (cliente público).
- `access_token` (5 min) solo en memoria; `refresh_token` (30 días) en SecureStore.
- La cola de refresh comparte **una sola promesa** entre peticiones concurrentes; si el refresh falla, se limpia el almacenamiento y se vuelve al login.
- TOTP: `T = floor(unix/30)` en 8 bytes Big-Endian, HMAC-SHA1 armado sobre el SHA-1 nativo de `expo-crypto`, truncamiento dinámico y `% 1_000_000`.
- Backend: ventanas C-1, C y C+1, comparación en tiempo constante, caché anti-replay de 90 s, token de step-up de 5 min y token elevado (`mfa_verified: true`) de 10 min.

## Endpoints del backend

| Método | Ruta | Función |
|--------|------|---------|
| GET/POST | `/oauth/authorize` | Login del proveedor y emisión del authorization code |
| POST | `/auth/oauth/token` | Intercambio de `code` + `code_verifier` por tokens |
| POST | `/auth/refresh` | Renovación del access token |
| GET | `/api/ping` | Recurso estándar (prueba de la cola de refresh) |
| GET | `/api/boveda-critica` | Recurso crítico; 403 `mfa_required` sin MFA |
| POST | `/auth/mfa/verify` | Verifica el TOTP y emite el token elevado |
| GET | `/mfa/setup` | Muestra el QR de la semilla de prueba |