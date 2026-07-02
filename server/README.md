# AkkSec verification server (local test)

A tiny Node server that verifies **Play Integrity** tokens (Android) and **App
Attest** attestations/assertions (iOS) for the demo app. Run it on your laptop.

## Endpoints
| Method | Path | Body | Purpose |
|---|---|---|---|
| GET | `/health` | – | liveness |
| GET | `/challenge` | – | one-time nonce (use as App Attest challenge / Play Integrity requestHash) |
| POST | `/verify/play-integrity` | `{ token }` | decode + evaluate a Play Integrity token |
| POST | `/verify/app-attest/attestation` | `{ keyId, attestation, challenge }` | verify + register the device key |
| POST | `/verify/app-attest/assertion` | `{ keyId, assertion, challenge }` | verify a per-request assertion |

## Setup
```bash
cd server
npm install
cp .env.example .env    # then edit .env
npm start
```

### Play Integrity (Android)
1. **Play Console → your app → App integrity → link a Google Cloud project.**
   The project **number** is your `AkkSecConfig.android.playIntegrityCloudProjectNumber`.
2. In that GCP project: **enable the Play Integrity API**, create a **service account**,
   download its JSON key → point `GOOGLE_APPLICATION_CREDENTIALS` at it.
3. Set `ANDROID_PACKAGE_NAME=com.smartx.fluttersecuirtydemo`.

### App Attest (iOS)
1. Download Apple's root CA and save it where `.env` points:
   ```bash
   mkdir -p certs
   curl -o certs/Apple_App_Attestation_Root_CA.pem \
     https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem
   ```
2. Set `IOS_TEAM_ID`, `IOS_BUNDLE_ID`, and `APP_ATTEST_ENV`
   (`development` while testing via Xcode/TestFlight, `production` for App Store).

## Reaching the server from the phone
- **Same Wi‑Fi:** use your laptop's LAN IP, e.g. `http://192.168.1.20:8080`.
- **Anywhere (cellular):** expose it with a tunnel:
  ```bash
  ngrok http 8080          # → https://xxxx.ngrok-free.app
  # or: cloudflared tunnel --url http://localhost:8080
  ```
  Put that URL into the demo's **Backend server URL** field.

> This is a **test** server: in-memory key store, no auth, minimal hardening. Do not
> deploy as-is. The App Attest verifier is a reference implementation — review before
> production use.
