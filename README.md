# AkkSec Flutter Demo

A runnable example app for the **`akk_flutter_sec_sdk`** mobile security plugin. It
shows every feature the SDK provides and how to wire it into a real app. Use it as a
copy‑paste reference.

- Plugin repo: `git@github.com:akkodis-dmcc/Akk-Flutter-Security-SDK.git`
- All the integration code lives in **[`lib/main.dart`](lib/main.dart)**.

---

## What this demo shows
| Feature | API used | Where in the UI |
|---|---|---|
| Posture checks (root/jailbreak, tamper, hook, debugger, emulator, sideload, dev‑mode) | `AkkSec.runAppLaunchChecks()` / `evaluateAppLaunch()` | Risk score + check tiles |
| Policy enforcement | `RiskPolicy.standard` | "Allowed / Blocked" banner |
| Continuous monitoring | `AkkSec.securityEvents()` | "Live monitoring" toggle |
| Certificate‑pinned requests | `AkkSec.secureGet/securePost(...)` | "Pinned request" card |
| Screen‑capture protection | `AkkSec.setScreenProtectionEnabled()` | enabled on launch |
| App attestation (Play Integrity / App Attest) | `AkkSec.prepareAppIntegrityProvider()` + `requestAppIntegrityAssertion()` | "Integrity" card |
| Secure storage (Keystore / Keychain) | `AkkSec.secureWrite/secureRead(...)` | "Secure storage" card |
| Biometric auth | `AkkSec.authenticate(reason:)` | "Biometric" card |
| Tap‑jacking protection | `AkkSec.setTapjackingProtectionEnabled()` | toggle |
| Active anti‑debug (opt‑in) | `AkkSecConfig(enableAntiDebugging: true)` | config only |

---

## 1. Add the plugin to your app
In your app's `pubspec.yaml`:
```yaml
dependencies:
  akk_flutter_sec_sdk:
    git:
      url: git@github.com:akkodis-dmcc/Akk-Flutter-Security-SDK.git
      ref: v0.3.0   # pin to a tag
```
```bash
flutter pub get
```

## 2. Platform setup (required)

### Android
- **`minSdk 24`** in `android/app/build.gradle.kts`:
  ```kotlin
  defaultConfig { minSdk = maxOf(24, flutter.minSdkVersion) }
  ```
- For **biometrics**, `MainActivity` must extend **`FlutterFragmentActivity`**:
  ```kotlin
  class MainActivity : FlutterFragmentActivity()
  ```

### iOS
- Deployment target **13.0+**.
- For **biometrics**, add to `ios/Runner/Info.plist`:
  ```xml
  <key>NSFaceIDUsageDescription</key>
  <string>Authenticate to protect sensitive actions.</string>
  ```
- For **App Attest**, add the **App Attest** capability in Xcode
  (Signing & Capabilities → + Capability → App Attest) and test on a real device.
  *(Already enabled in this demo — see [Testing App Attest end-to-end](#testing-app-attest-end-to-end-ios).)*

## 3. Configure & initialize
Call `AkkSec.initialize()` once before `runApp` (see `lib/main.dart`). Cross‑platform
options are top‑level; platform‑specific options live in `android:` / `ios:`:
```dart
await AkkSec.initialize(
  config: const AkkSecConfig(
    enabledChecks: SecurityCheck.productionDefaults, // all 5
    enableAntiDebugging: false,                       // opt-in (both platforms)
    pinnedHosts: [ PinnedHost(baseUrl: '…', primaryPinSha256: 'sha256/…', backupPinSha256: 'sha256/…') ],
    protectedEndpoints: [ ProtectedEndpoint(operation: 'login', baseUrl: '…', method: 'POST', path: '/v1/login') ],
    android: AndroidConfig(
      expectedSigningSha256: 'AA:BB:…',               // tamper detection
      enablePlayIntegrity: true,
      playIntegrityCloudProjectNumber: 1234567890,    // your GCP project number
    ),
    ios: IosConfig(
      expectedBundleIdentifier: 'com.yourco.app',
      expectedTeamIdentifier: 'ABCDE12345',
      enableAppAttest: true,
    ),
  ),
);
```

## 4. Use the features
```dart
// Posture + policy in one call
final decision = await AkkSec.evaluateAppLaunch(policy: RiskPolicy.standard);
if (decision.isBlocked) { /* block: decision.blockingReasons */ }

// Secure storage
await AkkSec.secureWrite(key: 'token', value: jwt);
final jwt = await AkkSec.secureRead(key: 'token');

// Biometric gate
final r = await AkkSec.authenticate(reason: 'Confirm payment');
if (r.authenticated) { /* proceed */ }

// Pinned request
final res = await AkkSec.securePost(operation: 'login', baseUrl: api, path: '/v1/login', body: {...});

// Screen protection / tapjacking
await AkkSec.setScreenProtectionEnabled(true);
await AkkSec.setTapjackingProtectionEnabled(true);
```
The full, commented config + every call is in `lib/main.dart`.

---

## Run it
```bash
flutter run --release        # use --release so tamper/posture reflect a signed build
```

## Testing Play Integrity end-to-end (Android)

The device gets a Play Integrity token; a small local server ([`server/`](server/))
decodes it with Google and returns the verdict.

### A. Google Play + Cloud (one-time)
1. **Play Console → your app → Test and release → App integrity → Play Integrity API →
   Link Cloud project.** If the dropdown is empty, create a project first at
   [console.cloud.google.com](https://console.cloud.google.com) (New Project), then refresh.
2. Note the **project number** → set it in `lib/main.dart`:
   `const int _playIntegrityCloudProjectNumber = 717693569664;`
3. In that GCP project: **APIs & Services → Library → "Play Integrity API" → Enable**.
4. **IAM & Admin → Service Accounts → Create service account** → open it → **Keys → Add key
   → Create new key → JSON** → save as `server/service-account.json`.

### B. Run the server
```bash
cd server
npm install
cp .env.example .env         # then edit:
#   ANDROID_PACKAGE_NAME=com.smartx.fluttersecuirtydemo
#   GOOGLE_APPLICATION_CREDENTIALS=./service-account.json
npm start                    # -> http://localhost:8080
```

### C. Expose it with ngrok
```bash
brew install ngrok/ngrok/ngrok          # or download from ngrok.com/download
ngrok config add-authtoken <YOUR_TOKEN> # once, from your ngrok dashboard
ngrok http 8080
```
Copy the `https://….ngrok-free.dev` "Forwarding" URL. Put it in the app's **Server URL**
field (or set it as the default `_serverController` text in `lib/main.dart`).

### D. Verify
Run the app on a **real device**, open **Backend attestation verify → Verify (Play
Integrity)**. Check the app card + the server console.
- `MEETS_DEVICE_INTEGRITY` ✅ + `requestHash` matching the challenge = the whole chain works.
- A **debug** build shows `UNRECOGNIZED_VERSION` / `UNEVALUATED` — expected. Install the
  build **from Play internal testing** to get `PLAY_RECOGNIZED` / `ok:true`.

> ⚠️ **Never commit** `server/service-account.json`, `server/.env`, `android/key.properties`,
> or `android/keystores/` — they're gitignored for you. The project number, SHA-256
> fingerprints and `.env.example` are safe to commit.

## Testing App Attest end-to-end (iOS)

The device asks Apple's **Secure Enclave** to (1) create a hardware key and produce an
**attestation** proving the app+key are genuine, then (2) sign each request with an
**assertion**. The same local server ([`server/`](server/)) verifies both against Apple's
root CA. **No App Store Connect setup is needed** and **no TestFlight install is required** —
App Attest works from a direct Xcode run to a real device.

### Prerequisites
- A **real iPhone/iPad** (App Attest uses the Secure Enclave — it is `unavailable` on the
  Simulator).
- A paid **Apple Developer** account / team (here: `RM486MVDAU`).

### A. App Attest capability (already done in this repo)
This project already ships the capability, so there is nothing to click in Xcode:
- [`ios/Runner/Runner.entitlements`](ios/Runner/Runner.entitlements) declares
  `com.apple.developer.devicecheck.appattest-environment = development`.
- It is wired into the Debug/Release/Profile build configs, and **automatic signing**
  provisions the App ID capability for you on first build.

> Doing it from scratch in another app? In Xcode: **Runner target → Signing & Capabilities
> → + Capability → App Attest**. That creates the entitlement above. Leave it at
> `development` for testing; switch to `production` only for the App Store build.
> **The entitlement environment and the server's `APP_ATTEST_ENV` must match** — a
> `development` app verified against a `production` server (or vice‑versa) fails the
> AAGUID check (`appattestdevelop` vs `appattest`).

### B. Give the server Apple's root CA + iOS identifiers
The server verifies the attestation certificate chain against Apple's App Attestation root.
```bash
cd server
mkdir -p certs
curl -o certs/Apple_App_Attestation_Root_CA.pem \
  https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem
```
Then in `server/.env` (copy from `.env.example` if you haven't):
```bash
IOS_TEAM_ID=RM486MVDAU
IOS_BUNDLE_ID=com.akksec.demo.akksecflutterdemo
APPLE_APP_ATTEST_ROOT_CA=./certs/Apple_App_Attestation_Root_CA.pem
APP_ATTEST_ENV=development        # must match the entitlement above
```

### C. Restart the server (required)
The `.env` and the root CA are read **once at startup**, so pick up the new values with a
restart. **ngrok stays as‑is** — same tunnel URL.
```bash
# Ctrl-C the running server, then:
npm start
# console should print:  Apple root CA: loaded
```
The one server serves both platforms at once; you don't run a second instance for iOS.

### D. Verify on the device
Install on a real device (Xcode run, or `flutter run --release`), open **Backend
attestation verify**, set the **Server URL** to your ngrok URL, then **Verify (App Attest)**.
The app runs the full round‑trip: `/challenge` → `generateKey` → `attestKey` →
`POST /verify/app-attest/attestation` → `generateAssertion` →
`POST /verify/app-attest/assertion`.
- Attestation success → `{ ok: true, keyId, aaguid: "appattestdevelop" }`.
- Assertion success → `{ ok: true, counter: N }`.
- A wrong `APP_ATTEST_ENV`, Simulator, or missing CA is what makes it fail — check the
  server console for the exact reason.

> ⚠️ The App Attest verifier in `server/appAttest.js` is a **reference implementation**
> (in‑memory key store, no auth). Review it before using anything like it in production.

## Build for distribution
**Android** (bump `version:` in `pubspec.yaml` so the build number is higher than the last
Play upload):
```bash
flutter build appbundle --release --obfuscate --split-debug-info=build/symbols # AAB → Play Console
flutter build apk --release --obfuscate --split-debug-info=build/symbols       # APK → audit / direct install
```
Release signing is read from `android/key.properties` (not committed).

**Upload for internal testing:** Play Console → your app → **Test and release → Testing →
Internal testing → Create new release** → upload the **AAB** → roll out → share the opt-in
link → install from the Play Store on the device. (That Play-signed install is what makes
Play Integrity return `PLAY_RECOGNIZED`.)

**iOS** — always archive via Flutter (a direct Xcode archive misses the SwiftPM package
and fails with *"Missing package product FlutterGeneratedPluginSwiftPackage"*):
```bash
flutter build ipa --release
```
Then upload the archive at `build/ios/archive/Runner.xcarchive` via Xcode Organizer
(Distribute App → App Store Connect). Needs an iOS Distribution cert + App Store profile.

---

## Notes / gotchas
- **Run the RELEASE build** for accurate results — a debug build is signed with the debug
  key, so tamper detection (correctly) flags it.
- **Biometrics & App Attest need a real device** with biometrics enrolled / the App Attest
  capability — they report `unavailable` on a simulator/emulator.
- **Play Integrity** needs your real **GCP cloud project number**; with `0` it reports
  `integrity_not_configured`. Likewise set `ios.enableAppAttest` to use App Attest.
- **Replace the demo host + pins** (`jsonplaceholder.typicode.com`) with your real backend
  and SPKI pins for production — the SDK warns with `demo_pinning_defaults` otherwise.
- **Tamper SHA‑256s:** the demo trusts both the Play app‑signing key (Play installs) and
  the upload key (direct APKs). For your app, use your own from Play Console → App integrity.
- Anti‑debug is **off** in this demo so it doesn't kill the app under dynamic analysis
  tools; set `enableAntiDebugging: true` to exercise it.

Full SDK documentation lives in the plugin repo's `README.md`.
