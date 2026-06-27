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

## Build for distribution
**Android**
```bash
flutter build apk --release --obfuscate --split-debug-info=build/symbols      # APK (audit / direct install)
flutter build appbundle --release --obfuscate --split-debug-info=build/symbols # AAB (Play Console)
```
Release signing is read from `android/key.properties` (not committed).

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
