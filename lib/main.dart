import 'dart:async';

import 'package:akk_flutter_sec_sdk/akk_flutter_sec_sdk.dart';
import 'package:flutter/material.dart';

// ---------------------------------------------------------------------------
// Configuration — every available AkkSecConfig option is shown here.
// Active lines are uncommented; the comments document the full menu so you can
// see (and toggle) everything you can pass.
// ---------------------------------------------------------------------------

// Demo API host for the pinned-request example. Replace the host and BOTH pins
// with your real values before production (the SDK warns with
// `demo_pinning_defaults` while these example pins are in use).
const String _apiBase = 'https://jsonplaceholder.typicode.com';

// Android Play Integrity: your Google Cloud project number (Play Console →
// App integrity). 0 = enabled but unconfigured.
const int _playIntegrityCloudProjectNumber = 0;

const AkkSecConfig _config = AkkSecConfig(
  // --- enabledChecks: which posture checks run. Remove a line to disable it. ---
  // Omit this field entirely to use SecurityCheck.productionDefaults (all five).
  enabledChecks: {
    SecurityCheck.deviceCompromise,   // root (Android) / jailbreak (iOS)
    SecurityCheck.appTamper,          // app signature / bundle tamper
    SecurityCheck.runtimeHook,        // hooking / injection (Frida, Xposed…)
    SecurityCheck.debugger,           // attached debugger / debuggable build
    SecurityCheck.virtualEnvironment, // emulator / simulator
  },

  // --- Active anti-debugging (both platforms) ---
  // Off here so it doesn't kill the app under the auditor's dynamic tools.
  // Set true to terminate on tracer attach (Android) / ptrace deny-attach (iOS).
  enableAntiDebugging: false,

  // --- Android-only settings ---
  android: AndroidConfig(
    // SHA-256 of the signing cert(s). Both are listed so tamper passes for BOTH
    // distribution paths (multiple values are comma-separated):
    //   1) Play app-signing key — installs from Google Play (Google re-signs the AAB)
    //   2) Upload key           — direct/sideloaded APKs you sign with your upload key
    expectedSigningSha256:
        '9D:9E:D3:BC:37:96:FC:B4:41:7A:C2:DC:F5:21:FC:DA:C3:38:7C:CD:0F:F6:39:B3:6C:28:EA:9C:94:CA:41:77,'
        'AE:6B:0A:71:46:EE:3D:81:96:C5:DF:D1:14:89:50:B8:E9:FC:22:65:56:1C:76:4F:A0:95:49:DD:2A:BF:90:8D',
    enablePlayIntegrity: true, // set playIntegrityCloudProjectNumber to make it functional
    playIntegrityCloudProjectNumber: _playIntegrityCloudProjectNumber,
  ),

  // --- iOS-only settings ---
  ios: IosConfig(
    expectedBundleIdentifier: 'com.akksec.demo.akksecflutterdemo',
    expectedTeamIdentifier: 'RM486MVDAU',
    // App Attest is independent of Play Integrity. Needs the App Attest
    // capability in Xcode + a real device to function.
    enableAppAttest: true,
  ),

  // --- Certificate pinning: hosts whose SPKI pins native requests must trust ---
  pinnedHosts: [
    PinnedHost(
      baseUrl: _apiBase, // HTTPS base URL
      // Real SPKI pins for this host. Pin to YOUR production host for a live app.
      primaryPinSha256: 'sha256/3U84jdV3AKjdpmiBjrwT1shpZS0fQDhoLspJ7Exj1AU=', // leaf (CN=typicode.com)
      backupPinSha256: 'sha256/kIdp6NNEd8wsugYyyIYFsi1ylMCED3hZbSR8ZFsa/A4=', // intermediate (GTS WE1)
    ),
    // Add more PinnedHost(...) entries for additional pinned hosts.
  ],

  // --- protectedEndpoints: allowlist of operations the pinned client may run ---
  protectedEndpoints: [
    ProtectedEndpoint(
      operation: 'get_post', // unique id you call at runtime
      baseUrl: _apiBase, // must match a PinnedHost above
      method: 'GET', // GET | POST | PUT | PATCH | DELETE
      path: '/posts/1', // must start with '/'
      // bodyPolicy: RequestBodyPolicy.none, // none | optional | required
      // allowedHeaders: {'Content-Type'},   // header names callers may pass
      // allowedQueryParameters: {'userId'}, // query names callers may pass
    ),
    ProtectedEndpoint(
      operation: 'create_post',
      baseUrl: _apiBase,
      method: 'POST',
      path: '/posts',
      bodyPolicy: RequestBodyPolicy.required, // body must be present
      allowedHeaders: {'Content-Type'},
    ),
    // Add more ProtectedEndpoint(...) entries as needed.
  ],
);

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await AkkSec.initialize(config: _config);
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    final scheme = ColorScheme.fromSeed(
      seedColor: const Color(0xFF14B8A6),
      brightness: Brightness.dark,
    );
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      title: 'AkkSec Demo',
      theme: ThemeData(
        useMaterial3: true,
        colorScheme: scheme,
        scaffoldBackgroundColor: const Color(0xFF0B1220),
      ),
      home: const SecurityHomePage(),
    );
  }
}

class SecurityHomePage extends StatefulWidget {
  const SecurityHomePage({super.key});

  @override
  State<SecurityHomePage> createState() => _SecurityHomePageState();
}

class _SecurityHomePageState extends State<SecurityHomePage> {
  final SecurityPlatformInfo _platform = SecurityPlatformInfo.current();

  SecurityResult? _result;
  RiskDecision? _decision;
  bool _scanning = false;
  String? _scanError;

  bool _screenProtected = false;

  bool _monitoring = false;
  StreamSubscription<SecurityResult>? _monitorSub;

  String _requestStatus = 'Not run';
  bool _requestBusy = false;

  String _integrityStatus = 'Not run';
  bool _integrityBusy = false;

  String _storageStatus = 'Not run';
  String _biometricStatus = 'Not run';
  bool _tapjackingOn = false;

  @override
  void initState() {
    super.initState();
    // Production posture: turn on screen-capture protection up front
    // (FLAG_SECURE on Android), then run the launch posture scan.
    _enableScreenProtectionByDefault();
    _scan();
  }

  Future<void> _enableScreenProtectionByDefault() async {
    try {
      final applied = await AkkSec.setScreenProtectionEnabled(true);
      if (mounted) setState(() => _screenProtected = applied);
    } on AkkSecException {
      // Non-fatal for the demo.
    }
  }

  @override
  void dispose() {
    _monitorSub?.cancel();
    super.dispose();
  }

  Future<void> _scan() async {
    setState(() {
      _scanning = true;
      _scanError = null;
    });
    try {
      final decision = await AkkSec.evaluateAppLaunch(policy: RiskPolicy.standard);
      setState(() {
        _decision = decision;
        _result = decision.result;
      });
    } on AkkSecException catch (e) {
      setState(() => _scanError = '${e.code.value}: ${e.message}');
    } finally {
      if (mounted) setState(() => _scanning = false);
    }
  }

  void _toggleMonitoring(bool value) {
    setState(() => _monitoring = value);
    if (value) {
      _monitorSub =
          AkkSec.securityEvents(interval: const Duration(seconds: 5)).listen((r) {
        setState(() {
          _result = r;
          _decision = RiskPolicy.standard.evaluate(r);
        });
      });
    } else {
      _monitorSub?.cancel();
      _monitorSub = null;
    }
  }

  Future<void> _toggleScreenProtection(bool value) async {
    final applied = await AkkSec.setScreenProtectionEnabled(value);
    setState(() => _screenProtected = applied);
  }

  Future<void> _runSecureRequest() async {
    setState(() {
      _requestBusy = true;
      _requestStatus = 'Sending…';
    });
    try {
      final res = await AkkSec.secureGet(
        operation: 'get_post',
        baseUrl: _apiBase,
        path: '/posts/1',
      );
      setState(() => _requestStatus =
          'HTTP ${res.statusCode} · ${res.host}${res.path}\n${_preview(res.body)}');
    } on AkkSecException catch (e) {
      setState(() => _requestStatus = '${e.code.value}: ${e.message}');
    } finally {
      if (mounted) setState(() => _requestBusy = false);
    }
  }

  Future<void> _runIntegrity() async {
    setState(() {
      _integrityBusy = true;
      _integrityStatus = 'Preparing…';
    });
    try {
      final prep = await AkkSec.prepareAppIntegrityProvider(
        androidCloudProjectNumber: _playIntegrityCloudProjectNumber,
      );
      if (!prep.isPrepared) {
        setState(() => _integrityStatus = '${prep.status}: ${prep.message}');
        return;
      }
      final token = await AkkSec.requestAppIntegrityAssertion(
        requestHash: 'demo-${DateTime.now().millisecondsSinceEpoch}',
      );
      setState(() => _integrityStatus = token.isIssued
          ? 'Issued ✓ token ${token.tokenLength} bytes — send to backend'
          : '${token.status}: ${token.message}');
    } on AkkSecException catch (e) {
      setState(() => _integrityStatus = '${e.code.value}: ${e.message}');
    } finally {
      if (mounted) setState(() => _integrityBusy = false);
    }
  }

  Future<void> _testSecureStorage() async {
    try {
      const key = 'demo_token';
      await AkkSec.secureWrite(key: key, value: 'secret-${DateTime.now().millisecondsSinceEpoch}');
      final read = await AkkSec.secureRead(key: key);
      final exists = await AkkSec.secureContains(key: key);
      setState(() => _storageStatus = 'Wrote + read back ✓\nvalue: $read\ncontains: $exists');
    } on AkkSecException catch (e) {
      setState(() => _storageStatus = '${e.code.value}: ${e.message}');
    }
  }

  Future<void> _testBiometric() async {
    setState(() => _biometricStatus = 'Prompting…');
    try {
      final r = await AkkSec.authenticate(reason: 'Confirm your identity');
      setState(() => _biometricStatus =
          '${r.authenticated ? "Authenticated ✓" : "Not authenticated"} (${r.status})\n${r.message}');
    } on AkkSecException catch (e) {
      setState(() => _biometricStatus = '${e.code.value}: ${e.message}');
    }
  }

  Future<void> _toggleTapjacking(bool value) async {
    try {
      final applied = await AkkSec.setTapjackingProtectionEnabled(value);
      setState(() => _tapjackingOn = applied);
    } on AkkSecException catch (e) {
      setState(() => _biometricStatus = '${e.code.value}: ${e.message}');
    }
  }

  String _preview(String body) {
    final t = body.trim();
    return t.length > 160 ? '${t.substring(0, 160)}…' : t;
  }

  @override
  Widget build(BuildContext context) {
    final result = _result;
    final decision = _decision;

    return Scaffold(
      appBar: AppBar(
        title: Row(
          children: [
            const Icon(Icons.shield_outlined, size: 20),
            const SizedBox(width: 8),
            const Text('AkkSec'),
            const Spacer(),
            Chip(
              avatar: Icon(_platform.isIOS ? Icons.apple : Icons.android, size: 16),
              label: Text(_platform.name),
            ),
          ],
        ),
      ),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          _postureCard(result, decision),
          const SizedBox(height: 12),
          if (result != null) ...[
            _checksCard(result),
            const SizedBox(height: 12),
            if (result.reasons.isNotEmpty) ...[
              _reasonsCard(result),
              const SizedBox(height: 12),
            ],
          ],
          _screenCard(),
          const SizedBox(height: 12),
          _requestCard(),
          const SizedBox(height: 12),
          _integrityCard(),
          const SizedBox(height: 12),
          _actionCard(
            icon: Icons.lock_person_outlined,
            title: 'Secure storage (Keystore / Keychain)',
            buttonLabel: 'Write + read',
            status: _storageStatus,
            onPressed: _testSecureStorage,
          ),
          const SizedBox(height: 12),
          _actionCard(
            icon: Icons.fingerprint,
            title: 'Biometric authentication',
            buttonLabel: 'Authenticate',
            status: _biometricStatus,
            onPressed: _testBiometric,
          ),
          const SizedBox(height: 12),
          !_platform.isIOS ? Card(
            child: SwitchListTile(
              secondary: const Icon(Icons.layers_clear_outlined),
              title: const Text('Tap-jacking protection'),
              subtitle: Text(_tapjackingOn
                  ? 'On (touches ignored when obscured)'
                  : 'Off (Android only)'),
              value: _tapjackingOn,
              onChanged: _toggleTapjacking,
            ),
          ) : Container(),
        ],
      ),
    );
  }

  Widget _postureCard(SecurityResult? result, RiskDecision? decision) {
    final score = result?.riskScore ?? 0;
    final blocked = decision?.isBlocked ?? false;
    final color = blocked
        ? Colors.red
        : score >= 20
            ? Colors.orange
            : Colors.green;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('Security posture',
                style: Theme.of(context).textTheme.titleMedium),
            const SizedBox(height: 8),
            if (_scanError != null)
              Text(_scanError!, style: const TextStyle(color: Colors.red))
            else if (result == null)
              const Text('Scanning…')
            else ...[
              Text('Risk score  $score / 100',
                  style: Theme.of(context)
                      .textTheme
                      .headlineSmall
                      ?.copyWith(color: color, fontWeight: FontWeight.bold)),
              const SizedBox(height: 6),
              Row(
                children: [
                  Icon(blocked ? Icons.gpp_bad : Icons.verified_user,
                      color: color, size: 18),
                  const SizedBox(width: 6),
                  Expanded(
                    child: Text(
                      blocked
                          ? 'BLOCKED: ${decision!.blockingReasons.join(", ")}'
                          : 'Allowed by RiskPolicy.standard',
                      style: TextStyle(color: color, fontWeight: FontWeight.w600),
                    ),
                  ),
                ],
              ),
            ],
            const SizedBox(height: 12),
            Row(
              children: [
                Expanded(
                  child: FilledButton.icon(
                    onPressed: _scanning ? null : _scan,
                    icon: _scanning
                        ? const SizedBox(
                            width: 16,
                            height: 16,
                            child: CircularProgressIndicator(strokeWidth: 2))
                        : const Icon(Icons.refresh),
                    label: const Text('Re-scan'),
                  ),
                ),
              ],
            ),
            SwitchListTile(
              contentPadding: EdgeInsets.zero,
              title: const Text('Live monitoring (5s)'),
              value: _monitoring,
              onChanged: _toggleMonitoring,
            ),
          ],
        ),
      ),
    );
  }

  Widget _checksCard(SecurityResult r) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(8),
        child: Column(
          children: [
            _checkTile(_platform.deviceCompromiseLabel, r.isRooted),
            _checkTile(_platform.tamperLabel, r.isTampered),
            _checkTile(_platform.hookingLabel, r.isHooked),
            _checkTile(_platform.debuggerLabel, r.isDebug),
            _checkTile(_platform.virtualRuntimeLabel, r.isEmulator),
          ],
        ),
      ),
    );
  }

  Widget _checkTile(String label, bool detected) {
    return ListTile(
      dense: true,
      leading: Icon(detected ? Icons.error : Icons.check_circle,
          color: detected ? Colors.red : Colors.green),
      title: Text(label),
      trailing: Text(detected ? 'Detected' : 'Clear',
          style: TextStyle(
              color: detected ? Colors.red : Colors.green,
              fontWeight: FontWeight.w600)),
    );
  }

  Widget _reasonsCard(SecurityResult r) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text('Reasons', style: TextStyle(fontWeight: FontWeight.bold)),
            const SizedBox(height: 8),
            ...r.reasons.map((x) => Text('• $x',
                style: const TextStyle(fontSize: 13, color: Colors.white70))),
          ],
        ),
      ),
    );
  }

  Widget _screenCard() {
    return Card(
      child: SwitchListTile(
        secondary: const Icon(Icons.screenshot_monitor_outlined),
        title: Text(_platform.screenProtectionTitle),
        subtitle: Text(_screenProtected
            ? _platform.screenProtectionEnabledDescription
            : _platform.screenProtectionDisabledDescription),
        value: _screenProtected,
        onChanged: _toggleScreenProtection,
      ),
    );
  }

  Widget _requestCard() {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                const Icon(Icons.lock_outline, size: 18),
                const SizedBox(width: 8),
                const Expanded(child: Text('Pinned request (GET /posts/1)')),
                FilledButton(
                  onPressed: _requestBusy ? null : _runSecureRequest,
                  child: _requestBusy
                      ? const SizedBox(
                          width: 16,
                          height: 16,
                          child: CircularProgressIndicator(strokeWidth: 2))
                      : const Text('Send'),
                ),
              ],
            ),
            const SizedBox(height: 10),
            Text(_requestStatus,
                style: const TextStyle(
                    fontFamily: 'monospace', fontSize: 12, color: Colors.white70)),
          ],
        ),
      ),
    );
  }

  Widget _integrityCard() {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                const Icon(Icons.workspace_premium_outlined, size: 18),
                const SizedBox(width: 8),
                Expanded(child: Text(_platform.integrityProviderName)),
                OutlinedButton(
                  onPressed: _integrityBusy ? null : _runIntegrity,
                  child: _integrityBusy
                      ? const SizedBox(
                          width: 16,
                          height: 16,
                          child: CircularProgressIndicator(strokeWidth: 2))
                      : const Text('Prepare + request'),
                ),
              ],
            ),
            const SizedBox(height: 10),
            Text(_integrityStatus,
                style: const TextStyle(fontSize: 12, color: Colors.white70)),
          ],
        ),
      ),
    );
  }

  Widget _actionCard({
    required IconData icon,
    required String title,
    required String buttonLabel,
    required String status,
    required VoidCallback onPressed,
  }) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(icon, size: 18),
                const SizedBox(width: 8),
                Expanded(child: Text(title)),
                OutlinedButton(onPressed: onPressed, child: Text(buttonLabel)),
              ],
            ),
            const SizedBox(height: 10),
            Text(status, style: const TextStyle(fontSize: 12, color: Colors.white70)),
          ],
        ),
      ),
    );
  }
}
