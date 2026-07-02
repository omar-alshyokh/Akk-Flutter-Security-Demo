'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const express = require('express');

const { verifyPlayIntegrity } = require('./playIntegrity');
const { verifyAttestation, verifyAssertion } = require('./appAttest');

// --- Minimal .env loader (no dependency) ---
(() => {
  const envPath = path.join(__dirname, '.env');
  if (!fs.existsSync(envPath)) return;
  for (const line of fs.readFileSync(envPath, 'utf8').split('\n')) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/);
    if (m && !process.env[m[1]]) process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
  }
})();

const PORT = process.env.PORT || 8080;
const ANDROID_PACKAGE_NAME = process.env.ANDROID_PACKAGE_NAME || 'com.smartx.fluttersecuirtydemo';
const IOS_TEAM_ID = process.env.IOS_TEAM_ID || '';
const IOS_BUNDLE_ID = process.env.IOS_BUNDLE_ID || '';
const APP_ATTEST_ENV = process.env.APP_ATTEST_ENV || 'development';

let appleRootCaPem = null;
if (process.env.APPLE_APP_ATTEST_ROOT_CA && fs.existsSync(process.env.APPLE_APP_ATTEST_ROOT_CA)) {
  appleRootCaPem = fs.readFileSync(process.env.APPLE_APP_ATTEST_ROOT_CA, 'utf8');
}

// --- In-memory stores (fine for a local test server) ---
const issuedChallenges = new Set();     // one-time challenges
const attestedKeys = new Map();         // keyId -> publicKeySpkiBase64

const app = express();
app.use(express.json({ limit: '256kb' }));

app.get('/health', (_req, res) => res.json({ ok: true }));

// The device calls this first; use the value as the App Attest challenge and as
// the Play Integrity requestHash so tokens are bound to a fresh server nonce.
app.get('/challenge', (_req, res) => {
  const challenge = crypto.randomBytes(24).toString('base64url');
  issuedChallenges.add(challenge);
  res.json({ challenge });
});

app.post('/verify/play-integrity', async (req, res) => {
  try {
    const { token } = req.body;
    if (!token) return res.status(400).json({ ok: false, error: 'token required' });
    const result = await verifyPlayIntegrity(token, ANDROID_PACKAGE_NAME);
    res.json({ ok: result.passed, ...result });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message });
  }
});

app.post('/verify/app-attest/attestation', async (req, res) => {
  try {
    if (!appleRootCaPem) throw new Error('APPLE_APP_ATTEST_ROOT_CA not configured.');
    const { keyId, attestation, challenge } = req.body;
    if (!keyId || !attestation || !challenge) {
      return res.status(400).json({ ok: false, error: 'keyId, attestation, challenge required' });
    }
    const out = await verifyAttestation({
      attestationBase64: attestation,
      keyId,
      challenge,
      teamId: IOS_TEAM_ID,
      bundleId: IOS_BUNDLE_ID,
      rootCaPem: appleRootCaPem,
      env: APP_ATTEST_ENV,
    });
    attestedKeys.set(keyId, out.publicKeySpkiBase64);
    issuedChallenges.delete(challenge);
    res.json({ ok: true, keyId, aaguid: out.aaguid });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message });
  }
});

app.post('/verify/app-attest/assertion', async (req, res) => {
  try {
    const { keyId, assertion, challenge } = req.body;
    const publicKeySpkiBase64 = attestedKeys.get(keyId);
    if (!publicKeySpkiBase64) {
      return res.status(400).json({ ok: false, error: 'unknown keyId (attest first)' });
    }
    const out = await verifyAssertion({
      assertionBase64: assertion,
      challenge,
      publicKeySpkiBase64,
      teamId: IOS_TEAM_ID,
      bundleId: IOS_BUNDLE_ID,
    });
    issuedChallenges.delete(challenge);
    res.json({ ok: out.valid, counter: out.counter });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message });
  }
});

app.listen(PORT, () => {
  console.log(`AkkSec verify server on http://0.0.0.0:${PORT}`);
  console.log(`  Android package: ${ANDROID_PACKAGE_NAME}`);
  console.log(`  iOS: ${IOS_TEAM_ID}.${IOS_BUNDLE_ID} (${APP_ATTEST_ENV})`);
  console.log(`  Apple root CA: ${appleRootCaPem ? 'loaded' : 'NOT set'}`);
});
