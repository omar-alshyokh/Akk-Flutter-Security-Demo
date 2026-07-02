'use strict';

const { google } = require('googleapis');

/**
 * Decodes and evaluates a Play Integrity Standard token via Google's
 * decodeIntegrityToken endpoint. Requires GOOGLE_APPLICATION_CREDENTIALS to point
 * at a service-account key with the Play Integrity API enabled, in the cloud
 * project linked to your app in Play Console.
 */
async function verifyPlayIntegrity(token, packageName) {
  const auth = new google.auth.GoogleAuth({
    scopes: ['https://www.googleapis.com/auth/playintegrity'],
  });
  const authClient = await auth.getClient();
  const playintegrity = google.playintegrity({ version: 'v1', auth: authClient });

  const res = await playintegrity.v1.decodeIntegrityToken({
    packageName,
    requestBody: { integrityToken: token },
  });

  const payload = res.data.tokenPayloadExternal || {};
  const appVerdict = payload.appIntegrity?.appRecognitionVerdict;
  const deviceVerdicts = payload.deviceIntegrity?.deviceRecognitionVerdict || [];

  const passed =
    appVerdict === 'PLAY_RECOGNIZED' &&
    deviceVerdicts.includes('MEETS_DEVICE_INTEGRITY');

  return {
    passed,
    appRecognitionVerdict: appVerdict,
    deviceRecognitionVerdict: deviceVerdicts,
    // The full verdict so you can apply your own policy.
    payload,
  };
}

module.exports = { verifyPlayIntegrity };
