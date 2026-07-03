'use strict';

// Reference App Attest verifier (test quality). Verifies the attestation object
// (once per install) and per-request assertions. See Apple's "Validating Apps
// That Connect to Your Server" for the canonical algorithm.

const crypto = require('crypto');
const cbor = require('cbor');
const x509 = require('@peculiar/x509');

x509.cryptoProvider.set(crypto.webcrypto);

const APPLE_NONCE_OID = '1.2.840.113635.100.8.2';

function sha256(buf) {
  return crypto.createHash('sha256').update(buf).digest();
}

// Uncompressed P-256 point (0x04 || X || Y) is the trailing 65 bytes of the SPKI.
function ecPointFromSpki(spkiDer) {
  return spkiDer.subarray(spkiDer.length - 65);
}

// The nonce extension value is DER: SEQUENCE { [1] OCTET STRING <32-byte nonce> }.
// The nonce is the trailing 32 bytes.
function nonceFromExtension(extValue) {
  const buf = Buffer.from(extValue);
  return buf.subarray(buf.length - 32);
}

async function verifyAttestation(opts) {
  const { attestationBase64, keyId, challenge, teamId, bundleId, rootCaPem, env } = opts;

  const attestation = await cbor.decodeFirst(Buffer.from(attestationBase64, 'base64'));
  if (attestation.fmt !== 'apple-appattest') {
    throw new Error(`Unexpected attestation format: ${attestation.fmt}`);
  }
  const x5c = attestation.attStmt.x5c;
  const authData = Buffer.from(attestation.authData);

  const credCert = new x509.X509Certificate(new Uint8Array(x5c[0]));
  const caCert = new x509.X509Certificate(new Uint8Array(x5c[1]));
  const rootCert = new x509.X509Certificate(rootCaPem);

  // 1) Certificate chain: root -> intermediate -> credential cert.
  const rootKey = await rootCert.publicKey.export();
  const caKey = await caCert.publicKey.export();
  if (!(await caCert.verify({ publicKey: rootKey }))) {
    throw new Error('Intermediate cert not signed by the Apple App Attest root.');
  }
  if (!(await credCert.verify({ publicKey: caKey }))) {
    throw new Error('Credential cert not signed by the intermediate.');
  }

  // 2) nonce = SHA256(authData || SHA256(challenge)) must match the cert extension.
  const clientDataHash = sha256(Buffer.from(challenge));
  const nonce = sha256(Buffer.concat([authData, clientDataHash]));
  const ext = credCert.getExtension(APPLE_NONCE_OID);
  if (!ext) throw new Error('Missing Apple nonce extension.');
  if (!nonceFromExtension(ext.value).equals(nonce)) {
    throw new Error('Attestation nonce mismatch.');
  }

  // 3) keyId must equal SHA256 of the credential public key.
  const spki = Buffer.from(credCert.publicKey.rawData);
  const computedKeyId = sha256(ecPointFromSpki(spki)).toString('base64');
  if (computedKeyId !== keyId) {
    throw new Error('keyId does not match the attested public key.');
  }

  // 4) authData: rpIdHash == SHA256("TEAMID.bundleId"), counter == 0, aaguid env.
  const rpIdHash = authData.subarray(0, 32);
  const appId = `${teamId}.${bundleId}`;
  if (!rpIdHash.equals(sha256(Buffer.from(appId)))) {
    throw new Error('rpIdHash does not match the app id.');
  }
  const counter = authData.readUInt32BE(33);
  const aaguid = authData.subarray(37, 53).toString('utf8').replace(/\0+$/, '');
  const expectedAaguid = env === 'production' ? 'appattest' : 'appattestdevelop';
  if (aaguid !== expectedAaguid) {
    throw new Error(`Unexpected aaguid "${aaguid}" (expected "${expectedAaguid}").`);
  }
  if (counter !== 0) throw new Error('Attestation counter must be 0.');

  // Success: return the SPKI to store (keyed by keyId) for future assertions.
  return { keyId, publicKeySpkiBase64: spki.toString('base64'), aaguid, counter };
}

function verifyAssertion(opts) {
  const { assertionBase64, challenge, publicKeySpkiBase64, teamId, bundleId } = opts;

  return cbor.decodeFirst(Buffer.from(assertionBase64, 'base64')).then((assertion) => {
    const signature = Buffer.from(assertion.signature);
    const authenticatorData = Buffer.from(assertion.authenticatorData);

    // Apple signs the assertion over nonce = SHA256(authenticatorData || clientDataHash).
    // The key is ES256 (ECDSA + SHA256), so crypto.verify('sha256', nonce, ...) hashes
    // nonce once more and checks the ECDSA signature over SHA256(nonce) — matching how
    // the Secure Enclave produced it. Passing the un-hashed concatenation would be one
    // SHA256 short and always fail.
    const clientDataHash = sha256(Buffer.from(challenge));
    const nonce = sha256(Buffer.concat([authenticatorData, clientDataHash]));

    const key = crypto.createPublicKey({
      key: Buffer.from(publicKeySpkiBase64, 'base64'),
      format: 'der',
      type: 'spki',
    });
    const valid = crypto.verify('sha256', nonce, { key, dsaEncoding: 'der' }, signature);
    if (!valid) throw new Error('Assertion signature is invalid.');

    const rpIdHash = authenticatorData.subarray(0, 32);
    const appId = `${teamId}.${bundleId}`;
    if (!rpIdHash.equals(sha256(Buffer.from(appId)))) {
      throw new Error('Assertion rpIdHash does not match the app id.');
    }
    const counter = authenticatorData.readUInt32BE(33);
    return { valid: true, counter };
  });
}

module.exports = { verifyAttestation, verifyAssertion };
