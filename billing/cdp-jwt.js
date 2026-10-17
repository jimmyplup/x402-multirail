'use strict';

/**
 * @fileoverview Per-request Bearer JWT for the Coinbase CDP x402 facilitator.
 *
 * CDP does not accept a static API key. Every REST call carries a short-lived
 * JWT signed with the project's Secret API Key and bound to that one request
 * (method + host + path). Shape mirrors coinbase/cdp-sdk
 * typescript/packages/cdp-sdk/src/auth/utils/jwt.ts, read 2026-10-14:
 *   header  { alg, kid: keyId, typ: 'JWT', nonce: 16 random bytes hex }
 *   claims  { sub: keyId, iss: 'cdp', uris: ['POST host/path'], iat, nbf, exp }
 * Two key formats exist: Ed25519 (base64 of 64 bytes, seed + public key, alg
 * EdDSA — the portal's default) and EC P-256 PEM (alg ES256).
 *
 * node:crypto only, for the same reason FacilitatorClient uses bare fetch: no
 * dependency that can change under us between the spec and the wire.
 */

const crypto = require('node:crypto');

// PKCS#8 wrapper for a raw 32-byte Ed25519 seed (RFC 8410 §7).
const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

function b64url(input) {
  return Buffer.from(input).toString('base64url');
}

/** @returns {{ key: crypto.KeyObject, alg: 'EdDSA'|'ES256' }} */
function loadSigningKey(keySecret) {
  const secret = String(keySecret || '').trim();
  if (!secret) throw new Error('CDP key secret is empty');
  if (secret.includes('-----BEGIN')) {
    return { key: crypto.createPrivateKey(secret.replace(/\\n/g, '\n')), alg: 'ES256' };
  }
  const decoded = Buffer.from(secret, 'base64');
  if (decoded.length !== 64) throw new Error('Invalid Ed25519 key length');
  const key = crypto.createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_PREFIX, decoded.subarray(0, 32)]),
    format: 'der',
    type: 'pkcs8',
  });
  return { key, alg: 'EdDSA' };
}

/**
 * @param {object} o
 * @param {string} o.keyId      CDP Secret API Key id
 * @param {string} o.keySecret  CDP Secret API Key secret (Ed25519 base64 or EC PEM)
 * @param {string} o.method     HTTP method of the request this token authorises
 * @param {string} o.url        Full URL of that request
 * @param {number} [o.expiresIn=120]
 * @param {number} [o.now]      Unix seconds; injectable for tests
 * @returns {string} compact JWS
 */
function generateCdpJwt({ keyId, keySecret, method, url, expiresIn = 120, now }) {
  if (!keyId) throw new Error('CDP key id is empty');
  const { key, alg } = loadSigningKey(keySecret);
  const u = new URL(url);
  const iat = now == null ? Math.floor(Date.now() / 1000) : now;
  const header = { alg, kid: keyId, typ: 'JWT', nonce: crypto.randomBytes(16).toString('hex') };
  const claims = {
    sub: keyId,
    iss: 'cdp',
    uris: [`${String(method).toUpperCase()} ${u.host}${u.pathname}`],
    iat,
    nbf: iat,
    exp: iat + expiresIn,
  };
  const signingInput = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(claims))}`;
  const signature = alg === 'EdDSA'
    ? crypto.sign(null, Buffer.from(signingInput), key)
    : crypto.sign('sha256', Buffer.from(signingInput), { key, dsaEncoding: 'ieee-p1363' });
  return `${signingInput}.${b64url(signature)}`;
}

module.exports = { generateCdpJwt, loadSigningKey };
