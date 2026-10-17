'use strict';

/**
 * @fileoverview Circle Facilitator Service — the `Facilitator-Seller-Proof`
 * header for the keyless trial (T-952, Circle Developer Grants Milestone 1).
 *
 * Circle's hosted x402 facilitator (https://api.circle.com/v1/facilitator/x402)
 * settles USDC on Arc, Base and Polygon. It authenticates a seller one of two
 * ways (developers.circle.com/facilitator-service/how-it-works.md):
 *   1. a Circle API key (Bearer) — needs a Circle Console account, or
 *   2. the keyless trial: an EIP-712 "seller proof" signed by the key that
 *      controls `payTo`, bound to one purpose, one request body, one network
 *      and one payTo, valid for at most 5 minutes
 *      (developers.circle.com/facilitator-service/sign-seller-proof.md).
 *
 * TRADE-OFF, stated where it is made: mode 2 puts the payTo private key on the
 * server, and billing/x402.js's founding rule is that this server can receive
 * money and cannot spend it. So mode 2 is for a testnet rehearsal (Arc testnet,
 * faucet USDC, a key that holds nothing of value) or a deliberately separate
 * trial wallet — never the main receiving wallet. Production on Arc mainnet is
 * meant to run on mode 1, which FacilitatorClient already supports as a plain
 * Bearer key. createSellerProofSigner refuses a key that does not control the
 * payTo it is asked to prove, so a mis-pasted key fails at boot, not at the
 * first customer's payment.
 */

const crypto = require('node:crypto');
const { keccak256 } = require('../lib/evm-address');
const { signDigest, addressFromPrivateKey, hashTypedData } = require('../lib/secp256k1');

const SELLER_PROOF_HEADER = 'Facilitator-Seller-Proof';

/** Circle: `expiresAt` no more than 5 minutes after `issuedAt`. */
const MAX_PROOF_LIFETIME_SECONDS = 300;

const SELLER_REQUEST_TYPES = {
  SellerRequest: [
    { name: 'purpose', type: 'string' },
    { name: 'method', type: 'string' },
    { name: 'bodyHash', type: 'bytes32' },
    { name: 'network', type: 'string' },
    { name: 'payTo', type: 'address' },
    { name: 'nonce', type: 'bytes32' },
    { name: 'issuedAt', type: 'uint64' },
    { name: 'expiresAt', type: 'uint64' },
  ],
};

const PURPOSES = new Set(['verify', 'settle', 'status']);

function chainIdOf(caip2) {
  const m = /^eip155:(\d+)$/.exec(String(caip2));
  if (!m) throw new TypeError(`seller proof needs a CAIP-2 eip155 network, got "${caip2}"`);
  return Number(m[1]);
}

/**
 * @param {Object} opts
 * @param {string} opts.privateKey — hex key that controls payTo
 * @param {string} [opts.payTo] — when given, must be the key's own address
 * @param {number} [opts.lifetimeSeconds=120]
 */
function createSellerProofSigner({ privateKey, payTo = null, lifetimeSeconds = 120 }) {
  const address = addressFromPrivateKey(privateKey);
  if (payTo && String(payTo).toLowerCase() !== address) {
    throw new Error(
      `seller-proof key controls ${address}, not payTo ${payTo} — Circle would answer 401 on every payment`,
    );
  }
  const lifetime = Math.min(Math.max(1, Math.floor(lifetimeSeconds)), MAX_PROOF_LIFETIME_SECONDS);

  /**
   * The header value for one request.
   * @param {Object} req
   * @param {'verify'|'settle'|'status'} req.purpose — must match the route called
   * @param {string} req.method — HTTP method
   * @param {string} req.body — the EXACT bytes sent (GET hashes empty bytes)
   * @param {string} req.network — CAIP-2; must equal paymentRequirements.network
   * @param {string} req.payTo — must equal paymentRequirements.payTo
   */
  function header({ purpose, method, body = '', network, payTo: proofPayTo, nowSeconds, nonce }) {
    if (!PURPOSES.has(purpose)) throw new TypeError(`seller proof purpose must be verify|settle|status, got ${purpose}`);
    if (String(proofPayTo).toLowerCase() !== address) {
      throw new Error(`seller proof asked for payTo ${proofPayTo} but this key controls ${address}`);
    }
    const issuedAt = Number.isFinite(nowSeconds) ? Math.floor(nowSeconds) : Math.floor(Date.now() / 1000);
    const message = {
      purpose,
      method: String(method).toUpperCase(),
      bodyHash: '0x' + keccak256(Buffer.from(String(body), 'utf8')),
      network,
      payTo: proofPayTo,
      nonce: nonce || '0x' + crypto.randomBytes(32).toString('hex'),
      issuedAt,
      expiresAt: issuedAt + lifetime,
    };
    const digest = hashTypedData({
      domain: { name: 'Circle Facilitator Seller Request', version: '1', chainId: chainIdOf(network) },
      types: SELLER_REQUEST_TYPES,
      primaryType: 'SellerRequest',
      message,
    });
    const envelope = {
      version: 1,
      signature: signDigest(digest, privateKey),
      network: message.network,
      payTo: message.payTo,
      nonce: message.nonce,
      issuedAt: message.issuedAt,
      expiresAt: message.expiresAt,
    };
    return Buffer.from(JSON.stringify(envelope), 'utf8').toString('base64url');
  }

  return { address, header };
}

module.exports = {
  createSellerProofSigner,
  SELLER_PROOF_HEADER,
  SELLER_REQUEST_TYPES,
  MAX_PROOF_LIFETIME_SECONDS,
};
