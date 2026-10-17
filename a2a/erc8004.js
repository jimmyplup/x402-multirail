'use strict';

/**
 * @fileoverview ERC-8004 registration file — the off-chain half of Synap's
 * on-chain agent identity (T-954, Celo "Agents on Open Rails" + Prezenti).
 *
 * ERC-8004's Identity Registry mints an NFT whose `agentURI` points at a JSON
 * file listing the service's endpoints (eips.ethereum.org/EIPS/eip-8004,
 * docs.celo.org/build/agents/8004.md). The hackathon makes this identity a hard
 * gate ("your project will only be valid with an ERC-8004 identity"), and the
 * file is what a registry crawler and the Loops judge actually read. Served at
 * GET /.well-known/agent-registration.json; the spec mandates no path.
 *
 * WHAT IT MAY CLAIM: only what this process actually serves. The payment
 * wallets and the networks named in the description come from the live x402
 * rail set — an extra rail that is disabled (no key, testnet, unknown token)
 * is not advertised — so the file cannot promise a chain we would refuse.
 *
 * `registrations` is the cross-check against the chain (file ↔ NFT). It is
 * empty until the register() transaction is mined, then filled from
 * ERC8004_REGISTRATIONS — never typed in by hand from a simulation, because
 * the simulated agentId is wrong whenever someone else registers first
 * (docs.celo.org/build/agents/8004.md, "Read the agent ID from the Registered event").
 */

const express = require('express');
const crypto = require('node:crypto');

const REGISTRATION_PATH = '/.well-known/agent-registration.json';
const REGISTRATION_TYPE = 'https://eips.ethereum.org/EIPS/eip-8004#registration-v1';

const NETWORK_LABEL = {
  'eip155:8453': 'Base',
  'eip155:42220': 'Celo',
  'eip155:5042': 'Arc',
};

const TOKEN_LABEL = { USDC: 'USDC', USDT: 'USDT', USAT: 'USA₮' };

/**
 * "eip155:42220:0x8004…a432:12345,eip155:11142220:0x8004…D9e:7" →
 * [{agentId: 12345, agentRegistry: "eip155:42220:0x8004…a432"}, …]
 * Malformed entries are dropped with a log line, never half-parsed.
 */
function parseRegistrations(raw) {
  const out = [];
  for (const item of String(raw || '').split(',').map((s) => s.trim()).filter(Boolean)) {
    const m = /^(eip155:\d+:0x[0-9a-fA-F]{40}):(\d+)$/.exec(item);
    if (!m) {
      console.warn(`[erc8004] ignoring malformed ERC8004_REGISTRATIONS entry "${item}"`);
      continue;
    }
    out.push({ agentId: Number(m[2]), agentRegistry: m[1] });
  }
  return out;
}

/**
 * @param {Object} opts
 * @param {string} opts.publicBaseUrl
 * @param {Array} opts.rails — createRailSet(...).summary()
 * @param {Array} [opts.registrations]
 * @param {string} [opts.image]
 */
function buildRegistration({ publicBaseUrl, rails = [], registrations = [], image = 'https://linkrra.com/favicon.svg' }) {
  const base = String(publicBaseUrl || 'https://pool.linkrra.com').replace(/\/$/, '');
  const live = rails.filter((r) => r.enabled && !r.testnet && r.payTo);

  const byNetwork = new Map();
  for (const r of live) {
    const label = NETWORK_LABEL[r.caip2] || r.caip2;
    if (!byNetwork.has(label)) byNetwork.set(label, []);
    const token = TOKEN_LABEL[r.symbol] || r.symbol || 'stablecoin';
    if (!byNetwork.get(label).includes(token)) byNetwork.get(label).push(token);
  }
  const payIn = [...byNetwork].map(([net, tokens]) => `${tokens.join('/')} on ${net}`).join(', ');

  const wallets = [];
  for (const r of live) {
    const endpoint = `${r.caip2}:${r.payTo}`;
    if (!wallets.some((w) => w.endpoint === endpoint)) wallets.push({ name: 'wallet', endpoint });
  }

  return {
    type: REGISTRATION_TYPE,
    name: 'Synap by Linkrra',
    description:
      'OpenAI-compatible LLM inference on open-weight models, served from GPUs Linkrra operates. ' +
      'An agent can buy a single chat completion, TTS clip or credit top-up with x402 — HTTP 402, sign a ' +
      'stablecoin authorization, retry — with no account and no API key' +
      (payIn ? `; payable in ${payIn}.` : '.') +
      ' Every settlement is re-read from the chain before anything is served or credited.',
    image,
    services: [
      { name: 'web', endpoint: `${base}/ai` },
      { name: 'A2A', endpoint: `${base}/.well-known/agent-card.json`, version: '1.0' },
      { name: 'MCP', endpoint: `${base}/mcp`, version: '2025-06-18' },
      { name: 'x402', endpoint: `${base}/api/billing/x402/chat/completions` },
      { name: 'x402', endpoint: `${base}/api/billing/x402/tts` },
      { name: 'x402', endpoint: `${base}/api/billing/x402/topup` },
      { name: 'x402-discovery', endpoint: `${base}/.well-known/x402` },
      ...wallets,
    ],
    x402Support: true,
    active: true,
    supportedTrust: ['reputation'],
    registrations,
  };
}

/**
 * @param {Object} opts — as buildRegistration; `rails` may be a function so
 *   the file follows the rail set without a restart-time snapshot.
 */
function createErc8004Router(opts = {}) {
  const router = express.Router();
  router.get(REGISTRATION_PATH, (req, res) => {
    const rails = typeof opts.rails === 'function' ? opts.rails() : opts.rails;
    const body = JSON.stringify(buildRegistration({ ...opts, rails }), null, 2);
    const etag = `"${crypto.createHash('sha256').update(body).digest('hex').slice(0, 32)}"`;
    res.set('Cache-Control', 'public, max-age=300');
    res.set('ETag', etag);
    res.set('Access-Control-Allow-Origin', '*');
    if (req.headers['if-none-match'] === etag) return res.status(304).end();
    return res.type('application/json').send(body);
  });
  return router;
}

module.exports = {
  createErc8004Router,
  buildRegistration,
  parseRegistrations,
  REGISTRATION_PATH,
  REGISTRATION_TYPE,
};
