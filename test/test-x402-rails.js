'use strict';

/**
 * T-954 (Celo) / T-952 (Arc) — one x402 door, several payment rails.
 *
 * The money properties a second and third chain put at risk, each asserted:
 *  1. With no extra rails, the 402 is exactly the pre-T-954 Base body.
 *  2. Each rail advertises its own chain, token and EIP-712 domain.
 *  3. A payment is verified, settled AND confirmed on the rail its payload
 *     names — that rail's facilitator, requirements, RPC, token, payTo — and
 *     never on another one. An unoffered chain or token is refused before any
 *     facilitator is called.
 *  4. Testnet rails, unknown tokens and broken seller-proof keys are disabled,
 *     with a reason, instead of quoting a price nobody can safely pay.
 *  5. Facilitator auth on the wire: Celo gets X-API-Key and no Bearer; Circle
 *     gets a seller proof over the exact bytes sent; a 401 from /settle credits
 *     nothing.
 *  6. Circle's `settlement_pending` is a 202 "retry the same header", never a
 *     402 that would invite a second signature (double charge).
 *  7. On-chain confirmation counts only the paid token's Transfer to our payTo:
 *     Arc's 18-decimal system log and Celo fee-currency logs never add up.
 *  8. The same transaction credits once.
 */

const test = require('node:test');
const assert = require('node:assert');
const express = require('express');
const http = require('node:http');

const {
  createX402Router, FacilitatorClient, confirmTransferOnChain, settleX402Payment,
} = require('../billing/x402');
const { createRailSet, extraRailsFromEnv } = require('../billing/x402-rails');
const { ARC_NATIVE_USDC_SYSTEM_EMITTER } = require('../billing/x402-networks');
const { recoverAddress, hashTypedData } = require('../lib/secp256k1');
const { SELLER_REQUEST_TYPES } = require('../billing/circle-seller-proof');
const { keccak256 } = require('../lib/evm-address');
const { CreditLedger } = require('../lib/credit-ledger');

const PAY_TO = '0x209693Bc6afc0C5328bA36FaF03C514EF312287C';
const PAYER = '0x857b06519E91e3A54538791bDbb0E22373e36b66';
const RATE = 0.1667;

const BASE_USDC = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
const CELO_USDC = '0xcebA9300f2b948710d2653dD7B07f33A8B32118C';
const CELO_USAT = '0xD2ab3C9A02DBBAB236BfEC45D1d755DF4267F771';
const ARC_USDC = '0x3600000000000000000000000000000000000000';

// Public anvil key #0 — used ONLY as a seller-proof key in tests. Never fund it.
const TEST_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
const TEST_ADDR = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';

function stubFacilitator(name, { transaction = `0x${name}tx`, settleResult = null } = {}) {
  const seen = { verify: [], settle: [] };
  return {
    name,
    seen,
    async verify(payload, requirements) { seen.verify.push({ payload, requirements }); return { isValid: true, payer: PAYER }; },
    async settle(payload, requirements) {
      seen.settle.push({ payload, requirements });
      return settleResult || { success: true, transaction, network: requirements.network, payer: PAYER };
    },
    async supported() { return { kinds: [] }; },
  };
}

function header(accepted, value) {
  return Buffer.from(JSON.stringify({
    x402Version: 2,
    accepted,
    payload: {
      signature: '0xsig',
      authorization: { from: PAYER, to: accepted.payTo, value, validAfter: '0', validBefore: '9999999999', nonce: '0xn' },
    },
  }), 'utf8').toString('base64');
}

function serve(router) {
  const app = express();
  app.use('/api/billing', router);
  const server = http.createServer(app);
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port })));
}
function stop(server) { server.closeAllConnections?.(); server.close(); }

async function call(port, path, { method = 'GET', body, headers = {} } = {}) {
  const res = await fetch(`http://127.0.0.1:${port}${path}`, {
    method, headers: { 'Content-Type': 'application/json', ...headers }, body: body ? JSON.stringify(body) : undefined,
  });
  return { status: res.status, body: await res.json().catch(() => null), headers: res.headers };
}

/** Production-shaped config: Base primary + Celo (USDC, USA₮) + Arc, injected facilitators. */
function multiRailConfig(facs, extra = {}) {
  return {
    payTo: PAY_TO,
    network: 'base',
    confirmOnChain: false,
    extraRails: [
      { network: 'celo', asset: 'USDC', payTo: PAY_TO, facilitator: facs.celo },
      { network: 'celo', asset: 'USAT', payTo: PAY_TO, facilitator: facs.celo },
      { network: 'arc', asset: 'USDC', payTo: PAY_TO, facilitator: facs.arc },
    ],
    ...extra,
  };
}

test('1. no extra rails: the topup 402 is the exact pre-T-954 Base body', async () => {
  const ledger = new CreditLedger(':memory:');
  const { server, port } = await serve(createX402Router({
    creditLedger: ledger, pricePerMillion: RATE, facilitator: stubFacilitator('base'),
    config: { payTo: PAY_TO, network: 'base', confirmOnChain: false },
  }));
  const res = await call(port, '/api/billing/x402/topup', { method: 'POST', body: { amountUsd: 5 } });
  assert.strictEqual(res.status, 402);
  assert.deepStrictEqual(res.body.accepts, [{
    scheme: 'exact', network: 'eip155:8453', amount: '5000000', asset: BASE_USDC, payTo: PAY_TO,
    maxTimeoutSeconds: 120, extra: { name: 'USD Coin', version: '2' },
  }]);
  const info = await call(port, '/api/billing/x402/info');
  assert.strictEqual(info.body.additionalNetworks, undefined, 'no new /info field unless a rail is configured');
  stop(server); ledger.close();
});

test('2. multi-rail 402 lists Base first, then Celo USDC, Celo USA₮ and Arc — each with its own domain', async () => {
  const facs = { celo: stubFacilitator('celo'), arc: stubFacilitator('arc') };
  const ledger = new CreditLedger(':memory:');
  const { server, port } = await serve(createX402Router({
    creditLedger: ledger, pricePerMillion: RATE, facilitator: stubFacilitator('base'), config: multiRailConfig(facs),
  }));
  const res = await call(port, '/api/billing/x402/topup', { method: 'POST', body: { amountUsd: 2 } });
  assert.strictEqual(res.status, 402);
  const view = res.body.accepts.map((a) => [a.network, a.asset, a.extra.name, a.extra.version, a.amount]);
  assert.deepStrictEqual(view, [
    ['eip155:8453', BASE_USDC, 'USD Coin', '2', '2000000'],
    ['eip155:42220', CELO_USDC, 'USDC', '2', '2000000'],
    ['eip155:42220', CELO_USAT, 'Tether America USD', '1', '2000000'],
    ['eip155:5042', ARC_USDC, 'USDC', '2', '2000000'],
  ]);
  assert.strictEqual(res.body.accepts[0].extra.assetTransferMethod, undefined, 'Base entry unchanged');
  assert.strictEqual(res.body.accepts[3].extra.assetTransferMethod, 'eip3009', 'Circle schema wants it');
  const decoded = JSON.parse(Buffer.from(res.headers.get('payment-required'), 'base64').toString('utf8'));
  assert.deepStrictEqual(decoded.accepts, res.body.accepts, 'PAYMENT-REQUIRED header carries the same rails');

  const info = await call(port, '/api/billing/x402/info');
  assert.strictEqual(info.body.network, 'base', 'top-level /info still describes the primary');
  assert.deepStrictEqual(info.body.additionalNetworks.map((r) => [r.caip2, r.symbol, r.enabled]), [
    ['eip155:42220', 'USDC', true], ['eip155:42220', 'USAT', true], ['eip155:5042', 'USDC', true],
  ]);
  assert.ok(!JSON.stringify(info.body).includes('apiKey'), 'no secret-shaped field in /info');
  stop(server); ledger.close();
});

test('3a. a Celo USA₮ topup is verified + settled by the Celo facilitator only, on Celo terms', async () => {
  const facs = { celo: stubFacilitator('celo'), arc: stubFacilitator('arc') };
  const base = stubFacilitator('base');
  const confirms = [];
  const ledger = new CreditLedger(':memory:');
  const { server, port } = await serve(createX402Router({
    creditLedger: ledger, pricePerMillion: RATE, facilitator: base,
    config: multiRailConfig(facs, { confirmOnChain: true }),
    confirmTransferOnChain: async (args) => { confirms.push(args); return { ok: true, receivedAtomic: 3000000n }; },
  }));
  const accepted = { scheme: 'exact', network: 'eip155:42220', amount: '3000000', asset: CELO_USAT, payTo: PAY_TO, maxTimeoutSeconds: 120, extra: { name: 'Tether America USD', version: '1' } };
  const res = await call(port, '/api/billing/x402/topup', {
    method: 'POST', body: { amountUsd: 3 }, headers: { 'PAYMENT-SIGNATURE': header(accepted, '3000000') },
  });
  assert.strictEqual(res.status, 200, JSON.stringify(res.body));
  assert.strictEqual(res.body.network, 'eip155:42220');
  assert.strictEqual(base.seen.verify.length + facs.arc.seen.verify.length, 0, 'no other facilitator touched');
  assert.strictEqual(facs.celo.seen.settle.length, 1);
  const reqs = facs.celo.seen.settle[0].requirements;
  assert.deepStrictEqual([reqs.network, reqs.asset, reqs.extra.name], ['eip155:42220', CELO_USAT, 'Tether America USD']);
  assert.deepStrictEqual(confirms, [{ rpcUrl: 'https://forno.celo.org', txHash: '0xcelotx', asset: CELO_USAT, payTo: PAY_TO }]);
  assert.strictEqual(ledger.getBalance(PAYER).balance, Math.floor((3 / RATE) * 1_000_000));
  stop(server); ledger.close();
});

test('3b. an Arc payment settles through the Arc (Circle) facilitator; Base still settles on Base', async () => {
  const facs = { celo: stubFacilitator('celo'), arc: stubFacilitator('arc') };
  const base = stubFacilitator('base');
  const ledger = new CreditLedger(':memory:');
  const { server, port } = await serve(createX402Router({
    creditLedger: ledger, pricePerMillion: RATE, facilitator: base, config: multiRailConfig(facs),
  }));
  const arc = { scheme: 'exact', network: 'eip155:5042', amount: '1000000', asset: ARC_USDC, payTo: PAY_TO, maxTimeoutSeconds: 120, extra: { name: 'USDC', version: '2' } };
  const r1 = await call(port, '/api/billing/x402/topup', { method: 'POST', body: { amountUsd: 1 }, headers: { 'PAYMENT-SIGNATURE': header(arc, '1000000') } });
  assert.strictEqual(r1.status, 200, JSON.stringify(r1.body));
  assert.strictEqual(facs.arc.seen.settle.length, 1);
  const baseAcc = { scheme: 'exact', network: 'eip155:8453', amount: '1000000', asset: BASE_USDC, payTo: PAY_TO, maxTimeoutSeconds: 120, extra: { name: 'USD Coin', version: '2' } };
  const r2 = await call(port, '/api/billing/x402/topup', { method: 'POST', body: { amountUsd: 1 }, headers: { 'PAYMENT-SIGNATURE': header(baseAcc, '1000000') } });
  assert.strictEqual(r2.status, 200, JSON.stringify(r2.body));
  assert.strictEqual(base.seen.settle.length, 1);
  assert.strictEqual(facs.celo.seen.verify.length, 0);
  stop(server); ledger.close();
});

test('3c. an unoffered chain or token is refused with a 402 before ANY facilitator call', async () => {
  const facs = { celo: stubFacilitator('celo'), arc: stubFacilitator('arc') };
  const base = stubFacilitator('base');
  const ledger = new CreditLedger(':memory:');
  const { server, port } = await serve(createX402Router({
    creditLedger: ledger, pricePerMillion: RATE, facilitator: base, config: multiRailConfig(facs),
  }));
  const polygon = { scheme: 'exact', network: 'eip155:137', amount: '1000000', asset: '0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359', payTo: PAY_TO };
  const r1 = await call(port, '/api/billing/x402/topup', { method: 'POST', body: { amountUsd: 1 }, headers: { 'PAYMENT-SIGNATURE': header(polygon, '1000000') } });
  assert.strictEqual(r1.status, 402);
  assert.match(r1.body.error, /eip155:137.*not accepted/);
  // USDT is a real Celo token in the registry, but this deployment did not offer it.
  const usdt = { scheme: 'exact', network: 'eip155:42220', amount: '1000000', asset: '0x48065fbBE25f71C9282ddf5e1cD6D6A887483D5e', payTo: PAY_TO };
  const r2 = await call(port, '/api/billing/x402/topup', { method: 'POST', body: { amountUsd: 1 }, headers: { 'PAYMENT-SIGNATURE': header(usdt, '1000000') } });
  assert.strictEqual(r2.status, 402);
  assert.match(r2.body.error, /not accepted on "eip155:42220"/);
  for (const f of [base, facs.celo, facs.arc]) assert.strictEqual(f.seen.verify.length, 0);
  assert.strictEqual(ledger.getBalance(PAYER).balance, 0);
  stop(server); ledger.close();
});

test('4. testnet rails, unknown tokens and a wrong seller-proof key are disabled with a reason', () => {
  const set = createRailSet({
    payTo: PAY_TO, network: 'base',
    extraRails: [
      { network: 'celo-sepolia', payTo: PAY_TO },
      { network: 'eip155:5042002', payTo: PAY_TO }, // Arc testnet by CAIP-2 only
      { network: 'celo-sepolia', asset: 'USDC', payTo: PAY_TO, allowTestnetCredit: true, rpcUrl: 'http://x' },
      { network: 'celo', asset: 'DAI', payTo: PAY_TO },
      { network: 'celo', asset: '0x0000000000000000000000000000000000000001', payTo: PAY_TO },
      { network: 'arc', payTo: PAY_TO, sellerProofKey: TEST_KEY }, // key controls a different address
      { network: 'arc', payTo: PAY_TO }, // same chain + token as the line above: dropped
    ],
  });
  assert.strictEqual(set.rails.length, 6, 'a repeated chain+token is dropped, the first one wins');
  const [, sepolia, arcTest, dai, unknown, badKey] = set.rails;
  assert.match(sepolia.disabledReason, /testnet/);
  assert.match(arcTest.disabledReason, /testnet/);
  assert.match(dai.disabledReason, /no DAI contract known/);
  assert.match(unknown.disabledReason, /no EIP-712 domain known/);
  assert.match(badKey.disabledReason, /seller-proof key rejected/);
  assert.strictEqual(set.accepts(1).length, 1, 'only the primary is quoted');
  assert.deepStrictEqual(set.select({ accepted: { network: 'eip155:11142220' } }).error !== undefined, true);
});

test('5a. Celo facilitator auth: X-API-Key header, no Bearer; a 401 on /settle credits nothing', async () => {
  const seen = [];
  const fake = http.createServer((req, res) => {
    let raw = '';
    req.on('data', (c) => { raw += c; });
    req.on('end', () => {
      seen.push({ path: req.url, headers: req.headers, raw });
      if (req.url === '/verify') { res.writeHead(200, { 'content-type': 'application/json' }); return res.end(JSON.stringify({ isValid: true, payer: PAYER })); }
      res.writeHead(401, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Missing X-API-Key' }));
    });
  });
  await new Promise((r) => fake.listen(0, '127.0.0.1', r));
  const url = `http://127.0.0.1:${fake.address().port}`;
  const ledger = new CreditLedger(':memory:');
  const { server, port } = await serve(createX402Router({
    creditLedger: ledger, pricePerMillion: RATE, facilitator: stubFacilitator('base'),
    config: {
      payTo: PAY_TO, network: 'base', confirmOnChain: false,
      extraRails: [{ network: 'celo', payTo: PAY_TO, facilitatorUrl: url, facilitatorApiKey: 'celo-key-123', facilitatorApiKeyHeader: 'X-API-Key' }],
    },
  }));
  const accepted = { scheme: 'exact', network: 'eip155:42220', amount: '1000000', asset: CELO_USDC, payTo: PAY_TO };
  const res = await call(port, '/api/billing/x402/topup', { method: 'POST', body: { amountUsd: 1 }, headers: { 'PAYMENT-SIGNATURE': header(accepted, '1000000') } });
  assert.strictEqual(res.status, 502, 'a refused settlement is an outage, never a credit');
  assert.strictEqual(ledger.getBalance(PAYER).balance, 0);
  assert.deepStrictEqual(seen.map((s) => s.path), ['/verify', '/settle']);
  for (const s of seen) {
    assert.strictEqual(s.headers['x-api-key'], 'celo-key-123');
    assert.strictEqual(s.headers.authorization, undefined);
  }
  stop(server); ledger.close(); fake.closeAllConnections?.(); fake.close();
});

test('5a2. Celo answers a rejected verify with HTTP 400 + a verdict: that is a 402 with the reason, not a 502', async () => {
  // Shape measured live on api.x402.celo.org, 2026-10-17 (ops/x402-rail-probe.js).
  const fake = http.createServer((req, res) => {
    req.resume();
    req.on('end', () => {
      if (req.url === '/verify') {
        res.writeHead(400, { 'content-type': 'application/json' });
        return res.end(JSON.stringify({ isValid: false, invalidReason: 'insufficient_funds', payer: PAYER }));
      }
      // A POSITIVE answer under an error status must never be believed.
      res.writeHead(500, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ success: true, transaction: '0xlie', network: 'eip155:42220' }));
    });
  });
  await new Promise((r) => fake.listen(0, '127.0.0.1', r));
  const fac = new FacilitatorClient({ baseUrl: `http://127.0.0.1:${fake.address().port}` });
  assert.deepStrictEqual(await fac.verify({}, {}), { isValid: false, invalidReason: 'insufficient_funds', payer: PAYER });
  await assert.rejects(() => fac.settle({}, {}), /facilitator \/settle 500/);

  const ledger = new CreditLedger(':memory:');
  const { server, port } = await serve(createX402Router({
    creditLedger: ledger, pricePerMillion: RATE, facilitator: stubFacilitator('base'),
    config: { payTo: PAY_TO, network: 'base', confirmOnChain: false, extraRails: [{ network: 'celo', payTo: PAY_TO, facilitator: fac }] },
  }));
  const accepted = { scheme: 'exact', network: 'eip155:42220', amount: '1000000', asset: CELO_USDC, payTo: PAY_TO };
  const res = await call(port, '/api/billing/x402/topup', { method: 'POST', body: { amountUsd: 1 }, headers: { 'PAYMENT-SIGNATURE': header(accepted, '1000000') } });
  assert.strictEqual(res.status, 402);
  assert.strictEqual(res.body.error, 'insufficient_funds');
  stop(server); ledger.close(); fake.closeAllConnections?.(); fake.close();
});

test('5b. the Celo default header comes from the registry when the facilitator URL is Celo\'s own', () => {
  const set = createRailSet({ payTo: PAY_TO, network: 'base', extraRails: [{ network: 'celo', payTo: PAY_TO, facilitatorApiKey: 'k' }] });
  const fac = set.rails[1].facilitator;
  assert.ok(fac instanceof FacilitatorClient);
  assert.strictEqual(fac.baseUrl, 'https://api.x402.celo.org');
  assert.strictEqual(fac.apiKeyHeader, 'X-API-Key');
  const arc = createRailSet({ payTo: PAY_TO, network: 'base', extraRails: [{ network: 'arc', payTo: PAY_TO, facilitatorApiKey: 'circle-key' }] });
  assert.strictEqual(arc.rails[1].facilitator.baseUrl, 'https://api.circle.com/v1/facilitator/x402');
  assert.strictEqual(arc.rails[1].facilitator.apiKeyHeader, null, 'Circle API key goes as Bearer');
  assert.deepStrictEqual(arc.rails[1].facilitator._headersFor('POST', '/settle', '{}', {}), { Authorization: 'Bearer circle-key' });
});

test('5c. Circle keyless trial: every verify/settle carries a seller proof over the exact bytes sent', async () => {
  const seen = [];
  const fake = http.createServer((req, res) => {
    let raw = '';
    req.on('data', (c) => { raw += c; });
    req.on('end', () => {
      seen.push({ path: req.url, headers: req.headers, raw });
      res.writeHead(200, { 'content-type': 'application/json' });
      if (req.url.endsWith('/verify')) return res.end(JSON.stringify({ isValid: true, payer: PAYER }));
      return res.end(JSON.stringify({ success: true, transaction: '0xarcproof', network: 'eip155:5042', payer: PAYER }));
    });
  });
  await new Promise((r) => fake.listen(0, '127.0.0.1', r));
  const url = `http://127.0.0.1:${fake.address().port}/v1/facilitator/x402`;
  const ledger = new CreditLedger(':memory:');
  const { server, port } = await serve(createX402Router({
    creditLedger: ledger, pricePerMillion: RATE, facilitator: stubFacilitator('base'),
    config: {
      payTo: PAY_TO, network: 'base', confirmOnChain: false,
      extraRails: [{ network: 'arc', payTo: TEST_ADDR, facilitatorUrl: url, sellerProofKey: TEST_KEY }],
    },
  }));
  const accepted = { scheme: 'exact', network: 'eip155:5042', amount: '1000000', asset: ARC_USDC, payTo: TEST_ADDR };
  const res = await call(port, '/api/billing/x402/topup', { method: 'POST', body: { amountUsd: 1 }, headers: { 'PAYMENT-SIGNATURE': header(accepted, '1000000') } });
  assert.strictEqual(res.status, 200, JSON.stringify(res.body));
  assert.deepStrictEqual(seen.map((s) => s.path), ['/v1/facilitator/x402/verify', '/v1/facilitator/x402/settle']);
  for (const s of seen) {
    assert.strictEqual(s.headers.authorization, undefined);
    const env = JSON.parse(Buffer.from(s.headers['facilitator-seller-proof'], 'base64url').toString('utf8'));
    assert.strictEqual(env.network, 'eip155:5042');
    assert.strictEqual(env.payTo.toLowerCase(), TEST_ADDR.toLowerCase());
    const purpose = s.path.endsWith('/verify') ? 'verify' : 'settle';
    const digest = hashTypedData({
      domain: { name: 'Circle Facilitator Seller Request', version: '1', chainId: 5042 },
      types: SELLER_REQUEST_TYPES,
      primaryType: 'SellerRequest',
      message: { purpose, method: 'POST', bodyHash: '0x' + keccak256(s.raw), network: env.network, payTo: env.payTo, nonce: env.nonce, issuedAt: env.issuedAt, expiresAt: env.expiresAt },
    });
    assert.strictEqual(recoverAddress(digest, env.signature), TEST_ADDR.toLowerCase(),
      `${purpose}: proof must sign the very bytes the facilitator received`);
  }
  assert.notStrictEqual(
    JSON.parse(Buffer.from(seen[0].headers['facilitator-seller-proof'], 'base64url')).nonce,
    JSON.parse(Buffer.from(seen[1].headers['facilitator-seller-proof'], 'base64url')).nonce,
    'a nonce is unique across purposes (Circle rule)',
  );
  stop(server); ledger.close(); fake.closeAllConnections?.(); fake.close();
});

test('6. settlement_pending is a 202 "retry the same header" — never a 402, never a credit', async () => {
  const pendingFac = stubFacilitator('arc', {
    settleResult: {
      success: false, errorReason: 'settlement_pending', transaction: '', network: 'eip155:5042', payer: PAYER,
      extensions: { 'settlement-status': { status: 'pending', paymentId: 'pay-123' } },
    },
  });
  const ledger = new CreditLedger(':memory:');
  const { server, port } = await serve(createX402Router({
    creditLedger: ledger, pricePerMillion: RATE, facilitator: stubFacilitator('base'),
    config: { payTo: PAY_TO, network: 'base', confirmOnChain: false, extraRails: [{ network: 'arc', payTo: PAY_TO, facilitator: pendingFac }] },
  }));
  const accepted = { scheme: 'exact', network: 'eip155:5042', amount: '1000000', asset: ARC_USDC, payTo: PAY_TO };
  const res = await call(port, '/api/billing/x402/topup', { method: 'POST', body: { amountUsd: 1 }, headers: { 'PAYMENT-SIGNATURE': header(accepted, '1000000') } });
  assert.strictEqual(res.status, 202);
  assert.strictEqual(res.body.paymentId, 'pay-123');
  assert.match(res.body.error, /SAME PAYMENT-SIGNATURE/);
  assert.strictEqual(res.headers.get('payment-required'), null, 'no fresh challenge to sign against');
  assert.strictEqual(ledger.getBalance(PAYER).balance, 0);
  stop(server); ledger.close();

  // The shared pipeline (inference / tts / byok / pearl doors) behaves the same.
  const out = await settleX402Payment({
    facilitator: pendingFac, payload: { payload: { authorization: { value: '1' } } }, requirements: {},
    confirmOnChain: false, network: 'arc', fallbackUsd: 1, buildPaymentRequiredBody: (e) => ({ error: e }),
  });
  assert.deepStrictEqual([out.ok, out.status, out.isPaymentRequired], [false, 202, false]);
});

function receiptFetch(logs) {
  return async () => ({ ok: true, json: async () => ({ result: { status: '0x1', logs } }) });
}
const TRANSFER = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';
const topic = (addr) => '0x' + addr.slice(2).toLowerCase().padStart(64, '0');
const word = (n) => '0x' + BigInt(n).toString(16).padStart(64, '0');

test('7a. Arc: the 18-decimal system Transfer log for the same move is never counted', async () => {
  const out = await confirmTransferOnChain({
    rpcUrl: 'x', txHash: '0x1', asset: ARC_USDC, payTo: PAY_TO,
    fetchImpl: receiptFetch([
      { address: ARC_USDC, topics: [TRANSFER, topic(PAYER), topic(PAY_TO)], data: word(1_000_000) },
      { address: ARC_NATIVE_USDC_SYSTEM_EMITTER, topics: [TRANSFER, topic(PAYER), topic(PAY_TO)], data: word(10n ** 18n) },
    ]),
  });
  assert.deepStrictEqual(out, { ok: true, receivedAtomic: 1_000_000n }, 'exactly $1, not $1 + 10^12');
});

test('7b. Celo: fee-currency debit/refund logs and other recipients never add to what we received', async () => {
  const feeRecipient = '0x' + 'fe'.repeat(20);
  const facilitatorEoa = '0x0d74D5Cefd2e7F24E623330ebE3d8D4cB45fFB48';
  const out = await confirmTransferOnChain({
    rpcUrl: 'x', txHash: '0x2', asset: CELO_USAT, payTo: PAY_TO,
    fetchImpl: receiptFetch([
      { address: CELO_USAT, topics: [TRANSFER, topic(facilitatorEoa), topic(feeRecipient)], data: word(900) },
      { address: CELO_USAT, topics: [TRANSFER, topic(PAYER), topic(PAY_TO)], data: word(250_000) },
      { address: CELO_USDC, topics: [TRANSFER, topic(PAYER), topic(PAY_TO)], data: word(5_000_000) }, // wrong token
      { address: CELO_USAT, topics: [TRANSFER, topic(feeRecipient), topic(facilitatorEoa)], data: word(400) },
    ]),
  });
  assert.deepStrictEqual(out, { ok: true, receivedAtomic: 250_000n });
});

test('8. the same Celo transaction credits once, even when replayed', async () => {
  const facs = { celo: stubFacilitator('celo', { transaction: '0xsame' }), arc: stubFacilitator('arc') };
  const ledger = new CreditLedger(':memory:');
  const { server, port } = await serve(createX402Router({
    creditLedger: ledger, pricePerMillion: RATE, facilitator: stubFacilitator('base'), config: multiRailConfig(facs),
  }));
  const accepted = { scheme: 'exact', network: 'eip155:42220', amount: '1000000', asset: CELO_USDC, payTo: PAY_TO };
  const h = { 'PAYMENT-SIGNATURE': header(accepted, '1000000') };
  const a = await call(port, '/api/billing/x402/topup', { method: 'POST', body: { amountUsd: 1 }, headers: h });
  const b = await call(port, '/api/billing/x402/topup', { method: 'POST', body: { amountUsd: 1 }, headers: h });
  assert.strictEqual(a.body.alreadyApplied, false);
  assert.strictEqual(b.body.alreadyApplied, true);
  assert.strictEqual(ledger.getBalance(PAYER).balance, Math.floor((1 / RATE) * 1_000_000));
  stop(server); ledger.close();
});

test('10. env parsing: nothing set means no extra rails; names map to prefixed keys', () => {
  assert.deepStrictEqual(extraRailsFromEnv({}, { payTo: PAY_TO }), []);
  const rails = extraRailsFromEnv({
    X402_EXTRA_NETWORKS: 'celo, arc-testnet',
    X402_CELO_ASSETS: 'USDC,USAT',
    X402_CELO_FACILITATOR_API_KEY: 'k1',
    X402_ARC_TESTNET_PAY_TO: TEST_ADDR,
    X402_ARC_TESTNET_SELLER_PROOF_KEY: TEST_KEY,
    X402_ARC_TESTNET_ALLOW_TESTNET_CREDIT: '1',
  }, { payTo: PAY_TO });
  assert.deepStrictEqual(rails.map((r) => [r.network, r.asset, r.payTo, r.facilitatorApiKey, r.allowTestnetCredit, !!r.sellerProofKey]), [
    ['celo', 'USDC', PAY_TO, 'k1', false, false],
    ['celo', 'USAT', PAY_TO, 'k1', false, false],
    ['arc-testnet', 'USDC', TEST_ADDR, null, true, true],
  ]);
  const set = createRailSet({ payTo: PAY_TO, network: 'base', extraRails: rails });
  assert.deepStrictEqual(set.rails.map((r) => [r.caip2, r.enabled]), [
    ['eip155:8453', true], ['eip155:42220', true], ['eip155:42220', true], ['eip155:5042002', true],
  ]);
});
