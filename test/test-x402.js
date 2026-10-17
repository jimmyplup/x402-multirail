'use strict';

/**
 * x402 — the agent payment path.
 *
 * The properties that matter here are the ones money depends on: credits are
 * granted ONLY against a settled transaction hash, the same hash can never
 * grant twice, and a rejected authorization leaves the ledger untouched. The
 * facilitator is stubbed so those properties are tested rather than the
 * network.
 */

const test = require('node:test');
const assert = require('node:assert');
const express = require('express');
const http = require('node:http');

const { createX402Router, usdToAtomic, atomicToUsd, decodePaymentHeader } = require('../billing/x402');
const { CreditLedger } = require('../lib/credit-ledger');

const PAY_TO = '0x209693Bc6afc0C5328bA36FaF03C514EF312287C';
const PAYER = '0x857b06519E91e3A54538791bDbb0E22373e36b66';
const RATE = 0.1667; // $/M tokens — the derived rate, passed in like production does

/** Shapes the v2 PaymentPayload a real x402 client sends in the
 * PAYMENT-SIGNATURE header (v1 called it X-PAYMENT) — see spec §5.2.1 and
 * transports-v2/http.md. The router only reads `.payload.authorization`, but
 * this mirrors what an echoing client actually produces (`accepted` replaces
 * the old top-level scheme/network, `resource`/`extensions` are echoed back). */
function paymentHeader({ value }) {
  return Buffer.from(JSON.stringify({
    x402Version: 2,
    resource: { url: 'https://pool.linkrra.com/api/billing/x402/topup' },
    accepted: {
      scheme: 'exact',
      network: 'eip155:84532',
      amount: value,
      asset: '0x036CbD53842c5426634e7929541eC2318f3dCF7e',
      payTo: PAY_TO,
      maxTimeoutSeconds: 120,
      extra: { name: 'USDC', version: '2' },
    },
    payload: {
      signature: '0xsig',
      authorization: {
        from: PAYER,
        to: PAY_TO,
        value,
        validAfter: '1740672089',
        validBefore: '1740672154',
        nonce: '0xnonce',
      },
    },
    extensions: {},
  }), 'utf8').toString('base64');
}

/** A facilitator we control, so verify/settle outcomes are inputs to the test. */
function stubFacilitator({ isValid = true, success = true, transaction = '0xtxdeadbeef' } = {}) {
  const calls = { verify: 0, settle: 0 };
  return {
    calls,
    async verify() { calls.verify++; return { isValid, payer: PAYER, invalidReason: isValid ? undefined : 'insufficient_funds' }; },
    async settle() {
      calls.settle++;
      return success
        ? { success: true, transaction, network: 'base-sepolia', payer: PAYER }
        : { success: false, errorReason: 'settlement_failed', transaction: '', network: 'base-sepolia', payer: PAYER };
    },
  };
}

function stopServer(server) {
  /* undici's connection pool keeps sockets alive, which keeps node --test
   * waiting on an open handle instead of exiting. Drop them explicitly. */
  server.closeAllConnections?.();
  server.close();
}

function startServer(routerDeps) {
  const app = express();
  app.use('/api/billing', createX402Router(routerDeps));
  const server = http.createServer(app);
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port }));
  });
}

async function call(port, path, { method = 'GET', body, headers = {} } = {}) {
  const res = await fetch(`http://127.0.0.1:${port}${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', ...headers },
    body: body ? JSON.stringify(body) : undefined,
  });
  return { status: res.status, body: await res.json().catch(() => null), headers: res.headers };
}

test('x402', async (t) => {
  await t.test('usd <-> atomic units round-trips at USDC 6dp', () => {
    assert.strictEqual(usdToAtomic(1), '1000000');
    assert.strictEqual(usdToAtomic(0.01), '10000');
    assert.strictEqual(atomicToUsd('25000000'), 25);
  });

  await t.test('decodes a base64 PAYMENT-SIGNATURE header', () => {
    const decoded = decodePaymentHeader(paymentHeader({ value: '1000000' }));
    assert.strictEqual(decoded.accepted.scheme, 'exact');
    assert.strictEqual(decoded.payload.authorization.from, PAYER);
  });

  await t.test('unconfigured: info says why, topup refuses', async () => {
    const ledger = new CreditLedger(':memory:');
    const { server, port } = await startServer({
      creditLedger: ledger,
      pricePerMillion: RATE,
      config: {}, // no payTo
      facilitator: stubFacilitator(),
    });

    const info = await call(port, '/api/billing/x402/info');
    assert.strictEqual(info.body.enabled, false);
    assert.match(info.body.reason, /X402_PAY_TO/);

    const topup = await call(port, '/api/billing/x402/topup', { method: 'POST', body: { amountUsd: 5 } });
    assert.strictEqual(topup.status, 503);

    stopServer(server); ledger.close();
  });

  await t.test('no PAYMENT-SIGNATURE header returns a 402 with usable requirements, in the header AND the body', async () => {
    const ledger = new CreditLedger(':memory:');
    const { server, port } = await startServer({
      creditLedger: ledger,
      pricePerMillion: RATE,
      config: { payTo: PAY_TO, network: 'base-sepolia', allowTestnetCredit: true, confirmOnChain: false },
      facilitator: stubFacilitator(),
    });

    const res = await call(port, '/api/billing/x402/topup', { method: 'POST', body: { amountUsd: 5 } });
    assert.strictEqual(res.status, 402);
    assert.strictEqual(res.body.x402Version, 2);
    assert.ok(res.body.resource?.url, 'v2 carries a top-level resource object');
    assert.ok(res.body.extensions?.bazaar, 'v2 declares the Bazaar discovery extension');
    const req0 = res.body.accepts[0];
    assert.strictEqual(req0.scheme, 'exact');
    assert.strictEqual(req0.network, 'eip155:84532', 'network is CAIP-2 in v2, not the alias');
    assert.strictEqual(req0.payTo, PAY_TO);
    assert.strictEqual(req0.amount, '5000000'); // $5 at 6dp
    assert.ok(req0.asset, 'a USDC contract must be named');

    /* The CDP Bazaar validator reads ONLY the PAYMENT-REQUIRED header, not the
     * body — v2's HTTP transport moves all protocol data into headers. */
    const headerRaw = res.headers.get('payment-required');
    assert.ok(headerRaw, 'PAYMENT-REQUIRED header must be present — the v2 transport, not just the body');
    const decoded = JSON.parse(Buffer.from(headerRaw, 'base64').toString('utf8'));
    assert.deepStrictEqual(decoded, res.body, 'the header carries the same PaymentRequired object as the body');

    stopServer(server); ledger.close();
  });

  await t.test('settled payment credits the payer wallet, priced at the shared rate', async () => {
    const ledger = new CreditLedger(':memory:');
    const fac = stubFacilitator();
    const { server, port } = await startServer({
      creditLedger: ledger,
      pricePerMillion: RATE,
      config: { payTo: PAY_TO, network: 'base-sepolia', allowTestnetCredit: true, confirmOnChain: false },
      facilitator: fac,
    });

    const res = await call(port, '/api/billing/x402/topup', {
      method: 'POST',
      body: { amountUsd: 5 },
      headers: { 'PAYMENT-SIGNATURE': paymentHeader({ value: '5000000' }) },
    });

    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.ok, true);
    assert.strictEqual(res.body.address, PAYER, 'the wallet IS the account');
    assert.strictEqual(res.body.credits, Math.floor((5 / RATE) * 1e6));
    assert.strictEqual(res.body.transaction, '0xtxdeadbeef');
    assert.ok(res.headers.get('payment-response'), 'settlement receipt travels back in the PAYMENT-RESPONSE header (v2)');
    assert.strictEqual(ledger.getBalance(PAYER).balance, res.body.credits);
    assert.strictEqual(fac.calls.verify, 1);
    assert.strictEqual(fac.calls.settle, 1);

    stopServer(server); ledger.close();
  });

  await t.test('the same transaction cannot credit twice', async () => {
    const ledger = new CreditLedger(':memory:');
    const { server, port } = await startServer({
      creditLedger: ledger,
      pricePerMillion: RATE,
      config: { payTo: PAY_TO, network: 'base-sepolia', allowTestnetCredit: true, confirmOnChain: false },
      facilitator: stubFacilitator({ transaction: '0xsamehash' }),
    });

    const hdr = { 'PAYMENT-SIGNATURE': paymentHeader({ value: '5000000' }) };
    const first = await call(port, '/api/billing/x402/topup', { method: 'POST', body: { amountUsd: 5 }, headers: hdr });
    const second = await call(port, '/api/billing/x402/topup', { method: 'POST', body: { amountUsd: 5 }, headers: hdr });

    assert.strictEqual(first.body.alreadyApplied, false);
    assert.strictEqual(second.body.alreadyApplied, true);
    assert.strictEqual(
      ledger.getBalance(PAYER).balance,
      first.body.credits,
      'a replayed header must not mint a second batch',
    );

    stopServer(server); ledger.close();
  });

  await t.test('rejected authorization credits nothing', async () => {
    const ledger = new CreditLedger(':memory:');
    const fac = stubFacilitator({ isValid: false });
    const { server, port } = await startServer({
      creditLedger: ledger,
      pricePerMillion: RATE,
      config: { payTo: PAY_TO, network: 'base-sepolia', allowTestnetCredit: true, confirmOnChain: false },
      facilitator: fac,
    });

    const res = await call(port, '/api/billing/x402/topup', {
      method: 'POST',
      body: { amountUsd: 5 },
      headers: { 'PAYMENT-SIGNATURE': paymentHeader({ value: '5000000' }) },
    });

    assert.strictEqual(res.status, 402);
    assert.match(res.body.error, /insufficient_funds/);
    assert.strictEqual(fac.calls.settle, 0, 'never settle what did not verify');
    assert.strictEqual(ledger.getBalance(PAYER).balance, 0);

    stopServer(server); ledger.close();
  });

  await t.test('failed settlement credits nothing', async () => {
    const ledger = new CreditLedger(':memory:');
    const { server, port } = await startServer({
      creditLedger: ledger,
      pricePerMillion: RATE,
      config: { payTo: PAY_TO, network: 'base-sepolia', allowTestnetCredit: true, confirmOnChain: false },
      facilitator: stubFacilitator({ success: false }),
    });

    const res = await call(port, '/api/billing/x402/topup', {
      method: 'POST',
      body: { amountUsd: 5 },
      headers: { 'PAYMENT-SIGNATURE': paymentHeader({ value: '5000000' }) },
    });

    assert.strictEqual(res.status, 402);
    assert.strictEqual(ledger.getBalance(PAYER).balance, 0);

    stopServer(server); ledger.close();
  });

  await t.test('credits follow the authorized amount, not the requested one', async () => {
    const ledger = new CreditLedger(':memory:');
    const { server, port } = await startServer({
      creditLedger: ledger,
      pricePerMillion: RATE,
      config: { payTo: PAY_TO, network: 'base-sepolia', allowTestnetCredit: true, confirmOnChain: false },
      facilitator: stubFacilitator({ transaction: '0xunderpaid' }),
    });

    // Asks for $5, authorizes $1. The chain is the source of truth.
    const res = await call(port, '/api/billing/x402/topup', {
      method: 'POST',
      body: { amountUsd: 5 },
      headers: { 'PAYMENT-SIGNATURE': paymentHeader({ value: '1000000' }) },
    });

    assert.strictEqual(res.body.amountUsd, 1);
    assert.strictEqual(res.body.credits, Math.floor((1 / RATE) * 1e6));

    stopServer(server); ledger.close();
  });

  await t.test('amount bounds are enforced before any facilitator call', async () => {
    const ledger = new CreditLedger(':memory:');
    const fac = stubFacilitator();
    const { server, port } = await startServer({
      creditLedger: ledger,
      pricePerMillion: RATE,
      config: { payTo: PAY_TO, network: 'base-sepolia', allowTestnetCredit: true, minUsd: 1, maxUsd: 100 },
      facilitator: fac,
    });

    const low = await call(port, '/api/billing/x402/topup', { method: 'POST', body: { amountUsd: 0.5 } });
    const high = await call(port, '/api/billing/x402/topup', { method: 'POST', body: { amountUsd: 5000 } });

    assert.strictEqual(low.status, 400);
    assert.strictEqual(high.status, 400);
    assert.strictEqual(fac.calls.verify, 0);

    stopServer(server); ledger.close();
  });
});

test('x402 testnet guard', async (t) => {
  await t.test('a testnet is disabled by default — faucet USDC must not buy real inference', async () => {
    const ledger = new CreditLedger(':memory:');
    const { server, port } = await startServer({
      creditLedger: ledger,
      pricePerMillion: RATE,
      config: { payTo: PAY_TO, network: 'base-sepolia', confirmOnChain: false }, // no allowTestnetCredit
      facilitator: stubFacilitator(),
    });

    const info = await call(port, '/api/billing/x402/info');
    assert.strictEqual(info.body.enabled, false);
    assert.strictEqual(info.body.testnet, true);
    assert.match(info.body.reason, /free from a faucet/);

    const paid = await call(port, '/api/billing/x402/topup', {
      method: 'POST',
      body: { amountUsd: 5 },
      headers: { 'PAYMENT-SIGNATURE': paymentHeader({ value: '5000000' }) },
    });
    assert.strictEqual(paid.status, 503);
    assert.strictEqual(ledger.getBalance(PAYER).balance, 0);

    stopServer(server); ledger.close();
  });

  await t.test('mainnet is enabled with the same config', async () => {
    const ledger = new CreditLedger(':memory:');
    const { server, port } = await startServer({
      creditLedger: ledger,
      pricePerMillion: RATE,
      config: { payTo: PAY_TO, network: 'base', confirmOnChain: false },
      facilitator: stubFacilitator(),
    });

    const info = await call(port, '/api/billing/x402/info');
    assert.strictEqual(info.body.enabled, true);
    assert.strictEqual(info.body.testnet, false);
    assert.strictEqual(info.body.asset, '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913');

    stopServer(server); ledger.close();
  });

  await t.test('a staging box can opt in explicitly', async () => {
    const ledger = new CreditLedger(':memory:');
    const { server, port } = await startServer({
      creditLedger: ledger,
      pricePerMillion: RATE,
      config: { payTo: PAY_TO, network: 'base-sepolia', allowTestnetCredit: true, confirmOnChain: false },
      facilitator: stubFacilitator(),
    });

    const info = await call(port, '/api/billing/x402/info');
    assert.strictEqual(info.body.enabled, true);
    assert.strictEqual(info.body.testnet, true);

    stopServer(server); ledger.close();
  });
});

test('x402 settlement capability probe', async (t) => {
  const { facilitatorSettles } = require('../billing/x402');

  await t.test('matches a network by name or by CAIP-2 id', () => {
    const byName = { kinds: [{ scheme: 'exact', network: 'base' }] };
    const byCaip = { kinds: [{ scheme: 'exact', network: 'eip155:8453' }] };
    assert.strictEqual(facilitatorSettles(byName, 'base'), true);
    assert.strictEqual(facilitatorSettles(byCaip, 'base'), true);
  });

  await t.test('a testnet-only facilitator does not settle mainnet', () => {
    const testnetOnly = { kinds: [{ scheme: 'exact', network: 'eip155:84532' }] };
    assert.strictEqual(facilitatorSettles(testnetOnly, 'base'), false);
  });

  await t.test('info reports settlementReady:false when the facilitator cannot settle', async () => {
    const ledger = new CreditLedger(':memory:');
    const fac = stubFacilitator();
    fac.supported = async () => ({ kinds: [{ scheme: 'exact', network: 'eip155:84532' }] });
    const { server, port } = await startServer({
      creditLedger: ledger,
      pricePerMillion: RATE,
      config: { payTo: PAY_TO, network: 'base', confirmOnChain: false },
      facilitator: fac,
    });

    const info = await call(port, '/api/billing/x402/info');
    assert.strictEqual(info.body.enabled, true);
    assert.strictEqual(info.body.settlementReady, false);
    assert.match(info.body.settlementNote, /does not settle/);

    stopServer(server); ledger.close();
  });

  await t.test('an unreachable facilitator is unknown, not a denial', async () => {
    const ledger = new CreditLedger(':memory:');
    const fac = stubFacilitator();
    fac.supported = async () => { throw new Error('ECONNREFUSED'); };
    const { server, port } = await startServer({
      creditLedger: ledger,
      pricePerMillion: RATE,
      config: { payTo: PAY_TO, network: 'base', confirmOnChain: false },
      facilitator: fac,
    });

    const info = await call(port, '/api/billing/x402/info');
    assert.strictEqual(info.body.settlementReady, null);
    assert.match(info.body.settlementNote, /unreachable/);

    stopServer(server); ledger.close();
  });
});

test('x402 on-chain confirmation', async (t) => {
  const { confirmTransferOnChain } = require('../billing/x402');
  const USDC = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
  const TOPIC = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';

  function pad(addr) { return '0x' + '0'.repeat(24) + addr.slice(2).toLowerCase(); }
  function rpc(result) {
    return async () => ({ ok: true, json: async () => ({ jsonrpc: '2.0', id: 1, result }) });
  }
  function receipt(logs, status = '0x1') { return { status, logs }; }
  function transferLog(to, atomic, address = USDC) {
    return {
      address,
      topics: [TOPIC, pad('0x1111111111111111111111111111111111111111'), pad(to)],
      data: '0x' + atomic.toString(16),
    };
  }

  const base = { rpcUrl: 'http://rpc.test', txHash: '0xabc', asset: USDC, payTo: PAY_TO };

  await t.test('reads the amount that actually reached us', async () => {
    const r = await confirmTransferOnChain({
      ...base, fetchImpl: rpc(receipt([transferLog(PAY_TO, 5_000_000n)])),
    });
    assert.strictEqual(r.ok, true);
    assert.strictEqual(r.receivedAtomic, 5_000_000n);
  });

  await t.test('a transfer to somebody else does not count', async () => {
    const r = await confirmTransferOnChain({
      ...base, fetchImpl: rpc(receipt([transferLog('0x' + 'de'.repeat(20), 5_000_000n)])),
    });
    assert.strictEqual(r.ok, false);
    assert.strictEqual(r.reason, 'no_transfer_to_us_in_this_transaction');
  });

  await t.test('a transfer of a DIFFERENT token does not count', async () => {
    /* The attack this blocks: settle a worthless token to our address and
       report it as USDC. */
    const fake = '0x' + 'ab'.repeat(20);
    const r = await confirmTransferOnChain({
      ...base, fetchImpl: rpc(receipt([transferLog(PAY_TO, 999_000_000n, fake)])),
    });
    assert.strictEqual(r.ok, false);
  });

  await t.test('a reverted transaction does not count', async () => {
    const r = await confirmTransferOnChain({
      ...base, fetchImpl: rpc(receipt([transferLog(PAY_TO, 5_000_000n)], '0x0')),
    });
    assert.strictEqual(r.ok, false);
    assert.strictEqual(r.reason, 'transaction_reverted');
  });

  await t.test('an unmined transaction is a retry, not a fraud', async () => {
    const r = await confirmTransferOnChain({ ...base, fetchImpl: rpc(null) });
    assert.strictEqual(r.ok, false);
    assert.strictEqual(r.reason, 'not_yet_mined');
  });

  await t.test('a facilitator claiming a settlement the chain denies credits nothing', async () => {
    const ledger = new CreditLedger(':memory:');
    const { server, port } = await startServer({
      creditLedger: ledger,
      pricePerMillion: RATE,
      config: { payTo: PAY_TO, network: 'base' },
      facilitator: stubFacilitator({ transaction: '0xlie' }),
      confirmTransferOnChain: async () => ({ ok: false, receivedAtomic: 0n, reason: 'no_transfer_to_us_in_this_transaction' }),
    });

    const res = await call(port, '/api/billing/x402/topup', {
      method: 'POST',
      body: { amountUsd: 5 },
      headers: { 'PAYMENT-SIGNATURE': paymentHeader({ value: '5000000' }) },
    });

    assert.strictEqual(res.status, 402);
    assert.strictEqual(ledger.getBalance(PAYER).balance, 0);

    stopServer(server); ledger.close();
  });

  await t.test('the ON-CHAIN amount wins over the authorized one', async () => {
    const ledger = new CreditLedger(':memory:');
    const { server, port } = await startServer({
      creditLedger: ledger,
      pricePerMillion: RATE,
      config: { payTo: PAY_TO, network: 'base' },
      facilitator: stubFacilitator({ transaction: '0xshort' }),
      /* header authorizes $5; only $1 actually landed */
      confirmTransferOnChain: async () => ({ ok: true, receivedAtomic: 1_000_000n }),
    });

    const res = await call(port, '/api/billing/x402/topup', {
      method: 'POST',
      body: { amountUsd: 5 },
      headers: { 'PAYMENT-SIGNATURE': paymentHeader({ value: '5000000' }) },
    });

    assert.strictEqual(res.body.amountUsd, 1);
    assert.strictEqual(res.body.credits, Math.floor((1 / RATE) * 1e6));

    stopServer(server); ledger.close();
  });

  await t.test('an unmined settlement answers 202 so the agent retries', async () => {
    const ledger = new CreditLedger(':memory:');
    const { server, port } = await startServer({
      creditLedger: ledger,
      pricePerMillion: RATE,
      config: { payTo: PAY_TO, network: 'base' },
      facilitator: stubFacilitator({ transaction: '0xpending' }),
      confirmTransferOnChain: async () => ({ ok: false, receivedAtomic: 0n, reason: 'not_yet_mined' }),
    });

    const res = await call(port, '/api/billing/x402/topup', {
      method: 'POST',
      body: { amountUsd: 5 },
      headers: { 'PAYMENT-SIGNATURE': paymentHeader({ value: '5000000' }) },
    });

    assert.strictEqual(res.status, 202);
    assert.match(res.body.error, /retry/);
    assert.strictEqual(ledger.getBalance(PAYER).balance, 0);

    stopServer(server); ledger.close();
  });
});
