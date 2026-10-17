'use strict';

/**
 * T-954 — the ERC-8004 registration file (a2a/erc8004.js).
 *
 * It is a public claim about what Synap serves, read by registry crawlers and
 * by the Celo hackathon judge, so the properties are about honesty: it names
 * only payment wallets/networks that are actually enabled, it never lists a
 * testnet as a payable wallet, `registrations` only ever carries well-formed
 * (registry, agentId) pairs, and the shape is the spec's registration-v1.
 */

const test = require('node:test');
const assert = require('node:assert');
const express = require('express');
const http = require('node:http');

const { buildRegistration, parseRegistrations, createErc8004Router, REGISTRATION_TYPE } = require('../a2a/erc8004');
const { createRailSet } = require('../billing/x402-rails');

const PAY_TO = '0xAA0a350f6080940c138A8A50C0Fa8c8387782eb4';
const REGISTRY = '0x8004A169FB4a3325136EB29fA0ceB6D2e539a432';

test('registration-v1 shape with Base only: no Celo/Arc claim, one wallet', () => {
  const rails = createRailSet({ payTo: PAY_TO, network: 'base' }).summary();
  const reg = buildRegistration({ publicBaseUrl: 'https://pool.linkrra.com/', rails });
  assert.strictEqual(reg.type, REGISTRATION_TYPE);
  assert.strictEqual(reg.x402Support, true);
  assert.strictEqual(reg.active, true);
  assert.deepStrictEqual(reg.registrations, []);
  assert.match(reg.description, /payable in USDC on Base\./);
  assert.doesNotMatch(reg.description, /Celo|Arc/);
  assert.deepStrictEqual(reg.services.filter((s) => s.name === 'wallet'), [{ name: 'wallet', endpoint: `eip155:8453:${PAY_TO}` }]);
  assert.ok(reg.services.some((s) => s.name === 'A2A' && s.endpoint === 'https://pool.linkrra.com/.well-known/agent-card.json'));
  assert.ok(reg.services.some((s) => s.name === 'MCP' && s.endpoint === 'https://pool.linkrra.com/mcp'));
});

test('only ENABLED mainnet rails are advertised as wallets and in the description', () => {
  const rails = createRailSet({
    payTo: PAY_TO, network: 'base',
    extraRails: [
      { network: 'celo', asset: 'USDC', payTo: PAY_TO },
      { network: 'celo', asset: 'USAT', payTo: PAY_TO },
      { network: 'arc', asset: 'USDC', payTo: PAY_TO },
      { network: 'celo-sepolia', asset: 'USDC', payTo: PAY_TO, allowTestnetCredit: true },
      { network: 'celo', asset: 'DAI', payTo: PAY_TO }, // unknown → disabled
    ],
  }).summary();
  const reg = buildRegistration({ publicBaseUrl: 'https://pool.linkrra.com', rails });
  assert.match(reg.description, /payable in USDC on Base, USDC\/USA₮ on Celo, USDC on Arc\./);
  assert.deepStrictEqual(reg.services.filter((s) => s.name === 'wallet').map((s) => s.endpoint), [
    `eip155:8453:${PAY_TO}`, `eip155:42220:${PAY_TO}`, `eip155:5042:${PAY_TO}`,
  ], 'one wallet per chain, no testnet, no disabled token');
});

test('registrations: well-formed (registry, agentId) pairs only', () => {
  assert.deepStrictEqual(parseRegistrations(''), []);
  assert.deepStrictEqual(
    parseRegistrations(`eip155:42220:${REGISTRY}:12345, bogus, eip155:42220:0x123:9, eip155:11142220:0x8004A818BFB912233c491871b3d84c89A494BD9e:7`),
    [
      { agentId: 12345, agentRegistry: `eip155:42220:${REGISTRY}` },
      { agentId: 7, agentRegistry: 'eip155:11142220:0x8004A818BFB912233c491871b3d84c89A494BD9e' },
    ],
  );
});

test('served at /.well-known/agent-registration.json as cacheable JSON with an ETag', async () => {
  const app = express();
  app.use(createErc8004Router({
    publicBaseUrl: 'https://pool.linkrra.com',
    rails: () => createRailSet({ payTo: PAY_TO, network: 'base' }).summary(),
    registrations: parseRegistrations(`eip155:42220:${REGISTRY}:42`),
  }));
  const server = http.createServer(app);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const url = `http://127.0.0.1:${server.address().port}/.well-known/agent-registration.json`;
  const res = await fetch(url);
  assert.strictEqual(res.status, 200);
  assert.match(res.headers.get('content-type'), /application\/json/);
  const body = await res.json();
  assert.deepStrictEqual(body.registrations, [{ agentId: 42, agentRegistry: `eip155:42220:${REGISTRY}` }]);
  const again = await fetch(url, { headers: { 'If-None-Match': res.headers.get('etag') } });
  assert.strictEqual(again.status, 304);
  server.closeAllConnections?.(); server.close();
});
