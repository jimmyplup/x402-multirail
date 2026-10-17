'use strict';

/**
 * T-954 / T-952 — the chain + token registry and the signing primitives under
 * the Celo and Arc rails.
 *
 * What is pinned here, and why each pin is worth a failing build:
 *  - Every EIP-712 domain in billing/x402-networks.js reproduces the
 *    DOMAIN_SEPARATOR() its token returns on its own chain (read over RPC on
 *    2026-10-17). A wrong domain is the T-789 failure: every client signs a
 *    digest the token rejects, and nothing errors until a stranger tries to pay.
 *  - lib/secp256k1.js signs byte-for-byte like eth_account (RFC 6979), and
 *    reproduces the EXACT example signature printed in Circle's own settle API
 *    reference — an independent third-party vector, not one we generated.
 *  - The Circle seller proof binds the exact body bytes, the network and the
 *    payTo, recovers to the payTo key, and refuses a key that is not payTo's.
 */

const test = require('node:test');
const assert = require('node:assert');

const {
  NETWORKS, resolveNetwork, resolveAsset, eip712DomainFor, caip2Of,
} = require('../billing/x402-networks');
const { isTestnet, USDC_BY_NETWORK, CAIP2_BY_NETWORK, RPC_BY_NETWORK } = require('../billing/x402');
const { signDigest, recoverAddress, addressFromPrivateKey, hashTypedData } = require('../lib/secp256k1');
const { createSellerProofSigner, SELLER_REQUEST_TYPES } = require('../billing/circle-seller-proof');
const { keccak256 } = require('../lib/evm-address');

// Hardhat/anvil account #0 — a PUBLIC test key (Circle's docs use it too). Never fund it.
const TEST_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
const TEST_ADDR = '0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266';

const DOMAIN_TYPEHASH = Buffer.from(
  keccak256('EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'), 'hex',
);

function domainSeparator({ name, version }, chainId, address) {
  return '0x' + keccak256(Buffer.concat([
    DOMAIN_TYPEHASH,
    Buffer.from(keccak256(name), 'hex'),
    Buffer.from(keccak256(version), 'hex'),
    Buffer.from(BigInt(chainId).toString(16).padStart(64, '0'), 'hex'),
    Buffer.from(address.slice(2).toLowerCase().padStart(64, '0'), 'hex'),
  ]));
}

test('registry: every pinned EIP-712 domain reproduces its token\'s on-chain DOMAIN_SEPARATOR', () => {
  let checked = 0;
  for (const [alias, net] of Object.entries(NETWORKS)) {
    const chainId = Number(net.caip2.split(':')[1]);
    for (const [symbol, a] of Object.entries(net.assets)) {
      if (!a.domainSeparator) continue;
      assert.strictEqual(
        domainSeparator(a.eip712, chainId, a.address), a.domainSeparator,
        `${alias} ${symbol}: registry domain does not match the chain`,
      );
      checked++;
    }
  }
  assert.strictEqual(checked, 6, 'Celo USDC/USDT/USAT, Celo Sepolia USDC, Arc + Arc testnet USDC');
});

test('registry: the domains that differ per chain are the ones that bit us', () => {
  assert.deepStrictEqual(eip712DomainFor('base', 'USDC'), { name: 'USD Coin', version: '2' });
  assert.deepStrictEqual(eip712DomainFor('base-sepolia', 'USDC'), { name: 'USDC', version: '2' });
  assert.deepStrictEqual(eip712DomainFor('celo', 'USDC'), { name: 'USDC', version: '2' });
  assert.deepStrictEqual(eip712DomainFor('celo', 'USDT'), { name: 'Tether USD', version: '1' });
  assert.deepStrictEqual(eip712DomainFor('eip155:42220', '0xD2ab3C9A02DBBAB236BfEC45D1d755DF4267F771'),
    { name: 'Tether America USD', version: '1' }, 'by CAIP-2 + address, any case');
  assert.deepStrictEqual(eip712DomainFor('arc', 'USDC'), { name: 'USDC', version: '2' });
  assert.strictEqual(eip712DomainFor('celo', '0x0000000000000000000000000000000000000001'), null,
    'an unknown token has no domain — the caller must refuse, not guess');
  assert.strictEqual(eip712DomainFor('solana', 'USDC'), null);
});

test('registry: aliases, CAIP-2 ids and the legacy maps stay consistent', () => {
  assert.strictEqual(caip2Of('celo'), 'eip155:42220');
  assert.strictEqual(caip2Of('celo-sepolia'), 'eip155:11142220');
  assert.strictEqual(caip2Of('arc'), 'eip155:5042');
  assert.strictEqual(caip2Of('arc-testnet'), 'eip155:5042002');
  assert.strictEqual(resolveNetwork('eip155:5042').alias, 'arc');
  assert.strictEqual(resolveAsset('arc', 'usdc').address, '0x3600000000000000000000000000000000000000');
  // Base values are byte-identical to the pre-T-954 literals.
  assert.strictEqual(USDC_BY_NETWORK.base, '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913');
  assert.strictEqual(USDC_BY_NETWORK['base-sepolia'], '0x036CbD53842c5426634e7929541eC2318f3dCF7e');
  assert.strictEqual(CAIP2_BY_NETWORK.base, 'eip155:8453');
  assert.strictEqual(RPC_BY_NETWORK.base, 'https://mainnet.base.org');
  assert.strictEqual(RPC_BY_NETWORK.celo, 'https://forno.celo.org');
  for (const net of Object.values(NETWORKS)) {
    for (const a of Object.values(net.assets)) assert.strictEqual(a.decimals, 6);
  }
});

test('testnet guard: CAIP-2 ids with no "sepolia"/"testnet" text are still testnets', () => {
  assert.strictEqual(isTestnet('eip155:11142220'), true, 'Celo Sepolia');
  assert.strictEqual(isTestnet('eip155:5042002'), true, 'Arc testnet');
  assert.strictEqual(isTestnet('celo-sepolia'), true);
  assert.strictEqual(isTestnet('arc-testnet'), true);
  assert.strictEqual(isTestnet('eip155:42220'), false, 'Celo mainnet');
  assert.strictEqual(isTestnet('eip155:5042'), false, 'Arc mainnet');
  assert.strictEqual(isTestnet('celo'), false);
  assert.strictEqual(isTestnet('base'), false);
});

test('secp256k1: address derivation and raw-digest signatures match eth_account byte for byte', () => {
  assert.strictEqual(addressFromPrivateKey(TEST_KEY), TEST_ADDR);
  // Vectors from eth_account 0.13.7 Account.unsafe_sign_hash (RFC 6979), 2026-10-17.
  assert.strictEqual(
    signDigest('0x' + '00'.repeat(31) + '01', TEST_KEY),
    '0xa60a6906512e182138437a161eebd743f725438c71210b926fcd721b9a7c4bfa151b0de4e4103d8b44f1539c214dc5b85a2c217c93d3f3c69dd7f9d0a93ac3061c',
  );
  assert.strictEqual(
    signDigest('0x' + keccak256('linkrra'), TEST_KEY),
    '0x322d9ca33a512f241afe9b380154bee6893c99385f5247fd25624253bd6cd1730dcdfbdac26ad6eadc2131646e24fea0f2e3120867cc9de091f915ab427439991b',
  );
});

test('EIP-712: reproduces the exact EIP-3009 signature in Circle\'s settle API reference', () => {
  // developers.circle.com/api-reference/facilitator-service/settle-payment.md, example "exact".
  const digest = hashTypedData({
    domain: { name: 'USDC', version: '2', chainId: 5042002, verifyingContract: '0x3600000000000000000000000000000000000000' },
    types: {
      TransferWithAuthorization: [
        { name: 'from', type: 'address' }, { name: 'to', type: 'address' },
        { name: 'value', type: 'uint256' }, { name: 'validAfter', type: 'uint256' },
        { name: 'validBefore', type: 'uint256' }, { name: 'nonce', type: 'bytes32' },
      ],
    },
    primaryType: 'TransferWithAuthorization',
    message: {
      from: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266',
      to: '0x7c3ea945Fc4253255d8260fc18c2dee3D8C5dD3A',
      value: '1000000', validAfter: '0', validBefore: '1791400000',
      nonce: '0x4d3f8a2c9b1e7f60d5a4c3b2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2',
    },
  });
  const sig = signDigest(digest, TEST_KEY);
  assert.strictEqual(sig,
    '0x15e13cbd896cdf88f30cb826b2e79b97a35280b2ab459a1f50cd64ee48034e2849e7445b14feadcc3d1bb2868b41e8cf7997b623daa73872509c7027194765311b');
  assert.strictEqual(recoverAddress(digest, sig), TEST_ADDR);
  assert.match(sig, /(1b|1c)$/, 'Circle requires v = 27 or 28');
});

test('EIP-712: refuses types it cannot encode instead of hashing something wrong', () => {
  assert.throws(() => hashTypedData({
    domain: { name: 'x' }, types: { T: [{ name: 'a', type: 'uint256[]' }] }, primaryType: 'T', message: { a: [] },
  }), /unsupported EIP-712 type/);
  assert.throws(() => hashTypedData({
    domain: { name: 'x' }, types: { T: [{ name: 'a', type: 'uint64' }] }, primaryType: 'T', message: { a: 2n ** 64n },
  }), /out of range/);
});

test('Circle seller proof: matches eth_account, binds body/network/payTo, recovers to payTo', () => {
  const body = '{"x402Version":2,"hello":"world"}';
  const signer = createSellerProofSigner({
    privateKey: TEST_KEY, payTo: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266', lifetimeSeconds: 300,
  });
  const header = signer.header({
    purpose: 'settle', method: 'post', body, network: 'eip155:5042002',
    payTo: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266',
    nowSeconds: 1791399400, nonce: '0x' + 'ab'.repeat(32),
  });
  const envelope = JSON.parse(Buffer.from(header, 'base64url').toString('utf8'));
  // eth_account sign_message(encode_typed_data(...)) over the same SellerRequest, 2026-10-17.
  assert.strictEqual(envelope.signature,
    '0x1fc39d5d86d8a19bcd8186d518f352073d8e975a8347a98820fb7439fb47c3dd7db57638bb524b58c65c9e798920183978e5fe930d7df432efaee187384af8521c');
  assert.deepStrictEqual(
    { version: envelope.version, network: envelope.network, issuedAt: envelope.issuedAt, expiresAt: envelope.expiresAt },
    { version: 1, network: 'eip155:5042002', issuedAt: 1791399400, expiresAt: 1791399400 + 300 },
  );

  const digest = hashTypedData({
    domain: { name: 'Circle Facilitator Seller Request', version: '1', chainId: 5042002 },
    types: SELLER_REQUEST_TYPES,
    primaryType: 'SellerRequest',
    message: {
      purpose: 'settle', method: 'POST', bodyHash: '0x' + keccak256(body), network: 'eip155:5042002',
      payTo: envelope.payTo, nonce: envelope.nonce, issuedAt: envelope.issuedAt, expiresAt: envelope.expiresAt,
    },
  });
  assert.strictEqual(recoverAddress(digest, envelope.signature), TEST_ADDR);

  const otherBody = signer.header({
    purpose: 'settle', method: 'POST', body: body + ' ', network: 'eip155:5042002',
    payTo: TEST_ADDR, nowSeconds: 1791399400, nonce: '0x' + 'ab'.repeat(32),
  });
  assert.notStrictEqual(JSON.parse(Buffer.from(otherBody, 'base64url')).signature, envelope.signature,
    'one changed byte of body is a different proof');
});

test('Circle seller proof: refuses a key that does not control payTo, and bad purposes/lifetimes', () => {
  assert.throws(
    () => createSellerProofSigner({ privateKey: TEST_KEY, payTo: '0xAA0a350f6080940c138A8A50C0Fa8c8387782eb4' }),
    /controls 0xf39f.*not payTo/,
  );
  const signer = createSellerProofSigner({ privateKey: TEST_KEY, lifetimeSeconds: 3600 });
  const env = JSON.parse(Buffer.from(signer.header({
    purpose: 'verify', method: 'POST', body: '{}', network: 'eip155:5042', payTo: TEST_ADDR, nowSeconds: 100,
  }), 'base64url'));
  assert.strictEqual(env.expiresAt - env.issuedAt, 300, 'Circle caps a proof at 5 minutes');
  assert.match(env.nonce, /^0x[0-9a-f]{64}$/);
  assert.throws(() => signer.header({ purpose: 'refund', method: 'POST', network: 'eip155:5042', payTo: TEST_ADDR }), /purpose/);
  assert.throws(() => signer.header({ purpose: 'settle', method: 'POST', network: 'eip155:5042', payTo: '0x' + '11'.repeat(20) }), /controls/);
  assert.throws(() => signer.header({ purpose: 'settle', method: 'POST', network: 'solana:mainnet', payTo: TEST_ADDR }), /eip155/);
});
