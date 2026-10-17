'use strict';

/**
 * @fileoverview The chains and tokens x402 can be paid in here — one table.
 *
 * WHY A TABLE (T-954 Celo, T-952 Arc, 2026-10-17): until today every x402 door
 * hard-coded `extra: { name: 'USD Coin', version: '2' }` and the network maps
 * held only Base. `extra.name/version` is not decoration — it is the token's
 * EIP-712 domain, the thing a buyer signs over (scheme_exact_evm.md). Getting it
 * wrong is silent and total: every spec-following client signs a digest the
 * token rejects (T-789, 2026-10-07 — nobody outside could pay us for 7 weeks).
 * The domain differs per chain AND per token: Base USDC is "USD Coin" but Base
 * Sepolia, Celo and Arc USDC are "USDC"; Celo USDT is "Tether USD" v1 and has
 * no version() method at all. A literal cannot be right on more than one chain.
 *
 * EVERY DOMAIN BELOW IS PROVEN, NOT COPIED: on 2026-10-17 each token's
 * DOMAIN_SEPARATOR() was read from its own chain's RPC and recomputed from the
 * (name, version, chainId, address) here; all six matched. The separators are
 * pinned in test/test-x402-networks.js, so an edit that breaks one fails CI.
 * Sources for addresses: Celo — docs.celo.org/build/agents/x402.md and live
 * GET https://api.x402.celo.org/supported; Arc — docs.arc.io contract-addresses
 * and live GET https://api.circle.com/v1/facilitator/x402/supported.
 *
 * An unknown (network, asset) pair has NO domain here, and a rail built on it
 * is disabled with a reason rather than guessed at — see x402-rails.js.
 */

const NETWORKS = {
  base: {
    caip2: 'eip155:8453',
    testnet: false,
    rpcUrl: 'https://mainnet.base.org',
    explorerTx: 'https://basescan.org/tx/',
    assets: {
      USDC: {
        address: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
        decimals: 6,
        eip712: { name: 'USD Coin', version: '2' },
        domainSeparator: null, // checked by T-789 against PayAI verify, 2026-10-07
      },
    },
  },
  'base-sepolia': {
    caip2: 'eip155:84532',
    testnet: true,
    rpcUrl: 'https://sepolia.base.org',
    explorerTx: 'https://sepolia.basescan.org/tx/',
    assets: {
      USDC: {
        address: '0x036CbD53842c5426634e7929541eC2318f3dCF7e',
        decimals: 6,
        // name() on-chain = "USDC" (read 2026-10-17). The old literal "USD Coin"
        // was wrong here; harmless only because testnet credit is off in prod.
        eip712: { name: 'USDC', version: '2' },
        domainSeparator: null,
      },
    },
  },
  celo: {
    caip2: 'eip155:42220',
    testnet: false,
    rpcUrl: 'https://forno.celo.org',
    explorerTx: 'https://celoscan.io/tx/',
    facilitator: { url: 'https://api.x402.celo.org', apiKeyHeader: 'X-API-Key' },
    // Both Celo's and Circle's facilitators list assetTransferMethod beside the
    // domain in /supported; Circle's schema says `exact` "expects name, version,
    // and assetTransferMethod". Unsigned envelope data — never in the digest.
    exactExtra: { assetTransferMethod: 'eip3009' },
    assets: {
      USDC: {
        address: '0xcebA9300f2b948710d2653dD7B07f33A8B32118C',
        decimals: 6,
        eip712: { name: 'USDC', version: '2' },
        domainSeparator: '0xb2ce31d2838445fa765a491f550e7c78ac7280ab0f3bc9d6063a86df9c3fb578',
      },
      USDT: {
        address: '0x48065fbBE25f71C9282ddf5e1cD6D6A887483D5e',
        decimals: 6,
        // No version() on-chain; the separator only reproduces with "1".
        eip712: { name: 'Tether USD', version: '1' },
        domainSeparator: '0xbcb4d62e4834b598d0eacecd84c0b397a0254e077c41cf2143e394d5701d1088',
      },
      USAT: {
        address: '0xD2ab3C9A02DBBAB236BfEC45D1d755DF4267F771',
        decimals: 6,
        eip712: { name: 'Tether America USD', version: '1' },
        domainSeparator: '0xe6bbb7920a85afd44befe87c998da24b8b655c972faf8a8acbdf38c829ff8bf2',
      },
    },
  },
  'celo-sepolia': {
    caip2: 'eip155:11142220',
    testnet: true,
    rpcUrl: 'https://forno.celo-sepolia.celo-testnet.org',
    explorerTx: 'https://celo-sepolia.blockscout.com/tx/',
    facilitator: { url: 'https://api.x402.sepolia.celo.org', apiKeyHeader: 'X-API-Key' },
    exactExtra: { assetTransferMethod: 'eip3009' },
    assets: {
      USDC: {
        address: '0x01C5C0122039549AD1493B8220cABEdD739BC44E',
        decimals: 6,
        eip712: { name: 'USDC', version: '2' },
        domainSeparator: '0x23f491197bb8c5ea4fe8dd4c2293b600f073553f9814015e7a5eb57724df9578',
      },
    },
  },
  arc: {
    caip2: 'eip155:5042',
    testnet: false,
    rpcUrl: 'https://rpc.mainnet.arc.io',
    explorerTx: 'https://explorer.arc.io/tx/',
    facilitator: { url: 'https://api.circle.com/v1/facilitator/x402', apiKeyHeader: null },
    exactExtra: { assetTransferMethod: 'eip3009' },
    assets: {
      USDC: {
        // ERC-20 interface of Arc's native USDC (6 dp). Arc ALSO emits an
        // 18-dp Transfer from a system address for the same move; only this
        // contract's log may count (docs.arc.io usdc-system-events.md) —
        // confirmTransferOnChain matches on log.address, so it does.
        address: '0x3600000000000000000000000000000000000000',
        decimals: 6,
        eip712: { name: 'USDC', version: '2' },
        domainSeparator: '0x940506929bba468048a19b567f4f0d534714bc06604b5c3017e5d16785ccdf84',
      },
    },
  },
  'arc-testnet': {
    caip2: 'eip155:5042002',
    testnet: true,
    rpcUrl: 'https://rpc.testnet.arc.io',
    explorerTx: 'https://explorer.testnet.arc.io/tx/',
    facilitator: { url: 'https://api.circle.com/v1/facilitator/x402', apiKeyHeader: null },
    exactExtra: { assetTransferMethod: 'eip3009' },
    assets: {
      USDC: {
        address: '0x3600000000000000000000000000000000000000',
        decimals: 6,
        eip712: { name: 'USDC', version: '2' },
        domainSeparator: '0x361191522483d32a83e70ae7183b4b9629442c13a78bc9921d6f707911c8c6b0',
      },
    },
  },
};

/** The system address Arc emits its 18-decimal native-USDC Transfer log from. */
const ARC_NATIVE_USDC_SYSTEM_EMITTER = '0xffffFFFfFFffffffffffffffFfFFFfffFFFfFFfE';

/** Resolve "celo" or "eip155:42220" to its alias and entry; null if unknown. */
function resolveNetwork(name) {
  if (!name) return null;
  const key = String(name);
  if (NETWORKS[key]) return { alias: key, ...NETWORKS[key] };
  for (const [alias, entry] of Object.entries(NETWORKS)) {
    if (entry.caip2 === key) return { alias, ...entry };
  }
  return null;
}

/**
 * The registry entry for a token on a network, by symbol ("USAT") or by
 * contract address (any case). null when the pair is not in the table.
 */
function resolveAsset(network, assetOrSymbol) {
  const net = resolveNetwork(network);
  if (!net || !assetOrSymbol) return null;
  const want = String(assetOrSymbol);
  if (net.assets[want.toUpperCase()]) {
    const symbol = want.toUpperCase();
    return { symbol, ...net.assets[symbol] };
  }
  for (const [symbol, a] of Object.entries(net.assets)) {
    if (a.address.toLowerCase() === want.toLowerCase()) return { symbol, ...a };
  }
  return null;
}

/** `extra` for an x402 `exact` requirement: the token's EIP-712 domain, or null. */
function eip712DomainFor(network, asset) {
  const a = resolveAsset(network, asset);
  return a ? { ...a.eip712 } : null;
}

const caip2Of = (network) => resolveNetwork(network)?.caip2 || null;

module.exports = {
  NETWORKS,
  ARC_NATIVE_USDC_SYSTEM_EMITTER,
  resolveNetwork,
  resolveAsset,
  eip712DomainFor,
  caip2Of,
};
