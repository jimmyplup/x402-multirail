'use strict';

/**
 * @fileoverview x402 rails — the (network, token) pairs one door accepts.
 *
 * Before T-954/T-952 (2026-10-17) every door took exactly one network: one
 * wallet, one chain, one facilitator per process. Celo ("Agents on Open Rails",
 * Prezenti) and Arc (Circle Developer Grants) each need their own chain next to
 * Base, each with a different facilitator, RPC, token contract and EIP-712
 * domain. A RAIL bundles those so a door can quote all of them in one 402
 * (`accepts[]` gets one entry per rail) and settle a payment on exactly the one
 * the payer chose.
 *
 * SAFETY PROPERTIES, each tested in test/test-x402-rails.js:
 *  - The PRIMARY rail is built from the same config keys, with the same
 *    defaults, as the single network every door had before — so with no extra
 *    rails configured the 402 body is byte-identical to the pre-T-954 one.
 *  - A payment is settled on the rail its own `accepted.network` (and asset)
 *    names, and NOTHING else: that rail's facilitator verifies against that
 *    rail's requirements, and that rail's RPC confirms the transfer of that
 *    rail's token to that rail's payTo. A payer cannot claim one chain and be
 *    checked against another. A network or asset no rail offers is refused
 *    before any facilitator call.
 *  - An extra rail with anything unknown — token contract, EIP-712 domain,
 *    decimals other than 6, a testnet without explicit consent, no RPC to
 *    confirm on — is DISABLED with a reason, never guessed at (T-789).
 *  - Testnet rails follow the same rule the primary always did: faucet money
 *    buys nothing unless a staging box says `ALLOW_TESTNET_CREDIT` out loud.
 */

const { resolveNetwork, resolveAsset } = require('./x402-networks');
const { createSellerProofSigner } = require('./circle-seller-proof');

/* billing/x402.js requires this module from inside createX402Router, and this
 * module needs FacilitatorClient/usdToAtomic/isTestnet from it; requiring at
 * call time keeps the cycle harmless. */
const x402 = () => require('./x402');

/** The domain every door advertised before T-954, kept for a custom X402_ASSET
 *  on the primary rail only — the one case the registry cannot know about. */
const LEGACY_PRIMARY_DOMAIN = { name: 'USD Coin', version: '2' };

const isAddress = (s) => /^0x[0-9a-fA-F]{40}$/.test(String(s || ''));

/**
 * @param {Object} spec
 * @param {string} spec.network — alias ("celo") or CAIP-2 ("eip155:42220")
 * @param {string} [spec.asset] — contract address or registry symbol; default USDC
 * @param {string} spec.payTo
 * @param {string} [spec.facilitatorUrl]
 * @param {string|Object} [spec.facilitatorApiKey]
 * @param {string|null} [spec.facilitatorApiKeyHeader] — e.g. 'X-API-Key'
 * @param {string} [spec.sellerProofKey] — Circle keyless trial only (see circle-seller-proof.js)
 * @param {string} [spec.rpcUrl]
 * @param {boolean} [spec.confirmOnChain=true]
 * @param {boolean} [spec.allowTestnetCredit=false]
 * @param {{name: string, version: string}} [spec.eip712] — explicit domain override
 * @param {Object} [spec.facilitator] — injected client (tests)
 * @param {Object} opts
 * @param {boolean} opts.isPrimary
 */
function buildRail(spec, { isPrimary }) {
  const { FacilitatorClient, isTestnet } = x402();
  const network = spec.network || 'base-sepolia';
  const net = resolveNetwork(network);
  const caip2 = net ? net.caip2 : network;

  let assetEntry;
  let asset;
  if (isAddress(spec.asset)) {
    asset = spec.asset;
    assetEntry = resolveAsset(network, asset);
  } else {
    assetEntry = resolveAsset(network, spec.asset || 'USDC');
    asset = assetEntry ? assetEntry.address : null;
  }

  let eip712 = spec.eip712 || (assetEntry ? assetEntry.eip712 : null);
  if (!eip712 && isPrimary && asset) eip712 = LEGACY_PRIMARY_DOMAIN;
  const decimals = assetEntry ? assetEntry.decimals : 6;
  const symbol = assetEntry ? assetEntry.symbol : null;

  const payTo = spec.payTo || null;
  const rpcUrl = spec.rpcUrl || (net ? net.rpcUrl : null) || null;
  const confirmOnChain = spec.confirmOnChain !== false;
  const allowTestnetCredit = spec.allowTestnetCredit === true;
  const testnet = isTestnet(network) || isTestnet(caip2) || !!(net && net.testnet);

  /* The primary keeps its pre-T-954 default so an unset X402_FACILITATOR_URL
   * means what it always meant; an extra rail defaults to its chain's own
   * facilitator (Celo's, Circle's), because that is the only one that settles there. */
  const facilitatorUrl = spec.facilitatorUrl
    || (isPrimary ? 'https://x402.org/facilitator' : (net && net.facilitator && net.facilitator.url))
    || 'https://x402.org/facilitator';
  const apiKeyHeader = spec.facilitatorApiKeyHeader !== undefined
    ? spec.facilitatorApiKeyHeader
    : (net && net.facilitator && net.facilitator.url === facilitatorUrl ? net.facilitator.apiKeyHeader : null);

  let signerError = null;
  let sellerProof = null;
  if (spec.sellerProofKey) {
    try {
      sellerProof = createSellerProofSigner({ privateKey: spec.sellerProofKey, payTo });
    } catch (err) {
      signerError = `seller-proof key rejected: ${err.message}`;
    }
  }

  const facilitator = spec.facilitator || new FacilitatorClient({
    baseUrl: facilitatorUrl,
    apiKey: spec.facilitatorApiKey || null,
    apiKeyHeader,
    sellerProof,
  });

  const disabledReason = !payTo
    ? `no receiving wallet configured for "${network}"`
    : !asset
      ? `no ${spec.asset || 'USDC'} contract known for network "${network}"`
      : !eip712
        ? `no EIP-712 domain known for ${asset} on "${network}" — refusing to guess (T-789)`
        : decimals !== 6
          ? `${symbol || asset} has ${decimals} decimals; x402 doors here price in 6-decimal dollars`
          : testnet && !allowTestnetCredit
            ? `network "${network}" is a testnet — its tokens are free from a faucet`
            : !isPrimary && confirmOnChain && !rpcUrl
              ? `no RPC known for "${network}" to confirm settlements on`
              : signerError;

  return {
    id: `${caip2}:${String(asset || '').toLowerCase()}`,
    isPrimary,
    network,
    caip2,
    asset,
    symbol,
    decimals,
    eip712,
    exactExtra: (net && net.exactExtra) || null,
    payTo,
    rpcUrl,
    confirmOnChain,
    allowTestnetCredit,
    testnet,
    facilitator,
    facilitatorUrl,
    explorerTx: (net && net.explorerTx) || null,
    enabled: !disabledReason,
    disabledReason: disabledReason || null,
  };
}

/** One x402 `exact` PaymentRequirements for a rail. */
function requirementsForRail(rail, amountUsd, maxTimeoutSeconds = 120) {
  const { usdToAtomic } = x402();
  return {
    scheme: 'exact',
    network: rail.caip2,
    amount: usdToAtomic(amountUsd),
    asset: rail.asset,
    payTo: rail.payTo,
    maxTimeoutSeconds,
    /* T-789: the token's EIP-712 domain, from the registry — never a literal. */
    extra: { ...rail.eip712, ...(rail.exactExtra || {}) },
  };
}

/**
 * Rails for one door: the primary (from the door's existing config keys) plus
 * `cfg.extraRails`. Duplicates of an earlier rail (same chain + token) are dropped.
 *
 * @param {Object} cfg — the shared x402Config
 * @param {Object} [deps]
 * @param {Object} [deps.facilitator] — injected client for the PRIMARY rail (tests)
 */
function createRailSet(cfg = {}, deps = {}) {
  const primary = buildRail({
    network: cfg.network,
    asset: cfg.asset,
    payTo: cfg.payTo,
    facilitatorUrl: cfg.facilitatorUrl,
    facilitatorApiKey: cfg.facilitatorApiKey,
    facilitatorApiKeyHeader: cfg.facilitatorApiKeyHeader,
    sellerProofKey: cfg.sellerProofKey,
    rpcUrl: cfg.rpcUrl,
    confirmOnChain: cfg.confirmOnChain,
    allowTestnetCredit: cfg.allowTestnetCredit,
    eip712: cfg.assetEip712,
    facilitator: deps.facilitator,
  }, { isPrimary: true });

  const rails = [primary];
  for (const spec of cfg.extraRails || []) {
    const rail = buildRail({
      confirmOnChain: cfg.confirmOnChain,
      ...spec,
    }, { isPrimary: false });
    if (rails.some((r) => r.id === rail.id)) continue;
    rails.push(rail);
  }

  /** Rails a payment may arrive on: the primary, plus enabled extras. */
  function payable() {
    return rails.filter((r) => r.isPrimary || r.enabled);
  }

  return {
    rails,
    primary,

    /** accepts[] for a 402: the primary first (old clients read accepts[0]). */
    accepts(amountUsd, maxTimeoutSeconds) {
      return payable().map((r) => requirementsForRail(r, amountUsd, maxTimeoutSeconds));
    },

    requirements(rail, amountUsd, maxTimeoutSeconds) {
      return requirementsForRail(rail || primary, amountUsd, maxTimeoutSeconds);
    },

    /**
     * The rail a decoded PAYMENT-SIGNATURE says it pays on.
     * A payload that names no network (pre-v2 clients) is the primary's, as it
     * always was. With ONLY the primary configured, every payload goes to it
     * and the facilitator judges it against the primary's requirements —
     * exactly the pre-T-954 behaviour. Once extra rails exist, a named
     * network/asset no rail offers is an error, not a guess.
     * @returns {{rail: Object}|{error: string}}
     */
    select(payload) {
      if (rails.length === 1) return { rail: primary };
      const accepted = payload && typeof payload.accepted === 'object' && payload.accepted ? payload.accepted : null;
      const named = (accepted && accepted.network) || (payload && payload.network) || null;
      if (!named) return { rail: primary };
      const onNetwork = payable().filter((r) => r.caip2 === named || r.network === named);
      if (!onNetwork.length) {
        return { error: `network "${named}" is not accepted on this resource — pay on one of accepts[]` };
      }
      const asset = accepted && accepted.asset;
      if (!asset) return { rail: onNetwork[0] };
      const match = onNetwork.find((r) => String(r.asset).toLowerCase() === String(asset).toLowerCase());
      if (!match) return { error: `asset ${asset} is not accepted on "${named}" — pay with one of accepts[]` };
      return { rail: match };
    },

    /** Public, secret-free description for /info endpoints. */
    summary() {
      return rails.map((r) => ({
        network: r.network,
        caip2: r.caip2,
        asset: r.asset,
        symbol: r.symbol,
        eip712: r.eip712,
        payTo: r.payTo,
        facilitator: r.facilitatorUrl,
        testnet: r.testnet,
        enabled: r.enabled,
        reason: r.disabledReason,
        primary: r.isPrimary || undefined,
      }));
    },
  };
}

/**
 * Extra rails from the environment. Nothing set → no extra rails → every door
 * behaves exactly as before. Per network NAME in X402_EXTRA_NETWORKS
 * (e.g. "celo,arc"), with PREFIX = X402_<NAME upper-cased, non-alnum → _>_:
 *   PREFIX_ASSETS                 comma list of registry symbols (default USDC)
 *   PREFIX_PAY_TO                 default X402_PAY_TO (the same EVM key works on every chain)
 *   PREFIX_FACILITATOR_URL        default: the chain's own facilitator from x402-networks.js
 *   PREFIX_FACILITATOR_API_KEY    secret — Celo: sent as X-API-Key; Circle: Bearer
 *   PREFIX_FACILITATOR_API_KEY_HEADER  override the header name
 *   PREFIX_SELLER_PROOF_KEY       secret — Circle keyless trial; must control PAY_TO
 *   PREFIX_RPC_URL                default: the chain's public RPC
 *   PREFIX_ALLOW_TESTNET_CREDIT=1 staging boxes only
 */
function extraRailsFromEnv(env = process.env, base = {}) {
  const names = String(env.X402_EXTRA_NETWORKS || '').split(',').map((s) => s.trim()).filter(Boolean);
  const out = [];
  for (const name of names) {
    const p = `X402_${name.toUpperCase().replace(/[^A-Z0-9]+/g, '_')}_`;
    const symbols = String(env[`${p}ASSETS`] || 'USDC').split(',').map((s) => s.trim()).filter(Boolean);
    for (const asset of symbols) {
      out.push({
        network: name,
        asset,
        payTo: env[`${p}PAY_TO`] || base.payTo || null,
        facilitatorUrl: env[`${p}FACILITATOR_URL`] || undefined,
        facilitatorApiKey: env[`${p}FACILITATOR_API_KEY`] || null,
        facilitatorApiKeyHeader: env[`${p}FACILITATOR_API_KEY_HEADER`] || undefined,
        sellerProofKey: env[`${p}SELLER_PROOF_KEY`] || null,
        rpcUrl: env[`${p}RPC_URL`] || undefined,
        allowTestnetCredit: env[`${p}ALLOW_TESTNET_CREDIT`] === '1',
      });
    }
  }
  return out;
}

module.exports = {
  createRailSet,
  buildRail,
  requirementsForRail,
  extraRailsFromEnv,
  LEGACY_PRIMARY_DOMAIN,
};
