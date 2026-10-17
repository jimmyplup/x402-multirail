'use strict';

const { builderCodeExtensions, builderCodeEchoError } = require('./x402-builder-code');

/**
 * @fileoverview x402 — how an AI agent buys credits without a human.
 *
 * Stripe Checkout is a browser flow: a redirect, a card form, a human. An agent
 * has none of those. x402 is the answer the industry converged on — HTTP 402
 * with a machine-readable price, paid in stablecoin, settled in one round trip,
 * no account and no card. The Linux Foundation's x402 Foundation went
 * operational on 2026-07-14 with Visa, Mastercard, Stripe, Google, AWS,
 * Cloudflare and Coinbase in it, and the agent frameworks (LangChain, CrewAI,
 * MCP clients) ship x402 adapters, so an agent that finds this endpoint can pay
 * it with no code written by us and none written by them.
 *
 * WHAT THIS BUYS: credits, in the same ledger the Stripe path credits. The
 * gateway burns one credit per token regardless of how the credit was paid for,
 * so there is exactly one balance and one price — see billing/payg.js for the
 * derivation of that price.
 *
 * THE LEDGER ADDRESS IS THE PAYER'S WALLET. A human signs in with Google and
 * gets `acct_<hex>`; an agent pays from `0x…` and that address IS its account.
 * No sign-up, no key exchange, no email. If the caller does happen to be signed
 * in, the credits go to the signed-in account instead, so a human topping up
 * from their own wallet does not end up with two balances.
 *
 * WHAT WE DO NOT DO: hold a private key. We publish a `payTo` address supplied
 * by config and let the facilitator move funds from the payer to it. This
 * server can receive money; it cannot spend it. That is deliberate and is the
 * reason no wallet secret exists anywhere in this repo.
 *
 * TRUST: verification and settlement are delegated to a facilitator over the
 * standard /verify and /settle interface. We credit ONLY on a settled
 * transaction hash returned by the facilitator — never on the payload the
 * client handed us, which is a claim, not a receipt. The transaction hash is
 * the idempotency key, so a replayed PAYMENT-SIGNATURE header credits nothing
 * twice.
 *
 * Spec: https://github.com/coinbase/x402 — specs/x402-specification-v2.md and
 * specs/transports-v2/http.md. Protocol v2 is also what makes us discoverable
 * in the x402 Bazaar: a v2 402 body carries a top-level `resource` object and
 * an `extensions.bazaar` declaration that facilitators (payai, CDP) catalog on
 * every /verify and /settle call. See docs.payai.network/x402/facilitators/bazaar
 * and docs.cdp.coinbase.com/x402/seller/get-discovered — v1's per-requirement
 * `outputSchema.input` discovery style is retired along with v1 itself.
 *
 * TRANSPORT (v2 HTTP, specs/transports-v2/http.md): all protocol data moves
 * through headers now, not just the body — the CDP Bazaar validator reads
 * ONLY the `PAYMENT-REQUIRED` header on a 402 and ignores the JSON body
 * entirely. `PAYMENT-REQUIRED` (server→client) carries the same
 * PaymentRequired object as the body, base64-encoded; `PAYMENT-SIGNATURE`
 * (client→server, was `X-PAYMENT` in v1) carries the PaymentPayload;
 * `PAYMENT-RESPONSE` (server→client, was `X-PAYMENT-RESPONSE`) carries the
 * SettlementResponse. The JSON body is kept alongside for humans/debugging —
 * the spec explicitly leaves response bodies as "a server implementation
 * concern" — but it is the headers a real v2 client and the Bazaar reads.
 *
 * @author Linkrra Contributors
 * @license MIT
 */

const express = require('express');
const { usdToMicro } = require('../lib/usd-micro');
const { generateCdpJwt } = require('./cdp-jwt');
const { NETWORKS } = require('./x402-networks');
const { SELLER_PROOF_HEADER } = require('./circle-seller-proof');

const X402_VERSION = 2;

/** USDC has 6 decimals on every chain we would take it on. */
const USDC_DECIMALS = 6;

/** How long a payment authorization we hand out stays valid. */
const MAX_TIMEOUT_SECONDS = 120;

/**
 * Known USDC contracts, so a deployment only has to name a network.
 * An unknown network must be given `X402_ASSET` explicitly rather than guessed
 * at — crediting against the wrong contract would be accepting a worthless
 * token as if it were a dollar.
 */
const USDC_BY_NETWORK = Object.fromEntries(
  Object.entries(NETWORKS).filter(([, n]) => n.assets.USDC).map(([alias, n]) => [alias, n.assets.USDC.address]),
);

/**
 * Networks whose tokens are free to mint from a public faucet.
 *
 * This is the difference between a demo and a giveaway. A settlement on
 * base-sepolia is a perfectly valid x402 payment that cost the payer nothing —
 * so crediting it grants real inference against play money. Testnets are
 * therefore treated as unpayable in production unless a deployment says
 * otherwise out loud (`allowTestnetCredit`), which only a test or a staging box
 * should ever do.
 */
const TESTNET_NETWORKS = new Set([
  'base-sepolia',
  'avalanche-fuji',
  'polygon-amoy',
  'sei-testnet',
  'solana-devnet',
  'radius-testnet',
  'eip155:84532',
  'eip155:11155111',
  'eip155:421614',
  'eip155:80002',
  // T-954/T-952: these two CAIP-2 ids carry no "sepolia"/"testnet" text, so
  // the regex below cannot catch them — eip155:11142220 is Celo Sepolia,
  // eip155:5042002 is Arc testnet. Without these lines X402_NETWORK set to the
  // CAIP-2 form would credit faucet money.
  'celo-sepolia',
  'eip155:11142220',
  'arc-testnet',
  'eip155:5042002',
]);

function isTestnet(network) {
  if (TESTNET_NETWORKS.has(network)) return true;
  if (/sepolia|testnet|devnet|fuji|amoy|goerli/i.test(network)) return true;
  return Object.values(NETWORKS).some((n) => n.testnet && n.caip2 === network);
}

/** atomic units (6dp) for a dollar amount, as the decimal string the spec wants */
function usdToAtomic(amountUsd) {
  return String(Math.round(amountUsd * 10 ** USDC_DECIMALS));
}

function atomicToUsd(atomic) {
  return Number(atomic) / 10 ** USDC_DECIMALS;
}

function decodePaymentHeader(raw) {
  const json = Buffer.from(String(raw), 'base64').toString('utf8');
  const parsed = JSON.parse(json);
  if (!parsed || typeof parsed !== 'object') throw new Error('payment payload is not an object');
  return parsed;
}

/** base64(JSON) — the encoding all three v2 transport headers share. */
function encodeJsonHeader(obj) {
  return Buffer.from(JSON.stringify(obj), 'utf8').toString('base64');
}

/**
 * Minimal facilitator client — /verify, /settle, /supported over HTTP.
 * Node 18+ global fetch; no SDK, so there is no dependency that can change
 * under us between the spec and the wire.
 *
 * `apiKey` is either a static bearer string (payai and most facilitators) or
 * `{ cdpKeyId, cdpKeySecret }` for Coinbase CDP, which rejects a static token
 * and wants a fresh JWT bound to each request — see billing/cdp-jwt.js.
 *
 * `apiKeyHeader` (T-954): send a static key under that header name instead of
 * `Authorization: Bearer`. Celo's facilitator wants `X-API-Key: <key>` and
 * answers 401 on /settle without it — while /verify and /supported stay open,
 * so an integration looks healthy right up to its first real payment
 * (docs.celo.org/build/agents/x402.md "Endpoints").
 *
 * `sellerProof` (T-952): a signer from billing/circle-seller-proof.js. Circle
 * Facilitator Service's keyless trial authenticates /verify and /settle with a
 * `Facilitator-Seller-Proof` header bound to the exact request body, so the
 * body is serialized once and the same bytes are both signed and sent.
 */
class FacilitatorClient {
  constructor({ baseUrl, apiKey = null, apiKeyHeader = null, sellerProof = null, timeoutMs = 20_000 }) {
    this.baseUrl = String(baseUrl).replace(/\/$/, '');
    this.apiKey = apiKey;
    this.apiKeyHeader = apiKeyHeader;
    this.sellerProof = sellerProof;
    this.timeoutMs = timeoutMs;
  }

  _authHeader(method, path) {
    if (!this.apiKey) return null;
    if (typeof this.apiKey === 'object') {
      const token = generateCdpJwt({
        keyId: this.apiKey.cdpKeyId,
        keySecret: this.apiKey.cdpKeySecret,
        method,
        url: `${this.baseUrl}${path}`,
      });
      return `Bearer ${token}`;
    }
    return `Bearer ${this.apiKey}`;
  }

  /** Every auth header this facilitator needs for one request. */
  _headersFor(method, path, rawBody, body) {
    const headers = {};
    if (this.apiKey && this.apiKeyHeader && typeof this.apiKey === 'string') {
      headers[this.apiKeyHeader] = this.apiKey;
    } else {
      const auth = this._authHeader(method, path);
      if (auth) headers.Authorization = auth;
    }
    const purpose = path.replace(/^\//, '');
    if (this.sellerProof && (purpose === 'verify' || purpose === 'settle')) {
      const reqs = body && body.paymentRequirements;
      headers[SELLER_PROOF_HEADER] = this.sellerProof.header({
        purpose, method, body: rawBody, network: reqs && reqs.network, payTo: reqs && reqs.payTo,
      });
    }
    return headers;
  }

  async _post(path, body) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const raw = JSON.stringify(body);
      const headers = { 'Content-Type': 'application/json', ...this._headersFor('POST', path, raw, body) };
      const res = await fetch(`${this.baseUrl}${path}`, {
        method: 'POST',
        headers,
        body: raw,
        signal: controller.signal,
      });
      /* CDP reports what its Bazaar indexer did with our discovery metadata
       * in this header (base64 JSON keyed by extension; bazaar.status is
       * success | processing | rejected + rejectedReason). It is the only
       * place a listing refusal is ever stated, so log it. */
      const extResp = res.headers.get('extension-responses');
      if (extResp) {
        let decoded = extResp;
        try { decoded = Buffer.from(extResp, 'base64').toString('utf8'); } catch (_) { /* log raw */ }
        console.log(`[x402] facilitator ${path} extension-responses: ${decoded.slice(0, 1500)}`);
      } else if (path === '/settle') {
        console.log('[x402] facilitator /settle returned no extension-responses header (discovery not submitted)');
      }
      const text = await res.text();
      let json = null;
      try { json = JSON.parse(text); } catch (_) { /* keep the raw text for the error */ }
      if (!res.ok) {
        /* T-954: Celo's facilitator (x402-rs) answers a REJECTED payment with
         * HTTP 400 and a well-formed verdict — {"isValid":false,
         * "invalidReason":"insufficient_funds"} — measured live 2026-10-17.
         * Reading that as an outage turned "you can't pay this" into a 502.
         * Only a NEGATIVE verdict is taken from an error status; a positive one
         * never is, so an error page cannot be mistaken for a settlement. */
        if (path === '/verify' && json && json.isValid === false) return json;
        if (path === '/settle' && json && json.success === false) return json;
        throw new Error(`facilitator ${path} ${res.status}: ${text.slice(0, 1500)}`);
      }
      return json;
    } finally {
      clearTimeout(timer);
    }
  }

  verify(paymentPayload, paymentRequirements) {
    return this._post('/verify', {
      x402Version: X402_VERSION,
      paymentPayload,
      paymentRequirements,
    });
  }

  settle(paymentPayload, paymentRequirements) {
    return this._post('/settle', {
      x402Version: X402_VERSION,
      paymentPayload,
      paymentRequirements,
    });
  }

  /** GET /supported — which (scheme, network) pairs this facilitator can settle. */
  async supported() {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const headers = this._headersFor('GET', '/supported', '', null);
      const res = await fetch(`${this.baseUrl}/supported`, { headers, signal: controller.signal });
      if (!res.ok) throw new Error(`facilitator /supported ${res.status}`);
      return await res.json();
    } finally {
      clearTimeout(timer);
    }
  }
}

/** ERC-20 Transfer(address,address,uint256) */
const TRANSFER_TOPIC = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';

/** Public JSON-RPC per network, so a settlement can be checked against the chain itself. */
const RPC_BY_NETWORK = Object.fromEntries(
  Object.entries(NETWORKS).map(([alias, n]) => [alias, n.rpcUrl]),
);

/** topic/address words are 32 bytes; an address is the low 20. */
function addressFromTopic(topic) {
  return '0x' + String(topic || '').slice(-40).toLowerCase();
}

/**
 * Read a settled transaction from the chain and say what it actually paid us.
 *
 * This exists because the facilitator is not a trusted party. It is a service
 * that broadcasts a signed authorization on our behalf, and its /settle reply
 * is a CLAIM — a hash and the word "success". It cannot steal the money (the
 * authorization names our payTo and nobody else), but a broken or dishonest one
 * could report a settlement that never happened, or one worth a fraction of
 * what it says. Crediting on that claim alone would make our balance sheet a
 * mirror of somebody else's honesty.
 *
 * So we ask the chain: does this transaction exist, did it succeed, and does it
 * carry a USDC Transfer to our address? The answer is the amount actually
 * received, in atomic units.
 *
 * @returns {Promise<{ok: boolean, receivedAtomic: bigint, reason?: string}>}
 */
async function confirmTransferOnChain({ rpcUrl, txHash, asset, payTo, fetchImpl = fetch, timeoutMs = 15_000 }) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetchImpl(rpcUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0', id: 1, method: 'eth_getTransactionReceipt', params: [txHash],
      }),
      signal: controller.signal,
    });
    if (!res.ok) throw new Error(`rpc ${res.status}`);
    const json = await res.json();
    const receipt = json && json.result;

    /* Not an error — a fresh transaction is simply not mined yet. The caller
       decides whether to wait or to refuse; it must not be read as fraud. */
    if (!receipt) return { ok: false, receivedAtomic: 0n, reason: 'not_yet_mined' };
    if (receipt.status !== '0x1') return { ok: false, receivedAtomic: 0n, reason: 'transaction_reverted' };

    const wanted = String(payTo).toLowerCase();
    const assetLower = String(asset).toLowerCase();
    let received = 0n;

    for (const log of receipt.logs || []) {
      if (String(log.address).toLowerCase() !== assetLower) continue;   // right token
      if (!log.topics || log.topics[0] !== TRANSFER_TOPIC) continue;     // right event
      if (addressFromTopic(log.topics[2]) !== wanted) continue;          // paid to US
      received += BigInt(log.data);
    }

    if (received === 0n) {
      return { ok: false, receivedAtomic: 0n, reason: 'no_transfer_to_us_in_this_transaction' };
    }
    return { ok: true, receivedAtomic: received };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Does this facilitator actually settle the network we are quoting prices in?
 *
 * Worth asking out loud, because the failure it catches is the expensive kind:
 * a correct-looking 402 that advertises a price on a chain nobody will settle,
 * so every agent that tries to pay gets a 502 after it has already signed.
 * Networks appear both as names ("base") and as CAIP-2 ids ("eip155:8453"), so
 * both spellings count as a match.
 */
const CAIP2_BY_NETWORK = Object.fromEntries(
  Object.entries(NETWORKS).map(([alias, n]) => [alias, n.caip2]),
);

function facilitatorSettles(supported, network) {
  const kinds = (supported && supported.kinds) || [];
  const aliases = new Set([network, CAIP2_BY_NETWORK[network]].filter(Boolean));
  return kinds.some((k) => k.scheme === 'exact' && aliases.has(k.network));
}

/**
 * @param {Object} deps
 * @param {import('../lib/credit-ledger').CreditLedger} deps.creditLedger
 * @param {number} deps.pricePerMillion — the SAME derived rate the card path uses
 * @param {Object} deps.config
 * @param {string} deps.config.payTo — receiving wallet address (required to enable)
 * @param {string} [deps.config.network]
 * @param {string} [deps.config.asset]
 * @param {string} [deps.config.facilitatorUrl]
 * @param {string} [deps.config.facilitatorApiKey]
 * @param {string} [deps.config.publicBaseUrl]
 * @param {number} [deps.config.minUsd]
 * @param {number} [deps.config.maxUsd]
 * @param {FacilitatorClient} [deps.facilitator] — injectable for tests
 * @returns {import('express').Router}
 */
function createX402Router(deps) {
  const { creditLedger, pricePerMillion } = deps;
  const promo = deps.promo || null; // T-758 first-deposit bonus (optional)
  const cfg = deps.config || {};
  /* T-953: Base Builder Code (ERC-8021) declared on every 402; throws at boot on a
   * malformed X402_BUILDER_CODE rather than silently attributing nothing. */
  const builderCodeExt = builderCodeExtensions(cfg.builderCode);

  if (!creditLedger) throw new TypeError('createX402Router: creditLedger required');
  if (!Number.isFinite(pricePerMillion) || pricePerMillion <= 0) {
    throw new TypeError('createX402Router: pricePerMillion must be a positive number');
  }

  /* T-954/T-952: the door's payment rails — the primary is built from exactly
   * the config keys (and defaults) this function always read; cfg.extraRails
   * adds Celo / Arc next to it. See billing/x402-rails.js. */
  const railSet = require('./x402-rails').createRailSet(cfg, { facilitator: deps.facilitator });
  const primary = railSet.primary;
  const network = primary.network;
  /* v2 payment requirements name the network in CAIP-2 form ("eip155:8453"),
   * not the human alias ("base") v1 used — everything internal (USDC_BY_NETWORK,
   * RPC_BY_NETWORK, the testnet guard) keeps using the alias; only what goes out
   * on the wire is translated. An already-CAIP-2 X402_NETWORK passes through. */
  const asset = primary.asset;
  const payTo = primary.payTo;
  const minUsd = Number.isFinite(cfg.minUsd) ? cfg.minUsd : 1;
  const maxUsd = Number.isFinite(cfg.maxUsd) ? cfg.maxUsd : 1000;
  const publicBaseUrl = (cfg.publicBaseUrl || 'https://pool.linkrra.com').replace(/\/$/, '');
  const resourceUrl = `${publicBaseUrl}/api/billing/x402/topup`;

  /* synap.linkrra.com and pool.linkrra.com proxy to this same process (T-543)
   * with the Host header preserved — an agent polling /info on one must be
   * quoted that same host back, not always "pool" from PUBLIC_BASE_URL. This
   * is display/discovery metadata only: requirementsFor() below (what
   * facilitator.verify/settle actually check) never references resourceUrl,
   * so getting the host "wrong" here cannot break a settlement, only mislabel
   * a discovery response. Limited to the known pair so a spoofed Host header
   * on a request that reached this process some other way can't put an
   * arbitrary domain in a payment-discovery response; anything else falls
   * back to the configured resourceUrl. */
  const KNOWN_RESOURCE_HOSTS = new Set(['synap.linkrra.com', 'pool.linkrra.com']);
  function resourceUrlForReq(req) {
    const host = req && typeof req.get === 'function' ? req.get('host') : null;
    if (!host || !KNOWN_RESOURCE_HOSTS.has(host.toLowerCase())) return resourceUrl;
    const proto = req.protocol === 'http' ? 'http' : 'https';
    return `${proto}://${host}/api/billing/x402/topup`;
  }

  /* Confirming on-chain is the default and turning it off is a decision, not a
     convenience: without it the facilitator's word is the only evidence a
     payment happened. */
  const confirmOnChain = primary.confirmOnChain;
  const rpcUrl = primary.rpcUrl;
  const confirmFn = deps.confirmTransferOnChain || confirmTransferOnChain;

  const facilitator = primary.facilitator;

  /* Enabled means: we know where the money goes and which token counts as a
   * dollar. Missing either is a configuration error, not a runtime surprise —
   * so it is reported by /info rather than discovered mid-payment. */
  const allowTestnetCredit = primary.allowTestnetCredit;
  const testnet = isTestnet(network);

  const enabled = !!(payTo && asset) && (!testnet || allowTestnetCredit);
  const disabledReason = !payTo
    ? 'no receiving wallet configured (X402_PAY_TO)'
    : !asset
      ? `no USDC contract known for network "${network}" (set X402_ASSET)`
      : testnet && !allowTestnetCredit
        ? `network "${network}" is a testnet — its USDC is free from a faucet, so ` +
          'crediting it would give away inference for nothing. Point X402_NETWORK at ' +
          'a mainnet (and a facilitator that settles there), or set ' +
          'X402_ALLOW_TESTNET_CREDIT=1 on a staging box.'
        : null;

  const router = express.Router();
  router.use(express.json({ limit: '256kb' }));

  function creditsForUsd(amountUsd) {
    return Math.floor((amountUsd / pricePerMillion) * 1_000_000);
  }

  /**
   * A v2 PaymentRequirements object — just the terms of payment. Discovery
   * metadata (description, schemas) moved out to the top-level `resource` and
   * `extensions` of the 402 body in v2; it no longer lives per-`accepts` entry.
   */
  function requirementsFor(amountUsd, rail = primary) {
    /* T-789: extra.name/version MUST be the token contract's EIP-712
     * domain (scheme_exact_evm.md: "Used for transferWithAuthorization
     * signature construction"). Base mainnet USDC's domain name is
     * "USD Coin" (name() on 0x8335…2913), not the ticker — advertising
     * 'USDC' there made every spec-following client sign a digest the
     * contract would reject. Since T-954 the domain comes from the
     * per-chain registry in billing/x402-networks.js, never a literal. */
    return railSet.requirements(rail, amountUsd, MAX_TIMEOUT_SECONDS);
  }

  /** v2 top-level ResourceInfo — what the endpoint is, independent of price. */
  function resourceInfo(req) {
    return {
      url: resourceUrlForReq(req),
      description:
        `Linkrra inference credits — pay-as-you-go top-up ($${minUsd}-$${maxUsd}) ` +
        `at $${pricePerMillion}/M tokens`,
      mimeType: 'application/json',
      /* Bazaar-specific service metadata the spec allows alongside url/description/
       * mimeType — see docs.payai.network/x402/facilitators/bazaar §"Declaring your
       * resource". */
      serviceName: 'Linkrra Inference Credits',
      tags: ['inference', 'llm', 'credits', 'ai-compute'],
    };
  }

  /**
   * x402 Bazaar discovery (v2): declared once via `extensions.bazaar` on the 402
   * body. The buyer's client is required (per spec §5.1.2) to echo it back into
   * the payment payload; the facilitator then catalogs the resource from that
   * payload on /verify and /settle — there is no separate registration form.
   * `schema` is the JSON Schema our own `info` object below is written to
   * satisfy, per the Extensions object shape in spec §5.1.2.
   */
  function bazaarExtension() {
    return {
      info: {
        input: {
          type: 'http',
          method: 'POST',
          bodyType: 'json',
          body: { amountUsd: `number, ${minUsd}-${maxUsd}` },
        },
        output: {
          type: 'json',
          example: { ok: true, credits: creditsForUsd(minUsd), balance: creditsForUsd(minUsd) },
        },
      },
      schema: {
        type: 'object',
        required: ['input', 'output'],
        properties: {
          input: {
            type: 'object',
            required: ['type', 'method', 'bodyType', 'body'],
            properties: {
              type: { type: 'string' },
              method: { type: 'string' },
              bodyType: { type: 'string' },
              body: { type: 'object' },
            },
          },
          output: {
            type: 'object',
            required: ['type', 'example'],
            properties: {
              type: { type: 'string' },
              example: { type: 'object' },
            },
          },
        },
      },
    };
  }

  /** The full v2 PaymentRequired body — what a 402 (or a rejected retry) sends. */
  function paymentRequiredBody(amountUsd, error, req) {
    return {
      x402Version: X402_VERSION,
      error,
      resource: resourceInfo(req),
      accepts: railSet.accepts(amountUsd, MAX_TIMEOUT_SECONDS),
      extensions: { bazaar: bazaarExtension(), ...builderCodeExt },
    };
  }

  /**
   * Sends a PaymentRequired signal the v2 HTTP transport way: the
   * `PAYMENT-REQUIRED` header carries the base64-encoded object — that is
   * what a real v2 client (and the CDP Bazaar validator) actually reads — and
   * the JSON body carries the same object for a human with curl.
   */
  function sendPaymentRequired(res, status, amountUsd, error, req) {
    const body = paymentRequiredBody(amountUsd, error, req);
    res.set('PAYMENT-REQUIRED', encodeJsonHeader(body));
    res.status(status).json(body);
  }

  // -------------------------------------------------------------------------
  // GET /x402/info — machine-readable "can I pay you, and how"
  // -------------------------------------------------------------------------
  /* Cached because /info is a public endpoint an agent may poll, and the answer
   * changes only when the facilitator's own capabilities do. A failed probe is
   * cached as "unknown", not as "no" — an unreachable facilitator is an outage,
   * not a statement about which chains it settles. */
  const settlementProbes = new Map(); // rail.id -> { at, value }
  const SETTLEMENT_TTL_MS = 10 * 60 * 1000;

  async function settlementStatus(rail = primary) {
    const now = Date.now();
    const cached = settlementProbes.get(rail.id);
    if (cached && now - cached.at < SETTLEMENT_TTL_MS) return cached.value;
    const fac = rail.facilitator;
    if (!fac || typeof fac.supported !== 'function') return { ready: null, reason: null };
    let value;
    try {
      const supported = await fac.supported();
      const ready = facilitatorSettles(supported, rail.network);
      value = {
        ready,
        reason: ready
          ? null
          : `the configured facilitator does not settle "exact" on "${rail.network}" — ` +
            'set X402_FACILITATOR_URL (and key) to one that does, e.g. Coinbase CDP for Base mainnet',
      };
    } catch (err) {
      value = { ready: null, reason: `facilitator unreachable: ${err.message}` };
    }
    settlementProbes.set(rail.id, { at: now, value });
    return value;
  }

  /** Extra rails, with their own settlement probe — absent when none are configured. */
  async function extraRailsInfo() {
    const extras = railSet.rails.filter((r) => !r.isPrimary);
    if (!extras.length) return undefined;
    const summary = railSet.summary().filter((r) => !r.primary);
    return Promise.all(extras.map(async (rail, i) => {
      const s = rail.enabled ? await settlementStatus(rail) : { ready: null, reason: null };
      return { ...summary[i], settlementReady: s.ready, settlementNote: s.reason };
    }));
  }

  router.get('/x402/info', async (req, res) => {
    const settlement = enabled ? await settlementStatus() : { ready: null, reason: null };
    const additionalNetworks = enabled ? await extraRailsInfo() : undefined;
    res.json({
      /* enabled = we will quote a price. settlementReady = a payment against
       * that quote can actually complete. They are different questions and a
       * caller deserves both. */
      settlementReady: settlement.ready,
      settlementNote: settlement.reason,
      x402Version: X402_VERSION,
      enabled,
      reason: disabledReason,
      scheme: 'exact',
      network,
      testnet,
      asset,
      payTo,
      confirmOnChain,
      rpcUrl,
      resource: resourceUrlForReq(req),
      pricePerMillionTokensUsd: pricePerMillion,
      creditsPerToken: 1,
      minUsd,
      maxUsd,
      /* Named amounts so an agent does not have to guess a sensible top-up. */
      suggestedUsd: [1, 5, 25, 100].filter((v) => v >= minUsd && v <= maxUsd),
      /* T-954/T-952: other chains this resource also settles on (Celo, Arc).
       * The fields above describe the primary rail, unchanged. */
      additionalNetworks,
      note:
        'POST to the resource with {"amountUsd": N}. Without a PAYMENT-SIGNATURE ' +
        'header you get 402 and the payment requirements (in the PAYMENT-REQUIRED ' +
        'header, per x402 v2); retry the same request with the header to receive ' +
        'credits. The paying wallet address is your account.',
    });
  });

  // -------------------------------------------------------------------------
  // GET /x402/topup — the same 402 challenge, for read-only discovery probes
  // -------------------------------------------------------------------------
  /* T-789: the PayAI Bazaar catalog worker admits a verify-only POST resource
   * only when its read-only probe (HEAD, then GET) answers 402 Payment
   * Required (docs.payai.network/x402/facilitators/bazaar, "How listing
   * works"). A 404 here used to refuse the listing outright. Express serves
   * HEAD through this GET handler automatically. Quoted at minUsd — a probe
   * wants the challenge shape, not a binding price. */
  router.get('/x402/topup', (req, res) => {
    if (!enabled) {
      return res.status(503).json({ error: `x402 is not configured: ${disabledReason}` });
    }
    return sendPaymentRequired(
      res, 402, minUsd,
      'PAYMENT-SIGNATURE header is required — POST {"amountUsd": N} with it to pay', req,
    );
  });

  // -------------------------------------------------------------------------
  // POST /x402/topup — the 402 challenge, and the settlement that follows it
  // -------------------------------------------------------------------------
  router.post('/x402/topup', async (req, res) => {
    if (!enabled) {
      return res.status(503).json({ error: `x402 is not configured: ${disabledReason}` });
    }

    /* v2 HTTP transport (specs/transports-v2/http.md): the client's payment
     * header is PAYMENT-SIGNATURE, not v1's X-PAYMENT. */
    const header = req.get('PAYMENT-SIGNATURE');

    /* A discovery crawler (Bazaar validators, agents probing before they have
     * a price in mind) sends no body at all — it wants the 402 challenge, not
     * a 400. Default the quote to minUsd; a real caller with a PAYMENT-SIGNATURE
     * header is expected to have already read a quote and supplied a real
     * amountUsd, so a missing/invalid one there is still an error. */
    const bodyHasAmount = req.body?.amountUsd !== undefined;
    const amountUsd = bodyHasAmount ? Number(req.body.amountUsd) : minUsd;
    if (!Number.isFinite(amountUsd) || amountUsd < minUsd || amountUsd > maxUsd) {
      return res.status(400).json({ error: `amountUsd must be between ${minUsd} and ${maxUsd}` });
    }

    // --- no payment yet: quote the price in the protocol's own words --------
    if (!header) {
      return sendPaymentRequired(res, 402, amountUsd, 'PAYMENT-SIGNATURE header is required', req);
    }

    let payload;
    try {
      payload = decodePaymentHeader(header);
    } catch (err) {
      return sendPaymentRequired(
        res, 400, amountUsd, `PAYMENT-SIGNATURE header is not valid base64 JSON: ${err.message}`, req,
      );
    }

    /* T-954/T-952: settle on the rail the payer chose — its facilitator, its
     * requirements, its chain's RPC. An unoffered network/asset stops here,
     * before any facilitator call. */
    const chosen = railSet.select(payload);
    if (chosen.error) return sendPaymentRequired(res, 402, amountUsd, chosen.error, req);
    const rail = chosen.rail;
    const requirements = requirementsFor(amountUsd, rail);

    /* T-789: complete the unsigned envelope fields (accepted/resource/
     * extensions) before the facilitator sees it — see completePaymentPayload. */
    payload = completePaymentPayload(payload, requirements, paymentRequiredBody(amountUsd, undefined, req));
    /* T-953: the resource server is the authority for the builder-code `a`. */
    const echoError = builderCodeEchoError(payload, cfg.builderCode);
    if (echoError) return sendPaymentRequired(res, 402, amountUsd, echoError, req);

    // --- verify before settling --------------------------------------------
    // A settle on an invalid authorization would burn a facilitator call and,
    // worse, tell the caller nothing useful about why it failed.
    let verification;
    try {
      verification = await rail.facilitator.verify(payload, requirements);
    } catch (err) {
      console.error(`[x402] verify failed: ${err.message}`);
      return res.status(502).json({ error: 'payment verification is unavailable' });
    }

    if (!verification || verification.isValid !== true) {
      return sendPaymentRequired(
        res, 402, amountUsd, (verification && verification.invalidReason) || 'payment authorization rejected', req,
      );
    }

    // --- settle: this is the only step that produces a receipt --------------
    let settlement;
    try {
      settlement = await rail.facilitator.settle(payload, requirements);
    } catch (err) {
      console.error(`[x402] settle failed: ${err.message}`);
      return res.status(502).json({ error: 'payment settlement failed' });
    }

    const pending = settlementPendingResponse(settlement);
    if (pending) return res.status(202).json(pending);

    if (!settlement || settlement.success !== true || !settlement.transaction) {
      return sendPaymentRequired(
        res, 402, amountUsd, (settlement && settlement.errorReason) || 'settlement did not complete', req,
      );
    }

    /* Credit the amount that was actually authorized, not the amount that was
     * asked for. They are the same in the happy path; if they ever diverge, the
     * chain is right and the request body is not. */
    let paidAtomic = payload?.payload?.authorization?.value;

    /* And then check that claim against the chain itself. The facilitator is
     * infrastructure, not a witness — see confirmTransferOnChain. On success
     * the ON-CHAIN figure replaces the authorized one, because what landed in
     * the wallet is the only number that is true. */
    if (rail.confirmOnChain) {
      if (!rail.rpcUrl) {
        console.error(`[x402] no RPC configured for "${rail.network}" — refusing to credit unverified`);
        return res.status(500).json({ error: 'cannot verify settlement on-chain' });
      }
      let onchain;
      try {
        onchain = await confirmFn({
          rpcUrl: rail.rpcUrl, txHash: settlement.transaction, asset: rail.asset, payTo: rail.payTo,
        });
      } catch (err) {
        console.error(`[x402] on-chain confirmation failed: ${err.message}`);
        return res.status(502).json({
          error: 'settlement could not be confirmed on-chain — nothing credited',
          transaction: settlement.transaction,
        });
      }
      if (!onchain.ok) {
        /* not_yet_mined is a retry, the rest is a facilitator telling us
           something the chain does not agree with. Both refuse to credit; only
           one of them is worth alarming about. */
        const level = onchain.reason === 'not_yet_mined' ? 'warn' : 'error';
        console[level](
          `[x402] settlement ${settlement.transaction} not credited: ${onchain.reason}`
        );
        return res.status(onchain.reason === 'not_yet_mined' ? 202 : 402).json({
          error: onchain.reason === 'not_yet_mined'
            ? 'payment is not confirmed on-chain yet — retry shortly with the same header'
            : `settlement did not check out on-chain: ${onchain.reason}`,
          transaction: settlement.transaction,
        });
      }
      paidAtomic = onchain.receivedAtomic.toString();
    }

    const paidUsd = paidAtomic ? atomicToUsd(paidAtomic) : amountUsd;
    const credits = creditsForUsd(paidUsd);

    /* The settled transaction hash is the idempotency key. Replaying the same
     * PAYMENT-SIGNATURE header cannot mint a second batch of credits. */
    const settledNetwork = settlement.network || rail.network;
    const ref = `x402:${settledNetwork}:${settlement.transaction}`;

    /* Signed-in humans keep their existing balance; an anonymous agent's wallet
     * becomes its ledger address. */
    const address = req.account?.id || settlement.payer || verification.payer;
    if (!address) {
      console.error('[x402] settled payment with no payer address — cannot credit');
      return res.status(502).json({ error: 'settled payment had no payer address' });
    }

    let applied = false;
    try {
      applied = creditLedger.credit(
        address,
        credits,
        ref,
        `x402 ${settledNetwork} ${paidUsd} ${rail.symbol || 'USDC'}`,
        undefined,
        { usdMicro: usdToMicro(paidUsd), coalesce: true },
      );
    } catch (err) {
      console.error(`[x402] ledger credit failed for ${ref}: ${err.message}`);
      return res.status(500).json({ error: 'payment settled but crediting failed', ref });
    }

    /* T-758: first crypto deposit bonus — only a NEWLY applied top-up counts,
     * and noteDeposit itself enforces the $10–$50 window and one-per-account. */
    if (applied && promo) {
      try {
        promo.noteDeposit({ address, usdMicro: usdToMicro(paidUsd), credits, ref, rail: 'x402' });
      } catch (err) {
        console.error(`[promo] deposit note failed for ${address}: ${err.message}`);
      }
    }

    res.set('PAYMENT-RESPONSE', encodeJsonHeader(settlement));
    res.json({
      ok: true,
      credits,
      alreadyApplied: !applied,
      amountUsd: paidUsd,
      address,
      balance: creditLedger.getBalance(address),
      transaction: settlement.transaction,
      network: settledNetwork,
      note: applied
        ? 'Credits added. Use this wallet address as your account, or create an API key against it.'
        : 'This transaction was already credited.',
    });
  });

  return router;
}

/**
 * Shared verify -> settle -> (optional) on-chain confirm pipeline.
 *
 * /x402/topup and /x402/chat/completions (billing/x402-inference.js) both pay
 * through the same three facilitator calls, in the same order, with the same
 * refusal rules — a bug fixed here is fixed for every door that reuses it.
 * Deliberately does NOT touch the credit ledger: this function proves money
 * moved and says how much; what that buys (topup credits, one inference call)
 * is the caller's decision, made after this returns.
 *
 * @param {Object} args
 * @param {{verify: Function, settle: Function}} args.facilitator
 * @param {Object} args.payload — decoded PAYMENT-SIGNATURE
 * @param {Object} args.requirements — this request's PaymentRequirements
 * @param {boolean} args.confirmOnChain
 * @param {string|null} args.rpcUrl
 * @param {string|null} args.asset
 * @param {string|null} args.payTo
 * @param {Function} [args.confirmFn] — defaults to confirmTransferOnChain
 * @param {string} args.network — alias, for log lines and the fallback network label
 * @param {number} args.fallbackUsd — used only if confirmOnChain is false
 * @param {(error: string) => Object} args.buildPaymentRequiredBody — builds a
 *   v2 PaymentRequired body for this specific request, on any 402 outcome
 * @returns {Promise<
 *   {ok: true, paidUsd: number, payer: string, transaction: string, network: string, settlement: Object} |
 *   {ok: false, status: number, body: Object, isPaymentRequired: boolean}
 * >}
 */
/**
 * Complete a client's PaymentPayload envelope with the unsigned v2 fields the
 * spec (§5.2) says the CLIENT should carry: `accepted` (the chosen
 * PaymentRequirements), `resource`, and `extensions` echoed from our 402.
 *
 * WHY THE SERVER DOES THE CLIENT'S JOB (T-789): Bazaar discovery (PayAI, CDP)
 * catalogs a resource from the payment payload the facilitator receives on
 * /verify and /settle — docs.payai.network/x402/facilitators/bazaar is
 * explicit that the single biggest cause of "my resource never appears" is a
 * client that drops the `extensions` object. Many real clients (including
 * v1-era ones, and our own synap-buyer before T-789) send only
 * {x402Version, scheme, network, payload}. The facilitator verifies the
 * EIP-712 signature over `payload.authorization` ONLY, so filling in these
 * unsigned envelope fields cannot change what is paid or to whom — it only
 * guarantees our own discovery declaration survives the round trip no matter
 * the client's quality. Client-supplied values win on conflict (the spec lets
 * a client append but never lets anyone overwrite what it sent).
 */
function completePaymentPayload(payload, requirements, declaredBody) {
  if (!payload || typeof payload !== 'object') return payload;
  const out = { ...payload };
  if (!out.accepted || typeof out.accepted !== 'object') out.accepted = requirements;
  if (declaredBody && typeof declaredBody === 'object') {
    if (!out.resource && declaredBody.resource) out.resource = declaredBody.resource;
    if (declaredBody.extensions) {
      out.extensions = { ...declaredBody.extensions, ...(out.extensions || {}) };
    }
  }
  return out;
}

/**
 * T-952: Circle Facilitator Service answers a settlement it could not resolve
 * inside its wait window with HTTP 200, `success: false` and
 * `errorReason: "settlement_pending"` — "Pending is not failure: settlement
 * continues ... Do not fulfill on pending"
 * (developers.circle.com/api-reference/facilitator-service/settle-payment.md).
 * Answering that with a 402 would invite the buyer to sign a SECOND
 * authorization while the first is still landing: a double charge. So it is a
 * 202 telling the client to retry with the SAME header, which Circle resolves
 * to the same payment. Nothing is credited either way until the chain says so.
 * @returns {Object|null} the 202 body, or null when the settlement is not pending
 */
function settlementPendingResponse(settlement) {
  if (!settlement || settlement.success === true || settlement.errorReason !== 'settlement_pending') return null;
  const status = settlement.extensions && settlement.extensions['settlement-status'];
  return {
    error: 'payment settlement is pending — retry shortly with the SAME PAYMENT-SIGNATURE header; ' +
      'do not sign a new authorization',
    settlementPending: true,
    paymentId: (status && status.paymentId) || null,
  };
}

async function settleX402Payment({
  facilitator, payload, requirements, confirmOnChain, rpcUrl, asset, payTo,
  confirmFn = confirmTransferOnChain, network, fallbackUsd, buildPaymentRequiredBody,
  railSet = null, requirementsForRail = null,
}) {
  /* T-954/T-952: with a rail set, the payment is settled on the rail its own
   * `accepted.network`/asset names — that rail's facilitator, requirements,
   * RPC, token and payTo replace the single-network arguments above. An
   * unoffered network/asset is a 402 before any facilitator call. */
  let rail = null;
  if (railSet) {
    const chosen = railSet.select(payload);
    if (chosen.error) {
      return { ok: false, status: 402, body: buildPaymentRequiredBody(chosen.error), isPaymentRequired: true };
    }
    rail = chosen.rail;
    facilitator = rail.facilitator;
    requirements = typeof requirementsForRail === 'function' ? requirementsForRail(rail) : railSet.requirements(rail, fallbackUsd);
    confirmOnChain = rail.confirmOnChain;
    rpcUrl = rail.rpcUrl;
    asset = rail.asset;
    payTo = rail.payTo;
    network = rail.network;
  }

  /* T-789: every door that pays through this pipeline gets its discovery
   * declaration completed the same way — buildPaymentRequiredBody already
   * knows this request's resource + extensions. */
  if (typeof buildPaymentRequiredBody === 'function') {
    const declared = buildPaymentRequiredBody(undefined);
    payload = completePaymentPayload(payload, requirements, declared);
    /* T-953: reject an echoed builder-code `a` that is not the one this door declared,
     * before any facilitator call (spec: extension_echo_mismatch). */
    const declaredCode = declared?.extensions?.['builder-code']?.info?.a;
    const echoError = builderCodeEchoError(payload, declaredCode);
    if (echoError) {
      return { ok: false, status: 402, body: buildPaymentRequiredBody(echoError), isPaymentRequired: true };
    }
  }

  let verification;
  try {
    verification = await facilitator.verify(payload, requirements);
  } catch (err) {
    console.error(`[x402] verify failed: ${err.message}`);
    return { ok: false, status: 502, body: { error: 'payment verification is unavailable' }, isPaymentRequired: false };
  }

  if (!verification || verification.isValid !== true) {
    return {
      ok: false,
      status: 402,
      body: buildPaymentRequiredBody((verification && verification.invalidReason) || 'payment authorization rejected'),
      isPaymentRequired: true,
    };
  }

  let settlement;
  try {
    settlement = await facilitator.settle(payload, requirements);
  } catch (err) {
    console.error(`[x402] settle failed: ${err.message}`);
    return { ok: false, status: 502, body: { error: 'payment settlement failed' }, isPaymentRequired: false };
  }

  const pending = settlementPendingResponse(settlement);
  if (pending) return { ok: false, status: 202, body: pending, isPaymentRequired: false };

  if (!settlement || settlement.success !== true || !settlement.transaction) {
    return {
      ok: false,
      status: 402,
      body: buildPaymentRequiredBody((settlement && settlement.errorReason) || 'settlement did not complete'),
      isPaymentRequired: true,
    };
  }

  let paidAtomic = payload?.payload?.authorization?.value;

  if (confirmOnChain) {
    if (!rpcUrl) {
      console.error(`[x402] no RPC configured for "${network}" — refusing to accept payment unverified`);
      return { ok: false, status: 500, body: { error: 'cannot verify settlement on-chain' }, isPaymentRequired: false };
    }
    let onchain;
    try {
      onchain = await confirmFn({ rpcUrl, txHash: settlement.transaction, asset, payTo });
    } catch (err) {
      console.error(`[x402] on-chain confirmation failed: ${err.message}`);
      return {
        ok: false,
        status: 502,
        body: { error: 'settlement could not be confirmed on-chain — nothing charged', transaction: settlement.transaction },
        isPaymentRequired: false,
      };
    }
    if (!onchain.ok) {
      const level = onchain.reason === 'not_yet_mined' ? 'warn' : 'error';
      console[level](`[x402] settlement ${settlement.transaction} not accepted: ${onchain.reason}`);
      return {
        ok: false,
        status: onchain.reason === 'not_yet_mined' ? 202 : 402,
        body: {
          error: onchain.reason === 'not_yet_mined'
            ? 'payment is not confirmed on-chain yet — retry shortly with the same header'
            : `settlement did not check out on-chain: ${onchain.reason}`,
          transaction: settlement.transaction,
        },
        isPaymentRequired: false,
      };
    }
    paidAtomic = onchain.receivedAtomic.toString();
  }

  const paidUsd = paidAtomic ? atomicToUsd(paidAtomic) : fallbackUsd;
  const payer = settlement.payer || verification.payer;
  if (!payer) {
    console.error('[x402] settled payment with no payer address');
    return { ok: false, status: 502, body: { error: 'settled payment had no payer address' }, isPaymentRequired: false };
  }

  return {
    ok: true,
    paidUsd,
    payer,
    transaction: settlement.transaction,
    network: settlement.network || network,
    symbol: (rail && rail.symbol) || 'USDC',
    settlement,
  };
}

module.exports = {
  createX402Router,
  FacilitatorClient,
  usdToAtomic,
  atomicToUsd,
  decodePaymentHeader,
  encodeJsonHeader,
  USDC_BY_NETWORK,
  TESTNET_NETWORKS,
  isTestnet,
  facilitatorSettles,
  confirmTransferOnChain,
  completePaymentPayload,
  settleX402Payment,
  settlementPendingResponse,
  RPC_BY_NETWORK,
  CAIP2_BY_NETWORK,
  X402_VERSION,
};
