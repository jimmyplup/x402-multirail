'use strict';

/**
 * Minimal paid endpoint on several x402 rails at once.
 *
 *   X402_PAY_TO=0xYourAddress X402_NETWORK=celo-sepolia X402_ALLOW_TESTNET_CREDIT=1 \
 *   X402_FACILITATOR_API_KEY=<Celo key, from x402.celo.org> \
 *   X402_EXTRA_NETWORKS=arc-testnet X402_ARC_TESTNET_ALLOW_TESTNET_CREDIT=1 \
 *   X402_ARC_TESTNET_PAY_TO=0xKeyedAddress X402_ARC_TESTNET_SELLER_PROOF_KEY=0x… \
 *   node server.example.js
 *
 * GET /paid/hello without PAYMENT-SIGNATURE -> 402 listing every enabled rail.
 * With one -> verified + settled by THAT rail's facilitator, confirmed on THAT
 * chain's RPC, then served. Testnet values only; read README before mainnet.
 */

const express = require('express');
const { createRailSet, extraRailsFromEnv } = require('./billing/x402-rails');
const { resolveNetwork } = require('./billing/x402-networks');
const { settleX402Payment, decodePaymentHeader, encodeJsonHeader, X402_VERSION } = require('./billing/x402');

const PRICE_USD = 0.01;
const network = process.env.X402_NETWORK || 'celo-sepolia';
const net = resolveNetwork(network);
const cfg = {
  payTo: process.env.X402_PAY_TO,
  network,
  allowTestnetCredit: process.env.X402_ALLOW_TESTNET_CREDIT === '1',
  facilitatorUrl: process.env.X402_FACILITATOR_URL || (net && net.facilitator && net.facilitator.url),
  facilitatorApiKey: process.env.X402_FACILITATOR_API_KEY || null,
};
cfg.extraRails = extraRailsFromEnv(process.env, cfg);
const rails = createRailSet(cfg);

const app = express();

function paymentRequired(error) {
  return {
    x402Version: X402_VERSION,
    error,
    resource: { url: '/paid/hello', description: 'A paid hello', mimeType: 'application/json' },
    accepts: rails.accepts(PRICE_USD),
  };
}

app.get('/paid/hello', async (req, res) => {
  const header = req.get('PAYMENT-SIGNATURE');
  if (!header) {
    const body = paymentRequired('PAYMENT-SIGNATURE header is required');
    res.set('PAYMENT-REQUIRED', encodeJsonHeader(body));
    return res.status(402).json(body);
  }
  let payload;
  try { payload = decodePaymentHeader(header); } catch (err) { return res.status(400).json({ error: err.message }); }

  const settled = await settleX402Payment({
    payload,
    railSet: rails,
    requirementsForRail: (rail) => rails.requirements(rail, PRICE_USD),
    fallbackUsd: PRICE_USD,
    buildPaymentRequiredBody: paymentRequired,
  });
  if (!settled.ok) {
    if (settled.isPaymentRequired) res.set('PAYMENT-REQUIRED', encodeJsonHeader(settled.body));
    return res.status(settled.status).json(settled.body);
  }
  if (settled.paidUsd + 1e-6 < PRICE_USD) return res.status(402).json(paymentRequired('underpaid'));
  res.set('PAYMENT-RESPONSE', encodeJsonHeader(settled.settlement));
  return res.json({ hello: 'paid world', paidUsd: settled.paidUsd, network: settled.network, transaction: settled.transaction });
});

const port = Number(process.env.PORT || 4021);
app.listen(port, () => {
  console.log(`listening on :${port}; rails:`);
  for (const r of rails.summary()) console.log(`  ${r.caip2} ${r.symbol} enabled=${r.enabled}${r.reason ? ` (${r.reason})` : ''}`);
});
