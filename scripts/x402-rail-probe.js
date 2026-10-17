#!/usr/bin/env node
'use strict';

/**
 * ops/x402-rail-probe.js — prove every x402 rail is PAYABLE by a stranger, at $0.
 *
 * T-954 (Celo) / T-952 (Arc), 2026-10-17. "The rail is live" (our 402 lists
 * it) and "the rail is sellable" (a third party's facilitator accepts a
 * signature built from that 402) are different receipts — T-789 is what
 * happens when only the first one is checked. This script produces the second
 * one without spending anything:
 *
 *   1. It mounts the REAL top-up door (billing/x402.js createX402Router) in
 *      this process, configured with the rails under test, on 127.0.0.1.
 *   2. It asks that door for a 402, and for every `accepts[]` entry signs an
 *      EIP-3009 TransferWithAuthorization exactly as a spec-following client
 *      does — domain from extra.name/version, chainId from the CAIP-2 id,
 *      verifyingContract = asset — with a THROWAWAY key generated in memory for
 *      this run (never stored, never funded).
 *   3. It retries with PAYMENT-SIGNATURE. The door sends it to the rail's real
 *      facilitator (Celo's, Circle's). An unfunded payer cannot settle, so the
 *      best possible answer is "insufficient funds" — which is only reachable
 *      AFTER the facilitator has recovered our signature against the token's
 *      real EIP-712 domain. "invalid signature" means the rail is broken.
 *
 * Nothing can be paid: the payer holds nothing, and /settle is never reached
 * because /verify refuses first. Circle's keyless trial needs a seller proof
 * from the key controlling payTo, so the Arc rails use a second throwaway key
 * as payTo — a probe address, not ours.
 *
 * Usage:
 *   node ops/x402-rail-probe.js                 # celo, celo-sepolia, arc, arc-testnet
 *   node ops/x402-rail-probe.js --rails celo    # subset
 *   node ops/x402-rail-probe.js --json          # machine-readable
 * Exit 0 only if every probed rail reached a balance/funds verdict.
 */

const path = require('node:path');
const crypto = require('node:crypto');
const http = require('node:http');

const CREDITS = path.join(__dirname, '..');
const express = require('express');
const { createX402Router } = require(path.join(CREDITS, 'billing', 'x402'));
const { CreditLedger } = require(path.join(CREDITS, 'lib', 'credit-ledger'));
const { signDigest, addressFromPrivateKey, hashTypedData } = require(path.join(CREDITS, 'lib', 'secp256k1'));

const args = process.argv.slice(2);
const asJson = args.includes('--json');
const railsArg = args.includes('--rails') ? args[args.indexOf('--rails') + 1] : 'celo,celo-sepolia,arc,arc-testnet';
const wanted = railsArg.split(',').map((s) => s.trim()).filter(Boolean);

/** Verdicts that can only be produced after the signature was accepted. */
const FUNDS_VERDICT = /insufficient|balance|funds/i;
const SIGNATURE_VERDICT = /signature/i;

const freshKey = () => '0x' + crypto.randomBytes(32).toString('hex');

function railSpecs(payToMain, arcKey) {
  const arcPayTo = addressFromPrivateKey(arcKey);
  const all = {
    celo: [
      { network: 'celo', asset: 'USDC', payTo: payToMain },
      { network: 'celo', asset: 'USDT', payTo: payToMain },
      { network: 'celo', asset: 'USAT', payTo: payToMain },
    ],
    'celo-sepolia': [{ network: 'celo-sepolia', asset: 'USDC', payTo: payToMain, allowTestnetCredit: true }],
    arc: [{ network: 'arc', asset: 'USDC', payTo: arcPayTo, sellerProofKey: arcKey }],
    'arc-testnet': [{ network: 'arc-testnet', asset: 'USDC', payTo: arcPayTo, sellerProofKey: arcKey, allowTestnetCredit: true }],
  };
  return wanted.flatMap((n) => {
    if (!all[n]) throw new Error(`unknown rail "${n}" (known: ${Object.keys(all).join(', ')})`);
    return all[n];
  });
}

function signExact(requirements, payerKey) {
  const from = addressFromPrivateKey(payerKey);
  const nonce = '0x' + crypto.randomBytes(32).toString('hex');
  const validBefore = String(Math.floor(Date.now() / 1000) + 110);
  const message = { from, to: requirements.payTo, value: requirements.amount, validAfter: '0', validBefore, nonce };
  const digest = hashTypedData({
    domain: {
      name: requirements.extra.name,
      version: requirements.extra.version,
      chainId: Number(requirements.network.split(':')[1]),
      verifyingContract: requirements.asset,
    },
    types: {
      TransferWithAuthorization: [
        { name: 'from', type: 'address' }, { name: 'to', type: 'address' },
        { name: 'value', type: 'uint256' }, { name: 'validAfter', type: 'uint256' },
        { name: 'validBefore', type: 'uint256' }, { name: 'nonce', type: 'bytes32' },
      ],
    },
    primaryType: 'TransferWithAuthorization',
    message,
  });
  return { signature: signDigest(digest, payerKey), authorization: message };
}

async function main() {
  // The receive-only address the live Base rail already publishes; probes on
  // Celo never move funds to it (the payer is empty), they only name it.
  const payToMain = '0xAA0a350f6080940c138A8A50C0Fa8c8387782eb4';
  const payerKey = freshKey();
  const arcKey = freshKey();
  const extraRails = railSpecs(payToMain, arcKey);

  const ledger = new CreditLedger(':memory:');
  const app = express();
  app.use('/api/billing', createX402Router({
    creditLedger: ledger,
    pricePerMillion: 0.2273,
    // Primary: Base, unchanged — included so the probe also shows it is untouched.
    config: { payTo: payToMain, network: 'base', facilitatorUrl: 'https://facilitator.payai.network', extraRails },
  }));
  const server = http.createServer(app);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${server.address().port}/api/billing/x402/topup`;

  const results = [];
  try {
    const challenge = await fetch(base, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ amountUsd: 1 }),
    });
    const body = await challenge.json();
    if (challenge.status !== 402) throw new Error(`expected 402, got ${challenge.status}: ${JSON.stringify(body)}`);

    async function attempt(req, signWith) {
      const signed = signExact(signWith, payerKey);
      const envelope = {
        x402Version: 2, accepted: req, resource: body.resource, extensions: body.extensions, payload: signed,
      };
      const res = await fetch(base, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'PAYMENT-SIGNATURE': Buffer.from(JSON.stringify(envelope)).toString('base64'),
        },
        body: JSON.stringify({ amountUsd: 1 }),
      });
      const out = await res.json().catch(() => ({}));
      return { status: res.status, verdict: String(out.error || '') };
    }

    for (const req of body.accepts.slice(1)) { // [0] is Base; the probe is about the new rails
      const started = Date.now();
      const real = await attempt(req, req);
      /* CONTROL: the same payment signed over a deliberately WRONG domain name.
       * It must come back as a signature failure. If it also says
       * "insufficient funds", this facilitator checks balance before the
       * signature and the real verdict above proves nothing — reported as such. */
      const control = await attempt(req, { ...req, extra: { ...req.extra, name: `${req.extra.name} WRONG` } });
      const realOk = FUNDS_VERDICT.test(real.verdict) && !SIGNATURE_VERDICT.test(real.verdict);
      const controlCaught = SIGNATURE_VERDICT.test(control.verdict) || /invalid_payload|invalid_exact/i.test(control.verdict);
      results.push({
        network: req.network,
        asset: req.asset,
        domain: `${req.extra.name} v${req.extra.version}`,
        httpStatus: real.status,
        facilitatorVerdict: real.verdict,
        controlVerdict: control.verdict,
        signatureAccepted: realOk && controlCaught,
        ms: Date.now() - started,
      });
    }
  } finally {
    server.closeAllConnections?.();
    server.close();
    ledger.close();
  }

  const ok = results.length > 0 && results.every((r) => r.signatureAccepted);
  const report = {
    at: new Date().toISOString(),
    payer: addressFromPrivateKey(payerKey) + ' (throwaway, unfunded, never stored)',
    arcProbePayTo: addressFromPrivateKey(arcKey) + ' (throwaway seller-proof key)',
    ok,
    results,
  };
  if (asJson) console.log(JSON.stringify(report, null, 2));
  else {
    for (const r of results) {
      console.log(`${r.signatureAccepted ? 'PASS' : 'FAIL'}  ${r.network} ${r.asset} [${r.domain}] -> ${r.httpStatus} "${r.facilitatorVerdict}" | control (wrong domain) -> "${r.controlVerdict}" (${r.ms} ms)`);
    }
    console.log(ok ? 'ALL RAILS PAYABLE (signature accepted, refused only for funds)' : 'AT LEAST ONE RAIL IS NOT PAYABLE');
  }
  process.exit(ok ? 0 : 1);
}

main().catch((err) => { console.error(`probe failed to run: ${err.message}`); process.exit(2); });
