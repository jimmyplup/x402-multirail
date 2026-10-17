'use strict';

/**
 * @fileoverview Dollars as integer millionths ("micro-USD").
 *
 * Everything that decides what a node operator is owed is counted in this
 * unit and never in floats: a float balance drifts, and drift in a payout
 * ledger is somebody's money. One micro-USD is also exactly one atomic unit
 * of USDC (6 decimals), so an accrued balance is already the on-chain amount.
 */

const MICRO_PER_USD = 1_000_000;

/**
 * Dollars → integer micro-USD. Anything that is not a real, positive amount is
 * 0: an unknown payment must never be counted as revenue.
 * @param {number} usd
 * @returns {number}
 */
function usdToMicro(usd) {
  const n = Number(usd);
  if (!Number.isFinite(n) || n <= 0) return 0;
  const micro = Math.round(n * MICRO_PER_USD);
  return Number.isSafeInteger(micro) ? micro : 0;
}

/** Integer micro-USD → a decimal string with six places, for display only. */
function microToUsdString(micro) {
  const n = BigInt(micro);
  const neg = n < 0n;
  const abs = neg ? -n : n;
  const whole = abs / BigInt(MICRO_PER_USD);
  const frac = String(abs % BigInt(MICRO_PER_USD)).padStart(6, '0');
  return `${neg ? '-' : ''}${whole}.${frac}`;
}

module.exports = { usdToMicro, microToUsdString, MICRO_PER_USD };
