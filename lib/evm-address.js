'use strict';

/**
 * @fileoverview Validation of an EVM address a payout will be sent to.
 *
 * A payout to a mistyped address is gone for good, so the one defence the
 * format offers is used: the EIP-55 mixed-case checksum. An address written in
 * mixed case MUST pass it. One written in a single case carries no checksum at
 * all and is accepted as-is (wallets and explorers emit both forms); it is
 * stored in checksummed form either way, so what we show back to the operator
 * is the form a typo cannot survive.
 *
 * EIP-55 needs Keccak-256 — the original Keccak, not the NIST SHA3-256 that
 * `node:crypto` ships (different padding, different digest). There is no
 * dependency in this package that provides it, so it is implemented here,
 * and pinned by known vectors in the tests.
 */

const MASK = (1n << 64n) - 1n;
const RC = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];
const ROT = [
  0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];
const rotl = (x, n) => (n === 0 ? x : ((x << BigInt(n)) | (x >> BigInt(64 - n))) & MASK);

function keccakF(s) {
  for (let round = 0; round < 24; round++) {
    const c = new Array(5);
    for (let x = 0; x < 5; x++) c[x] = s[x] ^ s[x + 5] ^ s[x + 10] ^ s[x + 15] ^ s[x + 20];
    for (let x = 0; x < 5; x++) {
      const d = c[(x + 4) % 5] ^ rotl(c[(x + 1) % 5], 1);
      for (let y = 0; y < 25; y += 5) s[x + y] ^= d;
    }
    const b = new Array(25);
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        b[y + ((2 * x + 3 * y) % 5) * 5] = rotl(s[x + 5 * y], ROT[x + 5 * y]);
      }
    }
    for (let y = 0; y < 25; y += 5) {
      for (let x = 0; x < 5; x++) {
        s[x + y] = b[x + y] ^ ((~b[((x + 1) % 5) + y] & MASK) & b[((x + 2) % 5) + y]);
      }
    }
    s[0] ^= RC[round];
  }
}

/**
 * Keccak-256 (the Ethereum hash; NOT SHA3-256).
 * @param {Buffer|string} input - a string is hashed as UTF-8
 * @returns {string} 64 lowercase hex characters
 */
function keccak256(input) {
  const data = Buffer.isBuffer(input) ? input : Buffer.from(String(input), 'utf8');
  const rate = 136;
  const padded = Buffer.alloc(Math.ceil((data.length + 1) / rate) * rate);
  data.copy(padded);
  padded[data.length] ^= 0x01;
  padded[padded.length - 1] ^= 0x80;

  const s = new Array(25).fill(0n);
  for (let off = 0; off < padded.length; off += rate) {
    for (let i = 0; i < rate / 8; i++) s[i] ^= padded.readBigUInt64LE(off + i * 8);
    keccakF(s);
  }
  const out = Buffer.alloc(32);
  for (let i = 0; i < 4; i++) out.writeBigUInt64LE(s[i], i * 8);
  return out.toString('hex');
}

/**
 * The EIP-55 checksummed form of 40 hex characters.
 * @param {string} hex40 - no 0x prefix, any case
 * @returns {string} `0x…` in checksum case
 */
function toChecksumAddress(hex40) {
  const lower = hex40.toLowerCase();
  const hash = keccak256(lower);
  let out = '0x';
  for (let i = 0; i < 40; i++) {
    out += parseInt(hash[i], 16) >= 8 ? lower[i].toUpperCase() : lower[i];
  }
  return out;
}

/**
 * Validate an address a payout may be sent to.
 *
 * @param {*} raw
 * @returns {{ok:true, address:string}|{ok:false, reason:string}} `address` is
 *   the checksummed form.
 */
function validateEvmAddress(raw) {
  if (typeof raw !== 'string') return { ok: false, reason: 'address must be a string' };
  const trimmed = raw.trim();
  if (!/^0x[0-9a-fA-F]{40}$/.test(trimmed)) {
    return { ok: false, reason: 'not an EVM address: expected 0x followed by 40 hex characters' };
  }
  const hex = trimmed.slice(2);
  if (/^0+$/.test(hex)) return { ok: false, reason: 'the zero address cannot receive a payout' };

  const checksummed = toChecksumAddress(hex);
  const singleCase = hex === hex.toLowerCase() || hex === hex.toUpperCase();
  if (!singleCase && trimmed !== checksummed) {
    return { ok: false, reason: 'address checksum does not match — it has been mistyped or altered' };
  }
  return { ok: true, address: checksummed };
}

module.exports = { keccak256, toChecksumAddress, validateEvmAddress };
