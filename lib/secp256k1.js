'use strict';

/**
 * @fileoverview secp256k1 ECDSA — sign, recover, and derive an EVM address —
 * plus the EIP-712 typed-data hash, with no dependency.
 *
 * WHY THIS EXISTS (T-952/T-954, 2026-10-17): Circle's Facilitator Service
 * keyless trial authenticates a seller with a `Facilitator-Seller-Proof`
 * header — an EIP-712 signature by the key that controls `payTo`
 * (developers.circle.com/facilitator-service/sign-seller-proof.md). This
 * package deliberately ships no crypto library (see lib/evm-address.js for
 * the Keccak it already had to carry), and adding ethers/viem to a money
 * path for one signature would put a large, fast-moving dependency between
 * us and the wire. The curve maths below is the textbook algorithm; the
 * nonce is RFC 6979 (deterministic, HMAC-SHA256 from node:crypto), so the
 * same key and digest give byte-for-byte the signature eth_account gives —
 * and the tests pin exactly that against vectors produced by eth_account.
 *
 * Not constant-time. It signs at most a few times per paid request on a
 * server whose key, in the keyless mode, is a testnet or trial key; it is not
 * a wallet. A production deployment authenticates with a Circle API key and
 * never calls sign() at all.
 */

const crypto = require('node:crypto');
const { keccak256 } = require('./evm-address');

const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const G = [
  0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
  0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n,
];

const mod = (a, m) => { const r = a % m; return r >= 0n ? r : r + m; };

function inv(a, m) {
  let [r0, r1] = [mod(a, m), m];
  let [s0, s1] = [1n, 0n];
  while (r1 !== 0n) {
    const q = r0 / r1;
    [r0, r1] = [r1, r0 - q * r1];
    [s0, s1] = [s1, s0 - q * s1];
  }
  if (r0 !== 1n) throw new Error('not invertible');
  return mod(s0, m);
}

function pointAdd(a, b) {
  if (a === null) return b;
  if (b === null) return a;
  if (a[0] === b[0]) {
    if (mod(a[1] + b[1], P) === 0n) return null;
    const l = mod(3n * a[0] * a[0] * inv(2n * a[1], P), P);
    const x = mod(l * l - 2n * a[0], P);
    return [x, mod(l * (a[0] - x) - a[1], P)];
  }
  const l = mod((b[1] - a[1]) * inv(b[0] - a[0], P), P);
  const x = mod(l * l - a[0] - b[0], P);
  return [x, mod(l * (a[0] - x) - a[1], P)];
}

function pointMul(k, pt) {
  let result = null;
  let addend = pt;
  let n = k;
  while (n > 0n) {
    if (n & 1n) result = pointAdd(result, addend);
    addend = pointAdd(addend, addend);
    n >>= 1n;
  }
  return result;
}

const toBig = (buf) => BigInt('0x' + (Buffer.from(buf).toString('hex') || '0'));
const to32 = (n) => Buffer.from(n.toString(16).padStart(64, '0'), 'hex');

function parseKey(privateKey) {
  const hex = String(privateKey).replace(/^0x/i, '');
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) throw new TypeError('private key must be 32 bytes of hex');
  const d = BigInt('0x' + hex);
  if (d <= 0n || d >= N) throw new RangeError('private key out of range');
  return d;
}

function parseDigest(digest) {
  const buf = Buffer.isBuffer(digest) ? digest : Buffer.from(String(digest).replace(/^0x/i, ''), 'hex');
  if (buf.length !== 32) throw new TypeError('digest must be 32 bytes');
  return buf;
}

function addressOfPoint(pt) {
  return '0x' + keccak256(Buffer.concat([to32(pt[0]), to32(pt[1])])).slice(-40);
}

/** Lowercase 0x address controlled by a private key. */
function addressFromPrivateKey(privateKey) {
  return addressOfPoint(pointMul(parseKey(privateKey), G));
}

/** RFC 6979 §3.2 nonce generator (HMAC-SHA256), yielding candidate k values. */
function* rfc6979(d, digest) {
  const x = to32(d);
  const h1 = to32(mod(toBig(digest), N));
  const hmac = (key, ...parts) => crypto.createHmac('sha256', key).update(Buffer.concat(parts)).digest();
  let v = Buffer.alloc(32, 0x01);
  let k = Buffer.alloc(32, 0x00);
  k = hmac(k, v, Buffer.from([0x00]), x, h1);
  v = hmac(k, v);
  k = hmac(k, v, Buffer.from([0x01]), x, h1);
  v = hmac(k, v);
  for (;;) {
    v = hmac(k, v);
    const candidate = toBig(v);
    if (candidate >= 1n && candidate < N) yield candidate;
    k = hmac(k, v, Buffer.from([0x00]));
    v = hmac(k, v);
  }
}

/**
 * Sign a 32-byte digest. Returns the Ethereum 65-byte form r‖s‖v with low-s
 * (EIP-2) and v ∈ {27, 28} — the form Circle requires ("EOA signatures must
 * use a v value of 27 or 28").
 */
function signDigest(digest, privateKey) {
  const d = parseKey(privateKey);
  const z = toBig(parseDigest(digest));
  for (const k of rfc6979(d, parseDigest(digest))) {
    const R = pointMul(k, G);
    const r = mod(R[0], N);
    if (r === 0n) continue;
    let s = mod(inv(k, N) * (z + r * d), N);
    if (s === 0n) continue;
    let recovery = Number(R[1] & 1n) | (R[0] >= N ? 2 : 0);
    if (s > N / 2n) { s = N - s; recovery ^= 1; }
    if (recovery > 1) continue; // astronomically rare; Ethereum's v cannot carry it
    return '0x' + to32(r).toString('hex') + to32(s).toString('hex') + (27 + recovery).toString(16);
  }
  throw new Error('unreachable');
}

/** Recover the signer address of a 65-byte r‖s‖v signature over a digest. */
function recoverAddress(digest, signature) {
  const hex = String(signature).replace(/^0x/i, '');
  if (hex.length !== 130) throw new TypeError('signature must be 65 bytes');
  const r = BigInt('0x' + hex.slice(0, 64));
  const s = BigInt('0x' + hex.slice(64, 128));
  let v = parseInt(hex.slice(128), 16);
  if (v >= 27) v -= 27;
  if (r <= 0n || r >= N || s <= 0n || s >= N || (v !== 0 && v !== 1)) throw new Error('invalid signature');
  const x = r;
  const alpha = mod(x * x * x + 7n, P);
  let y = modPow(alpha, (P + 1n) / 4n, P);
  if (mod(y * y, P) !== alpha) throw new Error('invalid signature');
  if (Number(y & 1n) !== v) y = P - y;
  const z = toBig(parseDigest(digest));
  const rInv = inv(r, N);
  const Q = pointAdd(pointMul(mod(s * rInv, N), [x, y]), pointMul(mod(-z * rInv, N), G));
  if (Q === null) throw new Error('invalid signature');
  return addressOfPoint(Q);
}

function modPow(b, e, m) {
  let result = 1n;
  let base = mod(b, m);
  let exp = e;
  while (exp > 0n) {
    if (exp & 1n) result = mod(result * base, m);
    base = mod(base * base, m);
    exp >>= 1n;
  }
  return result;
}

// ---------------------------------------------------------------------------
// EIP-712 — flat structs of atomic types only (what a seller proof uses).
// A nested struct or an array throws instead of hashing something wrong.
// ---------------------------------------------------------------------------

const k256 = (buf) => Buffer.from(keccak256(buf), 'hex');

function encodeAtomic(type, value) {
  if (type === 'string') return k256(Buffer.from(String(value), 'utf8'));
  if (type === 'bytes') return k256(Buffer.from(String(value).replace(/^0x/i, ''), 'hex'));
  if (type === 'address') {
    const hex = String(value).replace(/^0x/i, '');
    if (!/^[0-9a-fA-F]{40}$/.test(hex)) throw new TypeError(`bad address: ${value}`);
    return Buffer.from(hex.toLowerCase().padStart(64, '0'), 'hex');
  }
  if (type === 'bool') return to32(value ? 1n : 0n);
  let m = /^uint(\d+)$/.exec(type);
  if (m) {
    const n = BigInt(value);
    if (n < 0n || n >= (1n << BigInt(m[1]))) throw new RangeError(`${type} out of range: ${value}`);
    return to32(n);
  }
  m = /^bytes(\d+)$/.exec(type);
  if (m) {
    const hex = String(value).replace(/^0x/i, '');
    if (hex.length !== Number(m[1]) * 2) throw new TypeError(`${type} must be ${m[1]} bytes`);
    return Buffer.from(hex.padEnd(64, '0'), 'hex');
  }
  throw new TypeError(`unsupported EIP-712 type: ${type}`);
}

function hashStruct(name, fields, message) {
  const typeString = `${name}(${fields.map((f) => `${f.type} ${f.name}`).join(',')})`;
  const parts = [k256(Buffer.from(typeString, 'utf8'))];
  for (const f of fields) parts.push(encodeAtomic(f.type, message[f.name]));
  return k256(Buffer.concat(parts));
}

const DOMAIN_FIELDS = [
  { name: 'name', type: 'string' },
  { name: 'version', type: 'string' },
  { name: 'chainId', type: 'uint256' },
  { name: 'verifyingContract', type: 'address' },
  { name: 'salt', type: 'bytes32' },
];

/** EIP-712 digest: keccak256(0x1901 ‖ domainSeparator ‖ hashStruct(message)). */
function hashTypedData({ domain, types, primaryType, message }) {
  const domainFields = DOMAIN_FIELDS.filter((f) => domain[f.name] !== undefined);
  const fields = types[primaryType];
  if (!Array.isArray(fields)) throw new TypeError(`unknown primaryType ${primaryType}`);
  return k256(Buffer.concat([
    Buffer.from([0x19, 0x01]),
    hashStruct('EIP712Domain', domainFields, domain),
    hashStruct(primaryType, fields, message),
  ]));
}

module.exports = {
  signDigest,
  recoverAddress,
  addressFromPrivateKey,
  hashTypedData,
};
