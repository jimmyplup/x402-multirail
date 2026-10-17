'use strict';

/**
 * x402 `builder-code` extension — on-chain attribution for our settlements (T-953).
 *
 * Base attributes onchain activity to an app through a Builder Code (ERC-8021): a short
 * code appended to the settlement transaction's calldata. For x402 we never send the
 * settlement ourselves — the facilitator does — so the x402 spec routes the code through
 * the payment: we DECLARE our app code `a` in the 402 body's `extensions["builder-code"]`,
 * the payment payload echoes it, and a facilitator that implements the extension appends
 * the ERC-8021 Schema 2 suffix to the settlement tx it submits.
 * Spec: github.com/x402-foundation/x402/blob/main/specs/extensions/builder_code.md
 *
 * What this module owns:
 *   - validating and declaring our code (`builderCodeExtension`), so a typo in
 *     X402_BUILDER_CODE fails at boot instead of silently attributing nothing;
 *   - the resource server's two MUSTs before forwarding a payment (`builderCodeEchoError`):
 *     an echoed `a` that is not ours, and an `s` list padded past the combined budget;
 *   - encoding/parsing the Schema 2 suffix, so attribution can be CHECKED on a real tx
 *     hash rather than assumed (`parseBuilderCodeSuffix`), and so a sender we run ourselves
 *     (the payout engine, once T-680 arms it) can tag its own transactions.
 *
 * What it deliberately does not do: change anything that is signed or paid. The extension
 * lives in the unsigned envelope; the EIP-3009 authorization the facilitator verifies is
 * untouched, so declaring a code cannot alter amount, payer or recipient.
 */

const BUILDER_CODE_KEY = 'builder-code';
const BUILDER_CODE_RE = /^[a-z0-9_]{1,32}$/;
const MAX_CLIENT_SERVICE_CODES = 5;
const MAX_SERVER_SERVICE_CODES = 5;
const MAX_SERVICE_CODES = 11; // client 5 + server 5 + facilitator 1
const ERC8021_MARKER = '80218021802180218021802180218021';
const SCHEMA_2 = 0x02;

/* Verbatim from the spec's PaymentRequired example (and @x402/extensions server.ts). */
const BUILDER_CODE_SCHEMA = Object.freeze({
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  type: 'object',
  properties: {
    a: { type: 'string', pattern: '^[a-z0-9_]{1,32}$', description: 'App builder code' },
    w: { type: 'string', pattern: '^[a-z0-9_]{1,32}$', description: 'Wallet builder code' },
    s: {
      type: 'array',
      maxItems: MAX_SERVICE_CODES,
      items: { type: 'string', pattern: '^[a-z0-9_]{1,32}$' },
      description: 'Service builder codes',
    },
  },
  additionalProperties: false,
});

function isBuilderCode(code) {
  return typeof code === 'string' && BUILDER_CODE_RE.test(code);
}

/**
 * The `extensions["builder-code"]` declaration for a 402 body, or null when no code is
 * configured (then the 402 is byte-identical to before this module existed).
 * Throws on a malformed code: the spec says invalid codes "must be rejected at declaration
 * time", and a misconfigured code that silently attributes nothing is the failure mode
 * this exists to prevent.
 */
function builderCodeExtension(appCode) {
  if (appCode === undefined || appCode === null || appCode === '') return null;
  if (!isBuilderCode(appCode)) {
    throw new Error(
      `Invalid x402 builder code "${appCode}": must match ^[a-z0-9_]{1,32}$ ` +
      '(check X402_BUILDER_CODE — Base Dashboard / api.base.dev issue codes like "bc_abcd1234")',
    );
  }
  return { info: { a: appCode }, schema: BUILDER_CODE_SCHEMA };
}

/** `{ "builder-code": … }` to spread into a 402 body's extensions, or `{}`. */
function builderCodeExtensions(appCode) {
  const ext = builderCodeExtension(appCode);
  return ext ? { [BUILDER_CODE_KEY]: ext } : {};
}

/* The client's builder-code object may arrive info-wrapped ({info:{a,s}}, what the core
 * merge produces) or bare ({a,s}, the spec's PaymentPayload example). Read both. */
function payloadBuilderCodeInfo(payload) {
  const raw = payload && payload.extensions && payload.extensions[BUILDER_CODE_KEY];
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const info = raw.info && typeof raw.info === 'object' && !Array.isArray(raw.info) ? raw.info : raw;
  return info;
}

/**
 * The resource server's checks before a payment reaches the facilitator. Returns null when
 * the payload is acceptable, else the spec's error code `extension_echo_mismatch`.
 *   - `a` present and not exactly our declared code (including when we declared none):
 *     the resource server is the authority for `a`.
 *   - `s` longer than the combined client+server budget: padding that could later crowd
 *     out a legitimately declared entry.
 */
function builderCodeEchoError(payload, declaredAppCode) {
  const info = payloadBuilderCodeInfo(payload);
  if (!info) return null;
  if (info.a !== undefined && info.a !== (declaredAppCode || undefined)) {
    return 'extension_echo_mismatch';
  }
  if (info.s !== undefined) {
    const s = typeof info.s === 'string' ? [info.s] : info.s;
    if (!Array.isArray(s) || s.length > MAX_CLIENT_SERVICE_CODES + MAX_SERVER_SERVICE_CODES) {
      return 'extension_echo_mismatch';
    }
  }
  return null;
}

// --- ERC-8021 Schema 2 (CBOR) ------------------------------------------------------------
// Only what attribution needs: maps with text keys, text strings, arrays, unsigned ints.
// Deterministic shortest-form heads; top-level key order a, w, s, m per the spec.

function cborHead(major, n) {
  if (!Number.isInteger(n) || n < 0) throw new RangeError('CBOR: unsigned integer required');
  if (n < 24) return Buffer.from([(major << 5) | n]);
  if (n < 0x100) return Buffer.from([(major << 5) | 24, n]);
  if (n < 0x10000) return Buffer.from([(major << 5) | 25, n >> 8, n & 0xff]);
  if (n < 0x100000000) {
    const b = Buffer.alloc(5); b[0] = (major << 5) | 26; b.writeUInt32BE(n, 1); return b;
  }
  throw new RangeError('CBOR: value too large');
}

function cborEncode(v) {
  if (typeof v === 'string') {
    const s = Buffer.from(v, 'utf8');
    return Buffer.concat([cborHead(3, s.length), s]);
  }
  if (Number.isInteger(v) && v >= 0) return cborHead(0, v);
  if (Array.isArray(v)) return Buffer.concat([cborHead(4, v.length), ...v.map(cborEncode)]);
  if (v && typeof v === 'object') {
    const keys = Object.keys(v);
    return Buffer.concat([cborHead(5, keys.length), ...keys.flatMap((k) => [cborEncode(k), cborEncode(v[k])])]);
  }
  throw new TypeError(`CBOR: unsupported value ${JSON.stringify(v)}`);
}

/**
 * Hex (no 0x) suffix to append to calldata: [cbor][len 2B BE][0x02][marker].
 * `s` is always encoded as an array, as the facilitator does.
 */
function encodeBuilderCodeSuffix({ a, w, s } = {}) {
  const map = {};
  for (const [k, v] of [['a', a], ['w', w]]) {
    if (v === undefined) continue;
    if (!isBuilderCode(v)) throw new Error(`Invalid builder code for "${k}": ${v}`);
    map[k] = v;
  }
  if (s !== undefined) {
    const list = typeof s === 'string' ? [s] : s;
    if (!Array.isArray(list) || list.length > MAX_SERVICE_CODES || !list.every(isBuilderCode)) {
      throw new Error('Invalid builder service codes');
    }
    if (list.length) map.s = list;
  }
  if (!Object.keys(map).length) throw new Error('builder-code suffix needs at least one field');
  const cbor = cborEncode(map);
  if (cbor.length > 0xffff) throw new RangeError('builder-code CBOR exceeds 65535 bytes');
  const len = Buffer.from([cbor.length >> 8, cbor.length & 0xff]);
  return Buffer.concat([cbor, len, Buffer.from([SCHEMA_2])]).toString('hex') + ERC8021_MARKER;
}

function cborDecode(buf, pos = 0) {
  const ib = buf[pos];
  if (ib === undefined) throw new Error('CBOR: truncated');
  const major = ib >> 5;
  const ai = ib & 0x1f;
  let n; let p = pos + 1;
  if (ai < 24) n = ai;
  else if (ai === 24) { n = buf[p]; p += 1; }
  else if (ai === 25) { n = buf.readUInt16BE(p); p += 2; }
  else if (ai === 26) { n = buf.readUInt32BE(p); p += 4; }
  else throw new Error('CBOR: unsupported length encoding');
  if (n === undefined || Number.isNaN(n)) throw new Error('CBOR: truncated');
  if (major === 0) return [n, p];
  if (major === 3) {
    if (p + n > buf.length) throw new Error('CBOR: truncated string');
    return [buf.slice(p, p + n).toString('utf8'), p + n];
  }
  if (major === 4) {
    const out = [];
    for (let i = 0; i < n; i += 1) { const [v, q] = cborDecode(buf, p); out.push(v); p = q; }
    return [out, p];
  }
  if (major === 5) {
    const out = {};
    for (let i = 0; i < n; i += 1) {
      const [k, q] = cborDecode(buf, p);
      if (typeof k !== 'string') throw new Error('CBOR: non-text map key');
      const [v, r] = cborDecode(buf, q);
      out[k] = v; p = r;
    }
    return [out, p];
  }
  throw new Error(`CBOR: unsupported major type ${major}`);
}

/**
 * Read ERC-8021 Schema 2 attribution from a transaction's calldata (hex, 0x optional).
 * Returns { a?, w?, s?, m? } or null when the calldata carries no Schema 2 suffix — the
 * check that turns "we declared a code" into "this settlement was attributed".
 */
function parseBuilderCodeSuffix(calldataHex) {
  if (typeof calldataHex !== 'string') return null;
  const hex = calldataHex.replace(/^0x/i, '').toLowerCase();
  if (hex.length < (16 + 1 + 2) * 2 || !hex.endsWith(ERC8021_MARKER)) return null;
  const buf = Buffer.from(hex, 'hex');
  const end = buf.length - 16;
  if (buf[end - 1] !== SCHEMA_2) return null;
  const len = buf.readUInt16BE(end - 3);
  const start = end - 3 - len;
  if (start < 0) return null;
  try {
    const [map, stop] = cborDecode(buf.slice(start, end - 3));
    if (stop !== len || !map || typeof map !== 'object' || Array.isArray(map)) return null;
    return map;
  } catch (_) {
    return null;
  }
}

module.exports = {
  BUILDER_CODE_KEY,
  BUILDER_CODE_RE,
  BUILDER_CODE_SCHEMA,
  ERC8021_MARKER,
  MAX_CLIENT_SERVICE_CODES,
  MAX_SERVER_SERVICE_CODES,
  isBuilderCode,
  builderCodeExtension,
  builderCodeExtensions,
  builderCodeEchoError,
  encodeBuilderCodeSuffix,
  parseBuilderCodeSuffix,
};
