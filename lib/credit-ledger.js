'use strict';

/**
 * @fileoverview AI Credit Ledger for PearlPool's compute-for-credits system.
 *
 * Completely separate from the PRL mining balance (sqlite-ledger.js). This ledger
 * tracks **AI inference credits** — integer token-units that miners earn by
 * contributing GPU compute, and spend by calling the inference API.
 *
 * Design properties (mirrors sqlite-ledger.js / rebate.js patterns):
 *   - SQLite in WAL mode: each committed transaction is durable on disk.
 *   - Every credit/debit is a single ATOMIC transaction (journal + balance).
 *   - Operations are idempotent on `ref` (allocation period / spend request id).
 *   - Credits are integers (1 credit = 1 token of inference). Never floats.
 *   - Debit fails if balance < amount (throws InsufficientCreditsError).
 *   - Conservation invariant: totalAllocated === sum(balances) + totalSpent.
 *
 * Zero npm dependencies — built-in `node:sqlite` (Node >= 22.5).
 *
 * @author PearlPool Contributors (Jules / Linkrra)
 * @license MIT
 */

const { DatabaseSync } = require('node:sqlite');
const fs = require('fs');
const path = require('path');
const { applyNocase } = require('./nocase-migration');

const SCHEMA_VERSION = 1;

/**
 * Thrown when a debit would bring the balance below zero.
 * The caller is expected to check balance BEFORE attempting a debit
 * (e.g. the inference gateway checks before routing), but the ledger
 * enforces the invariant as the last line of defense.
 */
class InsufficientCreditsError extends Error {
  constructor(address, requested, available) {
    super(
      `Insufficient credits for ${address}: requested ${requested}, available ${available}`
    );
    this.name = 'InsufficientCreditsError';
    this.address = address;
    this.requested = requested;
    this.available = available;
  }
}

/**
 * Clamp a caller-supplied row limit to a safe positive integer before it is
 * bound into a `LIMIT ?` clause. Same doctrine as sqlite-ledger.js clampLimit.
 * @param {*} limit
 * @param {number} def
 * @param {number} [max=1000]
 * @returns {number} integer in [1, max]
 * @private
 */
function clampLimit(limit, def, max = 1000) {
  const n = Number.isFinite(limit) && limit >= 1 ? Math.floor(limit) : def;
  return Math.min(n, max);
}

/**
 * True when an error is the UNIQUE-constraint violation on credit_journal.ref.
 *
 * The pre-transaction hasRef() check can lose a race; the unique index then
 * rejects the second writer. That is a duplicate, not a failure, so callers
 * report it the same way as the fast-path check: "already applied".
 */
function isDuplicateRefError(err) {
  return /UNIQUE constraint failed: credit_journal\.ref/i.test(err && err.message || '');
}

class CreditLedger {
  /**
   * @param {string} filepath - Path to the SQLite database file.
   *   Use `:memory:` for tests.
   */
  constructor(filepath) {
    if (typeof filepath !== 'string' || filepath.length === 0) {
      throw new TypeError('CreditLedger(filepath): filepath must be a non-empty string');
    }

    if (filepath !== ':memory:') {
      fs.mkdirSync(path.dirname(path.resolve(filepath)), { recursive: true });
    }

    this.filepath = filepath;
    this.db = new DatabaseSync(filepath);

    // WAL = durable, concurrent-reader-friendly; NORMAL sync is the standard
    // safe-with-WAL setting.
    this.db.exec('PRAGMA journal_mode = WAL;');
    // WAL lets readers and writers coexist, but a second WRITER still gets
    // SQLITE_BUSY immediately unless told to wait. Under concurrent load that
    // surfaced as real "database is locked" failures on the debit path — and a
    // failed debit is indistinguishable from an overdraw to the caller, so the
    // request kept its compute and paid nothing. Free inference, triggered by
    // traffic. Waiting is the correct behaviour: the lock is held for
    // microseconds, so 5s is effectively "never give up spuriously".
    this.db.exec('PRAGMA busy_timeout = 5000;');
    this.db.exec('PRAGMA synchronous = NORMAL;');
    this.db.exec('PRAGMA foreign_keys = ON;');

    /** Lot rows fetched so far — lets a test prove a debit's cost is flat. */
    this.lotRowsRead = 0;

    this._migrate();
    this._prepare();
    /** What the start-up lot check had to clamp (see _reconcileLots). */
    this.lotReconciliation = this._reconcileLots();
  }

  /** Create tables on first run; record schema version. @private */
  _migrate() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS meta (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );

      -- Per-miner credit balance. SEPARATE from PRL mining balance.
      CREATE TABLE IF NOT EXISTS credit_balances (
        address      TEXT PRIMARY KEY,
        balance      INTEGER NOT NULL DEFAULT 0 CHECK (balance >= 0),
        total_earned INTEGER NOT NULL DEFAULT 0,
        total_spent  INTEGER NOT NULL DEFAULT 0,
        updated_at   INTEGER NOT NULL DEFAULT 0
      );

      -- Immutable append-only journal of every credit/spend/adjustment.
      CREATE TABLE IF NOT EXISTS credit_journal (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        ts          INTEGER NOT NULL,
        address     TEXT NOT NULL,
        kind        TEXT NOT NULL CHECK (kind IN ('allocation','spend','adjustment')),
        amount      INTEGER NOT NULL,  -- positive=credit, negative=debit
        ref         TEXT,              -- idempotency key (allocation period / spend request id)
        note        TEXT,
        api_key     TEXT,              -- for spend events only
        tokens_used INTEGER,            -- for spend events: actual tokens consumed
        team_id     TEXT,              -- Team Agent cost attribution (T-383 L1): which team, if any
        role        TEXT               -- Team Agent cost attribution: which role within it (e.g. "team-planner")
      );
      CREATE INDEX IF NOT EXISTS idx_cjournal_addr ON credit_journal(address);
      -- UNIQUE, not a plain index: the hasRef() pre-check happens before the
      -- write transaction, so two processes can both decide a ref is new. This
      -- constraint is the last line of defence against a double credit/debit.
      CREATE UNIQUE INDEX IF NOT EXISTS idx_cjournal_ref ON credit_journal(ref) WHERE ref IS NOT NULL;
      CREATE INDEX IF NOT EXISTS idx_cjournal_ts ON credit_journal(ts);

      -- Credits taken back because the payment that bought them was reversed
      -- (refund, chargeback). One row per provider event; the journal carries
      -- the balance change, this carries the arithmetic the journal cannot:
      -- how much of one GRANT has been reversed so far across several events,
      -- and how much could not be collected because it was already spent.
      CREATE TABLE IF NOT EXISTS credit_clawbacks (
        ref        TEXT PRIMARY KEY,   -- idempotency key (the provider event)
        grant_ref  TEXT NOT NULL,      -- which grant this reverses
        address    TEXT NOT NULL,
        due        INTEGER NOT NULL,   -- credits this event should take back
        debited    INTEGER NOT NULL,   -- credits it actually took
        shortfall  INTEGER NOT NULL,   -- due - debited: already spent
        ts         INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_clawback_grant ON credit_clawbacks(grant_ref);
    `);

    /* Funding lots (T-675, 2026-10-03): what real money stands behind which
     * credits.
     *
     * A balance is one fungible number, but it is filled from sources that are
     * not alike: a card top-up at the pay-as-you-go rate, a subscription grant
     * at a discount, an hourly allocation nobody paid for. Node operators are
     * now paid a share of the DOLLARS a served request brought in, so "how many
     * dollars did these credits cost the customer" has to have an exact answer
     * — zero for credits nobody bought.
     *
     * One lot per grant, consumed first-in-first-out by every balance decrease
     * (spend, negative adjustment, clawback), inside the same transaction as
     * the balance change. A lot's dollars can therefore be attributed at most
     * once, so the total ever attributed can never exceed the total collected.
     * Kept in their own tables rather than as journal columns: the journal is
     * rebuilt by the NOCASE migration and must not grow a column it does not
     * know how to copy.
     *
     * Balances that predate this table have no lot. They are the oldest
     * credits an address holds, so they are spent first and carry $0 — we do
     * not know what was paid for them, and an unknown is not revenue. */
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS credit_funding_lots (
        id                  INTEGER PRIMARY KEY AUTOINCREMENT,
        address             TEXT COLLATE NOCASE NOT NULL,
        grant_ref           TEXT NOT NULL UNIQUE,
        ts                  INTEGER NOT NULL,
        credits_total       INTEGER NOT NULL CHECK (credits_total > 0),
        credits_remaining   INTEGER NOT NULL CHECK (credits_remaining >= 0),
        usd_micro_total     INTEGER NOT NULL CHECK (usd_micro_total >= 0),
        usd_micro_remaining INTEGER NOT NULL CHECK (usd_micro_remaining >= 0),
        -- 1 = later grants of the same kind may be folded into this row (see
        -- _openLot). Only ever set for payments that cannot be refunded.
        coalesce            INTEGER NOT NULL DEFAULT 0,
        -- 1 = these credits are valid only for one billing period (a
        -- subscription grant, T-970). Never folded with any other grant, spent
        -- before every non-expiring credit, and expired by expireGrant().
        expiring            INTEGER NOT NULL DEFAULT 0
      );
      -- "The oldest open lot of this address" is the hot-path query: one index
      -- seek, however many lots there are.
      CREATE INDEX IF NOT EXISTS idx_lots_open ON credit_funding_lots(address, id) WHERE credits_remaining > 0;
      CREATE INDEX IF NOT EXISTS idx_lots_addr ON credit_funding_lots(address, id);

      -- Credits currently sitting in open lots, per address. Kept in step with
      -- the lots inside the same transactions, so a debit reads ONE row to
      -- learn it instead of summing every lot the address has.
      CREATE TABLE IF NOT EXISTS credit_lot_totals (
        address      TEXT COLLATE NOCASE PRIMARY KEY,
        open_credits INTEGER NOT NULL DEFAULT 0 CHECK (open_credits >= 0),
        -- of which in EXPIRING lots (plan credits, T-970). The flag a debit
        -- reads to know whether there is a plan lot to take first — without
        -- it every debit would pay an extra index seek to find out "none".
        expiring_credits INTEGER NOT NULL DEFAULT 0
      );

      -- What one spend took from one PAID lot. A spend that crosses lots has a
      -- row per lot; a spend of credits nobody bought has none.
      CREATE TABLE IF NOT EXISTS credit_spend_funding (
        ref                TEXT NOT NULL,      -- the spend's journal ref
        lot_id             INTEGER NOT NULL,
        address            TEXT COLLATE NOCASE NOT NULL,
        ts                 INTEGER NOT NULL,
        credits            INTEGER NOT NULL,   -- credits this spend took from this lot
        usd_micro          INTEGER NOT NULL,   -- dollars (x 1e6) those credits cost the customer
        reversed_credits   INTEGER NOT NULL DEFAULT 0,  -- of which later refunded…
        reversed_usd_micro INTEGER NOT NULL DEFAULT 0,  -- …and their dollars
        PRIMARY KEY (ref, lot_id)
      );
      CREATE INDEX IF NOT EXISTS idx_spend_lot ON credit_spend_funding(lot_id);

      -- Spends whose money went back to the customer AFTER the credits were
      -- used (a refund or chargeback with a shortfall). Written in the
      -- clawback's own transaction; whoever paid a share of those dollars out
      -- (lib/inference-earnings.js) reverses it from this record.
      CREATE TABLE IF NOT EXISTS credit_spend_reversals (
        clawback_ref TEXT NOT NULL,
        spend_ref    TEXT NOT NULL,
        lot_id       INTEGER NOT NULL,
        credits      INTEGER NOT NULL,
        usd_micro    INTEGER NOT NULL,
        ts           INTEGER NOT NULL,
        PRIMARY KEY (clawback_ref, spend_ref, lot_id)
      );
    `);

    /* T-970 (2026-10-17): `expiring` arrived after the lots table shipped, so
     * an existing database gets it as an ALTER. Every lot written before it is
     * 0 — non-expiring — which is what it was sold as. */
    const lotCols = new Set(
      this.db.prepare('PRAGMA table_info(credit_funding_lots)').all().map((c) => c.name),
    );
    if (!lotCols.has('expiring')) {
      this.db.exec('ALTER TABLE credit_funding_lots ADD COLUMN expiring INTEGER NOT NULL DEFAULT 0');
    }
    const totalCols = new Set(
      this.db.prepare('PRAGMA table_info(credit_lot_totals)').all().map((c) => c.name),
    );
    if (!totalCols.has('expiring_credits')) {
      this.db.exec('ALTER TABLE credit_lot_totals ADD COLUMN expiring_credits INTEGER NOT NULL DEFAULT 0');
    }
    // "This address's oldest open expiring lot" — the first take of every
    // debit. One index seek, and an address with no plan credits finds nothing.
    this.db.exec('CREATE INDEX IF NOT EXISTS idx_lots_expiring ON credit_funding_lots(address, id) WHERE expiring = 1 AND credits_remaining > 0');

    // team_id/role are new (2026-09-15, T-383 L1 gap #2). A DB from before this
    // shipped has credit_journal without them, and CREATE TABLE IF NOT EXISTS
    // above does not retrofit columns onto an existing table — so add them
    // here if missing. Nullable, no default needed: every existing row simply
    // has no team/role, which is the honest fact (it predates the concept).
    const journalCols = new Set(
      this.db.prepare('PRAGMA table_info(credit_journal)').all().map((c) => c.name),
    );
    if (!journalCols.has('team_id')) {
      this.db.exec('ALTER TABLE credit_journal ADD COLUMN team_id TEXT');
    }
    if (!journalCols.has('role')) {
      this.db.exec('ALTER TABLE credit_journal ADD COLUMN role TEXT');
    }

    // v1 shipped idx_cjournal_ref as a plain index. CREATE ... IF NOT EXISTS
    // won't upgrade it in place, so drop and rebuild on existing databases.
    const refIdx = this.db
      .prepare("SELECT sql FROM sqlite_master WHERE type='index' AND name='idx_cjournal_ref'")
      .get();
    if (refIdx && !/UNIQUE/i.test(refIdx.sql || '')) {
      const dupes = this.db
        .prepare('SELECT COUNT(*) AS n FROM (SELECT ref FROM credit_journal WHERE ref IS NOT NULL GROUP BY ref HAVING COUNT(*) > 1)')
        .get().n;
      if (dupes > 0) {
        throw new Error(
          `CreditLedger cannot enforce ref uniqueness: ${dupes} duplicate ref(s) already exist in credit_journal. ` +
          'These are double-applied credits/debits and must be reconciled manually before upgrading.'
        );
      }
      this.db.exec(`
        DROP INDEX idx_cjournal_ref;
        CREATE UNIQUE INDEX idx_cjournal_ref ON credit_journal(ref) WHERE ref IS NOT NULL;
      `);
    }

    // Storage-level backstop for the address case-folding bug (AUTH-REVIEW F-1).
    // The application layer lowercases at every entry point, but that is a
    // convention a future route can forget; COLLATE NOCASE makes it a guarantee.
    // Idempotent, and refuses to run rather than silently merging balances if
    // case-variant rows already exist.
    applyNocase(this.db, ['credit_balances', 'credit_journal']);

    const row = this.db.prepare('SELECT value FROM meta WHERE key = ?').get('schema_version');
    if (!row) {
      this.db
        .prepare('INSERT INTO meta (key, value) VALUES (?, ?)')
        .run('schema_version', String(SCHEMA_VERSION));
    } else if (Number(row.value) > SCHEMA_VERSION) {
      throw new Error(
        `CreditLedger schema version ${row.value} is newer than this code (${SCHEMA_VERSION}); upgrade the binary.`
      );
    }
  }

  /** Prepare hot-path statements once. @private */
  _prepare() {
    this._st = {
      getBalance: this.db.prepare(
        'SELECT balance, total_earned, total_spent, updated_at FROM credit_balances WHERE address = ?'
      ),
      upsertCredit: this.db.prepare(`
        INSERT INTO credit_balances (address, balance, total_earned, total_spent, updated_at)
        VALUES (?, ?, ?, 0, ?)
        ON CONFLICT(address) DO UPDATE SET
          balance = balance + excluded.balance,
          total_earned = total_earned + excluded.total_earned,
          updated_at = excluded.updated_at
      `),
      applyDebit: this.db.prepare(`
        UPDATE credit_balances
        SET balance = balance - ?,
            total_spent = total_spent + ?,
            updated_at = ?
        WHERE address = ?
      `),
      insJournal: this.db.prepare(`
        INSERT INTO credit_journal (ts, address, kind, amount, ref, note, api_key, tokens_used, team_id, role)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `),
      hasRef: this.db.prepare(
        'SELECT 1 FROM credit_journal WHERE ref = ? LIMIT 1'
      ),
      journalByAddr: this.db.prepare(
        'SELECT * FROM credit_journal WHERE address = ? ORDER BY ts DESC LIMIT ?'
      ),
      allBalances: this.db.prepare(
        'SELECT address, balance, total_earned, total_spent, updated_at FROM credit_balances'
      ),
      countMiners: this.db.prepare(
        'SELECT COUNT(*) AS n FROM credit_balances WHERE balance > 0'
      ),
      sumBalances: this.db.prepare(
        'SELECT COALESCE(SUM(balance), 0) AS s FROM credit_balances'
      ),
      sumEarned: this.db.prepare(
        'SELECT COALESCE(SUM(total_earned), 0) AS s FROM credit_balances'
      ),
      sumSpent: this.db.prepare(
        'SELECT COALESCE(SUM(total_spent), 0) AS s FROM credit_balances'
      ),
      insLot: this.db.prepare(`
        INSERT INTO credit_funding_lots
          (address, grant_ref, ts, credits_total, credits_remaining, usd_micro_total, usd_micro_remaining, coalesce, expiring)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `),
      newestLot: this.db.prepare(
        'SELECT id, usd_micro_total, coalesce, expiring FROM credit_funding_lots WHERE address = ? ORDER BY id DESC LIMIT 1'
      ),
      growLot: this.db.prepare(`
        UPDATE credit_funding_lots
        SET credits_total = credits_total + ?, credits_remaining = credits_remaining + ?,
            usd_micro_total = usd_micro_total + ?, usd_micro_remaining = usd_micro_remaining + ?
        WHERE id = ?
      `),
      oldestOpenLot: this.db.prepare(
        'SELECT id, credits_remaining, usd_micro_total, usd_micro_remaining, expiring FROM credit_funding_lots WHERE address = ? AND credits_remaining > 0 ORDER BY id LIMIT 1'
      ),
      oldestOpenExpiringLot: this.db.prepare(
        'SELECT id, credits_remaining, usd_micro_total, usd_micro_remaining, expiring FROM credit_funding_lots WHERE address = ? AND expiring = 1 AND credits_remaining > 0 ORDER BY id LIMIT 1'
      ),
      lotByRef: this.db.prepare(
        'SELECT id, address, credits_remaining, usd_micro_total, usd_micro_remaining, expiring FROM credit_funding_lots WHERE grant_ref = ?'
      ),
      takeFromLot: this.db.prepare(
        'UPDATE credit_funding_lots SET credits_remaining = credits_remaining - ?, usd_micro_remaining = usd_micro_remaining - ? WHERE id = ?'
      ),
      getOpenCredits: this.db.prepare('SELECT open_credits, expiring_credits FROM credit_lot_totals WHERE address = ?'),
      addExpiringCredits: this.db.prepare('UPDATE credit_lot_totals SET expiring_credits = expiring_credits + ? WHERE address = ?'),
      subExpiringCredits: this.db.prepare('UPDATE credit_lot_totals SET expiring_credits = MAX(0, expiring_credits - ?) WHERE address = ?'),
      addOpenCredits: this.db.prepare(`
        INSERT INTO credit_lot_totals (address, open_credits) VALUES (?, ?)
        ON CONFLICT(address) DO UPDATE SET open_credits = open_credits + excluded.open_credits
      `),
      subOpenCredits: this.db.prepare(
        'UPDATE credit_lot_totals SET open_credits = open_credits - ? WHERE address = ?'
      ),
      insSpendFunding: this.db.prepare(
        'INSERT INTO credit_spend_funding (ref, lot_id, address, ts, credits, usd_micro) VALUES (?, ?, ?, ?, ?, ?)'
      ),
      getSpendFunding: this.db.prepare(
        'SELECT COALESCE(SUM(credits), 0) AS credits, COALESCE(SUM(usd_micro), 0) AS usd FROM credit_spend_funding WHERE ref = ?'
      ),
      newestUnreversedSpend: this.db.prepare(`
        SELECT rowid AS rid, ref, credits, usd_micro, reversed_credits, reversed_usd_micro
        FROM credit_spend_funding WHERE lot_id = ? AND reversed_credits < credits
        ORDER BY rowid DESC LIMIT 1
      `),
      markSpendReversed: this.db.prepare(
        'UPDATE credit_spend_funding SET reversed_credits = reversed_credits + ?, reversed_usd_micro = reversed_usd_micro + ? WHERE rowid = ?'
      ),
      insReversal: this.db.prepare(
        'INSERT INTO credit_spend_reversals (clawback_ref, spend_ref, lot_id, credits, usd_micro, ts) VALUES (?, ?, ?, ?, ?, ?)'
      ),
      reversalsByClawback: this.db.prepare(
        'SELECT spend_ref, lot_id, credits, usd_micro FROM credit_spend_reversals WHERE clawback_ref = ? ORDER BY rowid'
      ),
      fundingByAddr: this.db.prepare(
        'SELECT COALESCE(SUM(credits_remaining), 0) AS credits, COALESCE(SUM(usd_micro_remaining), 0) AS usd FROM credit_funding_lots WHERE address = ? AND credits_remaining > 0 AND usd_micro_total > 0'
      ),
    };
  }

  /**
   * Run a piece of lot bookkeeping; if it fails, say so loudly and carry on.
   *
   * Lots answer "what did these credits cost" for the benefit of node payouts.
   * They are not the balance. A fault in them must never fail the credit or
   * the debit they ride along with — a customer who paid gets their credits, a
   * request that ran gets billed — so the error is logged and the money
   * operation completes. Whatever the fault left behind is put right by
   * _reconcileLots() on the next start.
   * @private
   */
  _lots(what, fn, fallback) {
    try {
      return fn();
    } catch (err) {
      console.error(`[credits] FUNDING-LOT BOOKKEEPING FAILED (${what}): ${err.message} — the balance change itself is unaffected`);
      return fallback;
    }
  }

  /**
   * Record what a grant's credits cost. MUST be called inside the grant's own
   * transaction, so a credit and its lot land together or not at all.
   *
   * `funding.usdMicro` is what the customer actually paid for these credits,
   * in integer millionths of a dollar; absent or zero means nobody bought them
   * (allocation, manual grant).
   *
   * The number of rows this creates is kept from growing with traffic, because
   * every debit has to find the oldest open lot:
   *
   *   - Credits nobody paid for need a row only to hold their PLACE in the
   *     first-in-first-out order. When the address has no open lot there is
   *     no order to keep — they simply join the unlotted balance, which is
   *     spent first and is worth $0, exactly as they would have been. When the
   *     newest lot is itself worth $0 they are added to it. So an address that
   *     only ever earns hourly allocations has no lot at all, and one that
   *     also buys has at most one $0 row between purchases.
   *   - `funding.coalesce` marks a payment that can never be refunded (an
   *     on-chain x402 settlement). Consecutive such grants fold into one row:
   *     a wallet paying per call leaves one lot, not one per call. The fold
   *     blends the price of adjacent grants — the dollars are conserved to the
   *     micro, only which request carries which cent shifts. Refundable
   *     payments are never folded: a refund must be able to find its own lot.
   *
   * A malformed figure becomes $0 and a warning rather than an exception.
   * @private
   */
  _openLot(address, credits, ref, ts, funding) {
    let usdMicro = 0;
    if (funding && funding.usdMicro !== undefined && funding.usdMicro !== null) {
      if (Number.isSafeInteger(funding.usdMicro) && funding.usdMicro >= 0) {
        usdMicro = funding.usdMicro;
      } else {
        console.warn(`[credits] funding for ${ref} ignored: usdMicro must be a non-negative integer, got ${funding.usdMicro}`);
      }
    }
    /* An expiring grant always gets a row of its own, whatever it cost and
     * whatever else the address holds: expireGrant() has to find exactly
     * these credits later, and they must never be blended with credits that
     * do not expire. */
    if (funding && funding.expiring === true) {
      this._st.insLot.run(address, ref, ts, credits, credits, usdMicro, usdMicro, 0, 1);
      this._st.addOpenCredits.run(address, credits);
      this._st.addExpiringCredits.run(credits, address);
      return;
    }
    const coalesce = usdMicro > 0 && funding && funding.coalesce === true ? 1 : 0;

    if (usdMicro === 0) {
      const open = this._st.getOpenCredits.get(address);
      if (!open || open.open_credits === 0) return; // joins the unlotted, $0 balance
    }
    if (usdMicro === 0 || coalesce) {
      const newest = this._st.newestLot.get(address);
      this.lotRowsRead++;
      const sameKind = newest && newest.expiring !== 1 && (usdMicro === 0
        ? newest.usd_micro_total === 0
        : newest.coalesce === 1 && newest.usd_micro_total > 0);
      if (sameKind) {
        this._st.growLot.run(credits, credits, usdMicro, usdMicro, newest.id);
        this._st.addOpenCredits.run(address, credits);
        return;
      }
    }
    this._st.insLot.run(address, ref, ts, credits, credits, usdMicro, usdMicro, coalesce, 0);
    this._st.addOpenCredits.run(address, credits);
  }

  /**
   * Take `amount` credits out of an address's funding, oldest first. MUST be
   * called inside the transaction that lowers the balance.
   *
   * Order: credits with no lot (they predate lots, or were never paid for and
   * had nothing to queue behind — the oldest, worth $0), then lots in the
   * order they were granted. `preferGrantRef` puts one lot at the front — a
   * refund reverses the purchase it refunds, not whichever is oldest.
   *
   * Cost is independent of how many lots the address has: the open total is
   * one row, and lots are fetched one at a time by index, only as many as the
   * amount actually reaches into.
   *
   * Dollars leave a lot in proportion to the credits taken, rounded DOWN, and
   * the last credits out take whatever is left — so a lot's dollars are handed
   * out exactly once, to the micro-dollar, however it is sliced.
   *
   * @param {string} address
   * @param {number} amount - credits being removed
   * @param {number} available - balance before the removal
   * @param {Object} [o]
   * @param {string} [o.preferGrantRef]
   * @param {string} [o.spendRef] - record what each paid lot gave to this spend
   * @param {number} [o.ts]
   * @param {boolean} [o.lotsOnly] - skip the unlotted balance (reconciliation)
   * @param {boolean} [o.expiringFirst] - take open EXPIRING lots (plan credits,
   *   T-970) before anything else, oldest first. Spends use it: credits that
   *   are about to expire must go before credits the customer bought outright,
   *   or a top-up burns while the plan's month quietly lapses. Gated on the
   *   per-address expiring total (the row this already reads), so an address
   *   with no plan credits pays nothing extra, and one with them pays one
   *   index seek per expiring lot the amount actually reaches into.
   * @returns {{usdMicro:number, fundedCredits:number, lotCredits:number}}
   * @private
   */
  _consumeFunding(address, amount, available, o = {}) {
    const none = { usdMicro: 0, fundedCredits: 0, lotCredits: 0 };
    if (!(amount > 0)) return none;
    const totals = this._st.getOpenCredits.get(address);
    const inLots = totals ? totals.open_credits : 0;
    if (inLots <= 0) return none;

    let remaining = amount;
    let usdMicro = 0;
    let fundedCredits = 0;
    let lotCredits = 0;
    let expiringCredits = 0;

    const takeFrom = (lot) => {
      const take = Math.min(lot.credits_remaining, remaining);
      if (take <= 0) return;
      if (lot.expiring === 1) expiringCredits += take;
      const usd = take === lot.credits_remaining
        ? lot.usd_micro_remaining
        : Number((BigInt(lot.usd_micro_remaining) * BigInt(take)) / BigInt(lot.credits_remaining));
      this._st.takeFromLot.run(take, usd, lot.id);
      remaining -= take;
      lotCredits += take;
      usdMicro += usd;
      if (lot.usd_micro_total > 0) {
        fundedCredits += take;
        if (o.spendRef) this._st.insSpendFunding.run(o.spendRef, lot.id, address, o.ts || Date.now(), take, usd);
      }
    };

    if (o.expiringFirst && totals && totals.expiring_credits > 0) {
      while (remaining > 0) {
        const lot = this._st.oldestOpenExpiringLot.get(address);
        this.lotRowsRead++;
        if (!lot) break;
        takeFrom(lot);
      }
    }
    if (o.preferGrantRef) {
      const target = this._st.lotByRef.get(o.preferGrantRef);
      this.lotRowsRead++;
      if (target && target.credits_remaining > 0 && String(target.address).toLowerCase() === String(address).toLowerCase()) {
        takeFrom(target);
      }
    }
    if (!o.lotsOnly) {
      // Unlotted credits: oldest of all, worth nothing we can prove.
      remaining -= Math.min(Math.max(0, available - inLots), remaining);
    }
    while (remaining > 0) {
      const lot = this._st.oldestOpenLot.get(address);
      this.lotRowsRead++;
      if (!lot) break;
      takeFrom(lot);
    }
    if (lotCredits > 0) this._st.subOpenCredits.run(lotCredits, address);
    if (expiringCredits > 0) this._st.subExpiringCredits.run(expiringCredits, address);
    return { usdMicro, fundedCredits, lotCredits };
  }

  /**
   * A refund could not take back `credits` of a purchase because they were
   * already spent. Find the spends that used them — most recent first — and
   * record that their dollars went back to the customer. MUST run inside the
   * clawback's transaction.
   *
   * Each spend row is reversed at most once in total, across any number of
   * partial refunds of the same purchase.
   * @private
   */
  _reverseSpends(lotId, credits, clawbackRef, ts) {
    let remaining = credits;
    while (remaining > 0) {
      const row = this._st.newestUnreversedSpend.get(lotId);
      if (!row) break;
      const left = row.credits - row.reversed_credits;
      const take = Math.min(left, remaining);
      const usdLeft = row.usd_micro - row.reversed_usd_micro;
      const usd = take === left ? usdLeft : Number((BigInt(usdLeft) * BigInt(take)) / BigInt(left));
      this._st.markSpendReversed.run(take, usd, row.rid);
      this._st.insReversal.run(clawbackRef, row.ref, lotId, take, usd, ts);
      remaining -= take;
    }
  }

  /**
   * The spends a clawback reversed (refunded after the credits were used).
   * Stored, so a replayed clawback event returns the same list and whoever
   * acts on it can finish a job a crash interrupted.
   *
   * @param {string} clawbackRef
   * @returns {Array<{spendRef:string, credits:number, usdMicro:number}>}
   */
  getReversals(clawbackRef) {
    return this._st.reversalsByClawback.all(clawbackRef)
      .map((r) => ({ spendRef: r.spend_ref, credits: r.credits, usdMicro: r.usd_micro }));
  }

  /**
   * Make the lots agree with the balances. Runs once at start-up.
   *
   * Lots can only hold credits an address actually has. That stops being true
   * if this code is rolled back and redeployed: the older ledger debits
   * balances without touching lots, so on return the lots still "hold"
   * credits that were spent — and the next debits would attribute their
   * dollars to credits bought with nothing. So: recompute the per-address
   * totals from the lots themselves, and where an address's open lots exceed
   * its balance, take the excess out of the OLDEST lots (the ones those
   * untracked debits would have consumed), dollars and all, and say so.
   *
   * Never throws: start-up of the billing service does not depend on it.
   *
   * @returns {{addresses:number, credits:number, usdMicro:number}|null} what
   *   was clamped, or null if the check itself failed.
   * @private
   */
  _reconcileLots() {
    try {
      this.db.exec('BEGIN IMMEDIATE');
      try {
        this.db.exec(`
          DELETE FROM credit_lot_totals;
          INSERT INTO credit_lot_totals (address, open_credits, expiring_credits)
            SELECT address, SUM(credits_remaining), SUM(CASE WHEN expiring = 1 THEN credits_remaining ELSE 0 END)
            FROM credit_funding_lots
            WHERE credits_remaining > 0 GROUP BY address;
        `);
        const over = this.db.prepare(`
          SELECT t.address AS address, t.open_credits AS open_credits, COALESCE(b.balance, 0) AS balance
          FROM credit_lot_totals t LEFT JOIN credit_balances b ON b.address = t.address
          WHERE t.open_credits > COALESCE(b.balance, 0)
        `).all();
        const out = { addresses: 0, credits: 0, usdMicro: 0 };
        for (const row of over) {
          const excess = row.open_credits - row.balance;
          const taken = this._consumeFunding(row.address, excess, row.open_credits, { lotsOnly: true });
          out.addresses++;
          out.credits += taken.lotCredits;
          out.usdMicro += taken.usdMicro;
          console.error(
            `[credits] FUNDING LOTS CLAMPED for ${row.address}: lots held ${row.open_credits} credits but the balance is ` +
            `${row.balance}; removed ${taken.lotCredits} credits / ${taken.usdMicro} µUSD from the oldest lots ` +
            '(balance changed while lots were not being tracked — a rollback?). Those dollars will not be attributed to any node.'
          );
        }
        this.db.exec('COMMIT');
        return out;
      } catch (err) {
        try { this.db.exec('ROLLBACK'); } catch (_) { /* already rolled back */ }
        throw err;
      }
    } catch (err) {
      console.error(`[credits] funding-lot consistency check FAILED: ${err.message} — continuing; lots may be inaccurate`);
      return null;
    }
  }

  /**
   * What real money was behind one spend.
   *
   * @param {string} ref - the spend's journal ref
   * @returns {{fundedCredits:number, usdMicro:number}} zeros when the spend
   *   was covered entirely by credits nobody paid for (or is unknown) — there
   *   is no revenue to share in either case.
   */
  getSpendFunding(ref) {
    const r = ref ? this._st.getSpendFunding.get(ref) : null;
    if (!r) return { fundedCredits: 0, usdMicro: 0 };
    return { fundedCredits: r.credits, usdMicro: r.usd };
  }

  /**
   * Paid-for credits an address still holds, and what was paid for them.
   * (A full scan of the address's lots — for reads and audits, not the hot path.)
   * @param {string} address
   * @returns {{credits:number, usdMicro:number}}
   */
  getFunding(address) {
    const r = this._st.fundingByAddr.get(address);
    return { credits: r.credits, usdMicro: r.usd };
  }

  /**
   * Current balance for an address (0 if no row yet).
   * @param {string} address
   * @returns {{ balance:number, totalEarned:number, totalSpent:number }}
   */
  getBalance(address) {
    const r = this._st.getBalance.get(address);
    if (!r) return { balance: 0, totalEarned: 0, totalSpent: 0 };
    return { balance: r.balance, totalEarned: r.total_earned, totalSpent: r.total_spent };
  }

  /**
   * Add credits to a miner's balance. Idempotent on `ref`.
   *
   * Used by the Allocation Engine to credit hourly allocations.
   *
   * @param {string} address  - Miner address
   * @param {number} amount   - Credits to add (positive integer)
   * @param {string} ref      - Idempotency key (e.g. `allocation:2026-08-01T10:00`)
   * @param {string} [note]   - Optional description
   * @param {number} [ts]     - Timestamp (default: now)
   * @param {{usdMicro:number}} [funding] - what the customer paid for these
   *   credits, in integer millionths of a dollar. Omit for credits nobody
   *   bought (allocations, grants): they are recorded as worth $0, and a
   *   request paid with them earns the node that served it nothing.
   * @returns {boolean} true if newly applied, false if `ref` was already seen
   */
  credit(address, amount, ref, note = null, ts = Date.now(), funding = null) {
    if (typeof address !== 'string' || address.length === 0) {
      throw new TypeError('credit requires a non-empty address');
    }
    if (!Number.isInteger(amount) || amount <= 0) {
      throw new RangeError(`credit amount must be a positive integer, got ${amount}`);
    }
    if (!ref || typeof ref !== 'string') {
      throw new TypeError('credit requires a non-empty ref (idempotency key)');
    }

    // Idempotency: if this ref was already processed, no-op.
    if (this._st.hasRef.get(ref)) return false;

    this.db.exec('BEGIN IMMEDIATE');
    try {
      this._st.insJournal.run(ts, address, 'allocation', amount, ref, note, null, null, null, null);
      this._st.upsertCredit.run(address, amount, amount, ts);
      this._lots(`open lot for ${ref}`, () => this._openLot(address, amount, ref, ts, funding));
      this.db.exec('COMMIT');
      return true;
    } catch (err) {
      try { this.db.exec('ROLLBACK'); } catch (_) { /* already rolled back */ }
      if (isDuplicateRefError(err)) return false;
      throw err;
    }
  }

  /**
   * Subtract credits from a miner's balance. Idempotent on `ref`.
   *
   * Used by the Inference Gateway to deduct tokens after an API call.
   * MUST fail if balance < amount.
   *
   * @param {string} address  - Miner address
   * @param {number} amount   - Credits to subtract (positive integer)
   * @param {string} ref      - Idempotency key (e.g. `spend:<requestId>`)
   * @param {string} [note]   - Optional description
   * @param {string} [apiKey] - API key used for this spend
   * @param {number} [tokensUsed] - Actual tokens consumed
   * @param {number} [ts]     - Timestamp (default: now)
   * @param {{teamId?: string|null, role?: string|null}} [meta] - Team Agent
   *   cost attribution (T-383 L1 gap #2): which team/role this spend belongs
   *   to, if the caller named one. Omitted or null leaves both columns NULL,
   *   identical to every debit recorded before this existed.
   * @returns {boolean} true if newly applied, false if `ref` was already seen
   * @throws {InsufficientCreditsError} if balance < amount
   */
  debit(address, amount, ref, note = null, apiKey = null, tokensUsed = null, ts = Date.now(), meta = null) {
    if (typeof address !== 'string' || address.length === 0) {
      throw new TypeError('debit requires a non-empty address');
    }
    if (!Number.isInteger(amount) || amount <= 0) {
      throw new RangeError(`debit amount must be a positive integer, got ${amount}`);
    }
    if (!ref || typeof ref !== 'string') {
      throw new TypeError('debit requires a non-empty ref (idempotency key)');
    }

    // Idempotency: if this ref was already processed, no-op.
    if (this._st.hasRef.get(ref)) return false;

    this.db.exec('BEGIN IMMEDIATE');
    try {
      // Check balance inside the transaction snapshot.
      const balRow = this._st.getBalance.get(address);
      const available = balRow ? balRow.balance : 0;
      if (amount > available) {
        throw new InsufficientCreditsError(address, amount, available);
      }

      // Record journal entry with negative amount for debits.
      this._st.insJournal.run(
        ts, address, 'spend', -amount, ref, note, apiKey, tokensUsed,
        (meta && meta.teamId) || null, (meta && meta.role) || null,
      );

      // Apply debit. The CHECK(balance >= 0) constraint is a secondary guard.
      const result = this._st.applyDebit.run(amount, amount, ts, address);
      if (result.changes === 0) {
        // Address doesn't exist — can't debit from nothing.
        throw new InsufficientCreditsError(address, amount, 0);
      }

      // Which purchases these credits came out of, and what they cost.
      // Plan credits (expiring) first, then the usual oldest-first order.
      this._lots(`spend ${ref}`, () => this._consumeFunding(address, amount, available, { spendRef: ref, ts, expiringFirst: true }));

      this.db.exec('COMMIT');
      return true;
    } catch (err) {
      try { this.db.exec('ROLLBACK'); } catch (_) { /* already rolled back */ }
      if (isDuplicateRefError(err)) return false;
      throw err;
    }
  }

  /**
   * Manual adjustment (admin operation). Idempotent on `ref`.
   * Positive amount = credit, negative = debit. Does NOT throw on
   * insufficient balance (admin override), but balance is floored at 0.
   *
   * @param {string} address
   * @param {number} amount  - Positive (credit) or negative (debit) integer
   * @param {string} ref     - Idempotency key
   * @param {string} [note]
   * @param {number} [ts]
   * @returns {boolean} true if newly applied
   */
  adjust(address, amount, ref, note = null, ts = Date.now()) {
    if (typeof address !== 'string' || address.length === 0) {
      throw new TypeError('adjust requires a non-empty address');
    }
    if (!Number.isInteger(amount) || amount === 0) {
      throw new RangeError(`adjust amount must be a non-zero integer, got ${amount}`);
    }
    if (!ref || typeof ref !== 'string') {
      throw new TypeError('adjust requires a non-empty ref (idempotency key)');
    }

    if (this._st.hasRef.get(ref)) return false;

    this.db.exec('BEGIN IMMEDIATE');
    try {
      if (amount > 0) {
        // Positive adjustment = credit
        this._st.insJournal.run(ts, address, 'adjustment', amount, ref, note, null, null, null, null);
        this._st.upsertCredit.run(address, amount, amount, ts);
        this._lots(`open lot for ${ref}`, () => this._openLot(address, amount, ref, ts, null));
      } else {
        // Negative adjustment = debit, clamped to the available balance.
        //
        // The journal must record what was ACTUALLY taken, not what was asked
        // for. Recording the requested amount while the balance floors at zero
        // breaks total_earned = balance + total_spent permanently, so
        // verifyConservation() would report drift forever after.
        const balRow = this._st.getBalance.get(address);
        const available = balRow ? balRow.balance : 0;
        const actualDebit = Math.min(Math.abs(amount), available);

        this._st.insJournal.run(ts, address, 'adjustment', -actualDebit, ref, note, null, null, null, null);

        if (actualDebit > 0) {
          this._lots(`adjustment ${ref}`, () => this._consumeFunding(address, actualDebit, available));
          this.db.prepare(`
            UPDATE credit_balances
            SET balance = balance - ?,
                total_spent = total_spent + ?,
                updated_at = ?
            WHERE address = ?
          `).run(actualDebit, actualDebit, ts, address);
        }
      }

      this.db.exec('COMMIT');
      return true;
    } catch (err) {
      try { this.db.exec('ROLLBACK'); } catch (_) { /* already rolled back */ }
      if (isDuplicateRefError(err)) return false;
      throw err;
    }
  }

  /**
   * Take back credits whose payment was reversed. Idempotent on `ref`.
   *
   * Three things make this different from debit() and adjust(), and each is
   * the reason it exists rather than being one of them:
   *
   *   - It never fails for lack of balance. The customer may have spent the
   *     credits already; what is left is drained and the rest is written down
   *     as a shortfall in the journal note. debit() would throw and take
   *     nothing — the worst outcome when the money has already gone back.
   *   - It is bounded by the GRANT, across events. `target` is cumulative:
   *     "this much of that grant should be reversed by now". A charge refunded
   *     in two halves, or refunded and then disputed, sends several events
   *     about the same money; each takes only what the earlier ones did not,
   *     and the total can never exceed what the grant was. Without that bound
   *     a second event would reach into credits bought with other payments.
   *   - The amount taken, the amount owed and the shortfall are decided inside
   *     one transaction, so the journal note cannot disagree with the balance.
   *
   * @param {Object} c
   * @param {string} c.address   - whose balance
   * @param {string} c.grantRef  - stable name of the grant being reversed
   * @param {string} [c.lotRef]  - the ledger ref the grant was CREDITED under,
   *                               when that is not `grantRef` (subscription
   *                               payments: filed as `sub-payment:<id>`,
   *                               credited as `sub-period:<key>`). It selects
   *                               the funding lot whose dollars are reversed.
   * @param {number} c.target    - cumulative credits of that grant to have
   *                               taken back once this event is applied
   * @param {string} c.ref       - idempotency key, e.g. `clawback:<event id>`
   * @param {string} [c.note]    - why (shortfall is appended)
   * @param {number} [c.ts]
   * @returns {{applied:boolean, due:number, debited:number, shortfall:number}}
   *   `applied` is false when `ref` was already processed. The spends whose
   *   money went back after the credits were used (the shortfall) are read
   *   with getReversals(ref) — after a replay too.
   *   `applied` is false when `ref` was already processed.
   */
  clawback(c) {
    const { address, grantRef, ref } = c || {};
    const lotRef = (c && typeof c.lotRef === 'string' && c.lotRef) || grantRef;
    const target = c && c.target;
    const ts = (c && c.ts) || Date.now();
    if (typeof address !== 'string' || address.length === 0) {
      throw new TypeError('clawback requires a non-empty address');
    }
    if (!grantRef || typeof grantRef !== 'string') {
      throw new TypeError('clawback requires a non-empty grantRef');
    }
    if (!Number.isInteger(target) || target < 0) {
      throw new RangeError(`clawback target must be a non-negative integer, got ${target}`);
    }
    if (!ref || typeof ref !== 'string') {
      throw new TypeError('clawback requires a non-empty ref (idempotency key)');
    }

    const seen = () => this.db
      .prepare('SELECT due, debited, shortfall FROM credit_clawbacks WHERE ref = ?').get(ref);
    const replay = (row) => ({ applied: false, due: row.due, debited: row.debited, shortfall: row.shortfall });

    const before = seen();
    if (before) return replay(before);
    if (this._st.hasRef.get(ref)) return { applied: false, due: 0, debited: 0, shortfall: 0 };

    this.db.exec('BEGIN IMMEDIATE');
    try {
      const prior = this.db
        .prepare('SELECT COALESCE(SUM(due), 0) AS s FROM credit_clawbacks WHERE grant_ref = ?')
        .get(grantRef).s;
      /* T-970: credits of this grant that already EXPIRED (plan credits at
       * the end of their month) have left the balance once. Taking them again
       * here would reach into whatever else the customer holds — a top-up
       * they paid for separately. */
      const expiredRow = this._st.hasRef.get(`sub-expire:${lotRef}`)
        ? this.db.prepare('SELECT amount FROM credit_journal WHERE ref = ?').get(`sub-expire:${lotRef}`)
        : null;
      const alreadyExpired = expiredRow ? Math.max(0, -expiredRow.amount) : 0;
      const due = Math.max(0, target - prior - alreadyExpired);

      const balRow = this._st.getBalance.get(address);
      const available = balRow ? balRow.balance : 0;
      const debited = Math.min(due, available);
      const shortfall = due - debited;

      const fullNote = [
        c.note || 'payment reversed',
        `clawback ${debited} of ${due} credits`,
        shortfall > 0 ? `SHORTFALL ${shortfall} (already spent)` : null,
      ].filter(Boolean).join(' — ');

      /* Recorded as an adjustment for what was ACTUALLY taken, like adjust():
       * journalling the amount owed while the balance floors at zero would
       * break total_earned = balance + total_spent for good. A zero-credit row
       * is still written — the attempt and its shortfall are the record. */
      this._st.insJournal.run(ts, address, 'adjustment', -debited, ref, fullNote, null, null, null, null);
      if (debited > 0) {
        // The refunded purchase's own lot goes first: its dollars went back to
        // the customer, so they must stop counting as revenue to share.
        this._lots(`clawback ${ref}`, () => this._consumeFunding(address, debited, available, { preferGrantRef: lotRef }));
        this._st.applyDebit.run(debited, debited, ts, address);
      }
      if (shortfall > 0) {
        // Credits of this purchase that were spent before the money went back:
        // name the spends, so a node's share of those dollars can be reversed.
        this._lots(`reversal ${ref}`, () => {
          const lot = this._st.lotByRef.get(lotRef);
          if (lot) this._reverseSpends(lot.id, shortfall, ref, ts);
        });
      }
      this.db
        .prepare('INSERT INTO credit_clawbacks (ref, grant_ref, address, due, debited, shortfall, ts) VALUES (?, ?, ?, ?, ?, ?, ?)')
        .run(ref, grantRef, address, due, debited, shortfall, ts);

      this.db.exec('COMMIT');
      return { applied: true, due, debited, shortfall };
    } catch (err) {
      try { this.db.exec('ROLLBACK'); } catch (_) { /* already rolled back */ }
      if (isDuplicateRefError(err) || /UNIQUE constraint failed: credit_clawbacks\.ref/i.test(err.message || '')) {
        const row = seen();
        return row ? replay(row) : { applied: false, due: 0, debited: 0, shortfall: 0 };
      }
      throw err;
    }
  }

  /**
   * Expire what is left of ONE grant. Idempotent on `ref`. (T-970)
   *
   * Subscription credits are valid for the billing period they were granted
   * for and do not carry over (Jimmie, DM 2026-10-17). This is the only way
   * they leave a balance other than by being spent, and it is deliberately
   * narrow:
   *
   *   - It touches exactly one funding lot — the one opened under `grantRef`
   *     — and takes min(what that lot still holds, the balance). Credits the
   *     customer bought separately (card top-up, TON, x402, PRL), hourly
   *     allocations and unlotted balance are never reached: there is no
   *     fall-through to the next lot the way a spend has.
   *   - The lot bookkeeping is part of the transaction, not best-effort: if
   *     the lot cannot be read or written, nothing is expired. An expiry that
   *     took the balance but not the lot would leave the lot "holding" credits
   *     that are gone, and the next spend would hand its dollars to them.
   *   - It is journalled as a negative 'adjustment' of what was ACTUALLY
   *     taken, so total_earned = balance + total_spent keeps holding. A
   *     zero-credit row is still written when there is nothing left (spent,
   *     clawed back, or no such lot), so a replayed sweep or webhook is a
   *     no-op by ref rather than a second look.
   *   - The dollars still in the lot leave with the credits and are attributed
   *     to no spend: a node is paid a share of what a request it served
   *     brought in, and an expired credit served nothing.
   *
   * @param {Object} e
   * @param {string} e.address
   * @param {string} e.grantRef - the ledger ref the grant was credited under
   *   (subscription_payments.ledger_ref)
   * @param {string} [e.ref] - idempotency key; default `sub-expire:<grantRef>`.
   *   Keep the default for anything clawback() may later reverse: a refund of
   *   the same grant looks the expiry up under that name so it does not take
   *   the expired credits a second time.
   * @param {string} [e.note]
   * @param {number} [e.ts]
   * @returns {{applied:boolean, expired:number, reason?:string}}
   */
  expireGrant(e) {
    const { address, grantRef } = e || {};
    if (typeof address !== 'string' || address.length === 0) {
      throw new TypeError('expireGrant requires a non-empty address');
    }
    if (!grantRef || typeof grantRef !== 'string') {
      throw new TypeError('expireGrant requires a non-empty grantRef');
    }
    const ref = (e && typeof e.ref === 'string' && e.ref) || `sub-expire:${grantRef}`;
    const ts = (e && e.ts) || Date.now();

    if (this._st.hasRef.get(ref)) return { applied: false, expired: 0, reason: 'already expired' };

    this.db.exec('BEGIN IMMEDIATE');
    try {
      const lot = this._st.lotByRef.get(grantRef);
      this.lotRowsRead++;
      const balRow = this._st.getBalance.get(address);
      const available = balRow ? balRow.balance : 0;
      let reason;
      let take = 0;
      if (!lot) reason = 'no funding lot for this grant';
      else if (String(lot.address).toLowerCase() !== String(address).toLowerCase()) reason = 'grant belongs to another address';
      else take = Math.min(lot.credits_remaining, available);
      if (!reason && take === 0) reason = 'nothing left to expire';

      const note = [e.note || `plan credits expired at the end of their billing period (${grantRef})`,
        `expired ${take} credits`].join(' — ');
      this._st.insJournal.run(ts, address, 'adjustment', -take, ref, note, null, null, null, null);
      if (take > 0) {
        const usd = take === lot.credits_remaining
          ? lot.usd_micro_remaining
          : Number((BigInt(lot.usd_micro_remaining) * BigInt(take)) / BigInt(lot.credits_remaining));
        this._st.takeFromLot.run(take, usd, lot.id);
        this._st.subOpenCredits.run(take, address);
        if (lot.expiring === 1) this._st.subExpiringCredits.run(take, address);
        this._st.applyDebit.run(take, take, ts, address);
      }
      this.db.exec('COMMIT');
      return reason ? { applied: true, expired: take, reason } : { applied: true, expired: take };
    } catch (err) {
      try { this.db.exec('ROLLBACK'); } catch (_) { /* already rolled back */ }
      if (isDuplicateRefError(err)) return { applied: false, expired: 0, reason: 'already expired' };
      throw err;
    }
  }

  /**
   * Credits still open in one grant's funding lot (0 if there is no such lot).
   * @param {string} grantRef
   * @returns {number}
   */
  getGrantRemaining(grantRef) {
    const lot = grantRef ? this._st.lotByRef.get(grantRef) : null;
    return lot ? lot.credits_remaining : 0;
  }

  /**
   * Get journal history for an address.
   * @param {string} address
   * @param {number} [limit=50]
   * @returns {Array<Object>}
   */
  getHistory(address, limit = 50) {
    return this._st.journalByAddr.all(address, clampLimit(limit, 50));
  }

  /**
   * Aggregate stats across all miners.
   * @returns {{ totalOutstanding:number, totalAllocated:number, totalSpent:number, minerCount:number }}
   */
  getStats() {
    const balSum = this._st.sumBalances.get();
    const earnedSum = this._st.sumEarned.get();
    const spentSum = this._st.sumSpent.get();
    const countRow = this._st.countMiners.get();
    return {
      totalOutstanding: balSum.s,
      totalAllocated: earnedSum.s,
      totalSpent: spentSum.s,
      minerCount: countRow.n,
    };
  }

  /**
   * Audit the conservation invariant:
   *   totalAllocated === sum(balances) + totalSpent
   *
   * For a sound credit ledger:
   *   - Every credit added `total_earned` and `balance`
   *   - Every debit subtracted from `balance` and added to `total_spent`
   *   - Therefore: total_earned = sum(balance) + total_spent
   *   - Drift should always be 0.
   *
   * @returns {{ ok:boolean, totalAllocated:number, totalOutstanding:number, totalSpent:number, drift:number }}
   */
  verifyConservation() {
    const stats = this.getStats();
    const drift = stats.totalAllocated - (stats.totalOutstanding + stats.totalSpent);
    return {
      ok: drift === 0,
      totalAllocated: stats.totalAllocated,
      totalOutstanding: stats.totalOutstanding,
      totalSpent: stats.totalSpent,
      drift,
    };
  }

  /**
   * Close the database connection and checkpoint WAL.
   */
  close() {
    try { this.db.exec('PRAGMA wal_checkpoint(TRUNCATE);'); } catch { /* best effort */ }
    this.db.close();
  }
}

module.exports = { CreditLedger, InsufficientCreditsError, SCHEMA_VERSION };
