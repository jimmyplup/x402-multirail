'use strict';

/**
 * Storage-level backstop for the address case-folding bug (AUTH-REVIEW F-1).
 *
 * bech32 is defined as case-insensitive, so `PRL1abc…` and `prl1abc…` are the
 * same wallet. Our tables stored `address TEXT` with SQLite's default BINARY
 * collation, so they compared as raw bytes: one wallet could become many
 * accounts. The application layer now lowercases at every entry point, but that
 * is a convention, not a guarantee — a future route that forgets to canonicalise
 * silently reintroduces the whole bug.
 *
 * `COLLATE NOCASE` moves the guarantee into the storage engine, where it cannot
 * be forgotten. SQLite's NOCASE is ASCII-only, which is exactly right: bech32 is
 * an ASCII alphabet, so there is no Unicode folding surprise to worry about.
 *
 * Applying it to a PRIMARY KEY / UNIQUE column requires the standard SQLite
 * table-rebuild dance (create-copy-drop-rename), because collation is baked into
 * the column definition and `ALTER TABLE` cannot change it.
 *
 * Design rules this module holds to:
 *
 *   1. SURVEY FIRST, NEVER MERGE. If two rows would collide once folded, that is
 *      either a live instance of the bug or two distinct miners — and deciding
 *      which, or merging balances, is a money operation. This module reports and
 *      refuses; it does not guess.
 *   2. IDEMPOTENT. Detects collation already applied and returns cleanly, so it
 *      is safe on every startup.
 *   3. TRANSACTIONAL, WITH A ROW-COUNT PROOF. Counts before and after and aborts
 *      the transaction on any mismatch, so a partial rebuild cannot be committed.
 */

/** Tables whose `address` column must be case-insensitive, and their indexes. */
const ADDRESS_TABLES = {
  credit_balances: { column: 'address' },
  credit_journal: { column: 'address' },
  api_keys: { column: 'address' },
  contributions: { column: 'address' },
  contribution_scores: { column: 'address' },
};

function tableExists(db, table) {
  return !!db
    .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name=?")
    .get(table);
}

/**
 * True when `column` on `table` already carries COLLATE NOCASE.
 *
 * Read from the stored DDL rather than PRAGMA table_info, because table_info
 * does not report collation.
 */
function hasNocase(db, table, column) {
  const row = db
    .prepare("SELECT sql FROM sqlite_master WHERE type='table' AND name=?")
    .get(table);
  if (!row || !row.sql) return false;
  // Match the column definition line specifically, so that COLLATE NOCASE on
  // some *other* column of the same table is not mistaken for this one.
  const re = new RegExp(`\\b${column}\\b[^,)]*collate\\s+nocase`, 'i');
  return re.test(row.sql);
}

/**
 * Find addresses that are distinct byte-wise but identical when folded.
 *
 * @returns {Array<{folded: string, variants: string[], rows: number}>}
 */
function surveyCollisions(db, table, column) {
  if (!tableExists(db, table)) return [];
  const rows = db
    .prepare(
      `SELECT LOWER(${column}) AS folded,
              COUNT(DISTINCT ${column}) AS variant_count,
              COUNT(*) AS rows
         FROM ${table}
        WHERE ${column} IS NOT NULL
        GROUP BY LOWER(${column})
       HAVING COUNT(DISTINCT ${column}) > 1`
    )
    .all();

  return rows.map((r) => ({
    folded: r.folded,
    rows: r.rows,
    variants: db
      .prepare(
        `SELECT DISTINCT ${column} AS v FROM ${table} WHERE LOWER(${column}) = ?`
      )
      .all(r.folded)
      .map((x) => x.v),
  }));
}

/**
 * Survey every address table without modifying anything.
 *
 * Safe to call at any time, including against production, and is the mode that
 * must be run and shown to a human before an apply.
 *
 * @param {import('node:sqlite').DatabaseSync} db
 * @param {string[]} [tables] - Restrict to these tables (default: all present).
 * @returns {{clean: boolean, tables: Array<Object>}}
 */
function survey(db, tables = Object.keys(ADDRESS_TABLES)) {
  const out = [];
  for (const table of tables) {
    if (!tableExists(db, table)) {
      out.push({ table, present: false });
      continue;
    }
    const { column } = ADDRESS_TABLES[table];
    const total = db.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get().n;
    const distinct = db
      .prepare(`SELECT COUNT(DISTINCT ${column}) AS n FROM ${table}`)
      .get().n;
    const nonLower = db
      .prepare(
        `SELECT COUNT(*) AS n FROM ${table} WHERE ${column} <> LOWER(${column})`
      )
      .get().n;
    const collisions = surveyCollisions(db, table, column);
    out.push({
      table,
      present: true,
      column,
      applied: hasNocase(db, table, column),
      rows: total,
      distinctAddresses: distinct,
      nonLowercaseRows: nonLower,
      collisions,
    });
  }
  return {
    clean: out.every((t) => !t.present || t.collisions.length === 0),
    tables: out,
  };
}

/**
 * Format a survey result as human-readable text for a runbook / log.
 * @param {ReturnType<typeof survey>} result
 * @returns {string}
 */
function formatSurvey(result) {
  const lines = [];
  for (const t of result.tables) {
    if (!t.present) {
      lines.push(`  ${t.table.padEnd(20)} — not present in this database`);
      continue;
    }
    lines.push(
      `  ${t.table.padEnd(20)} rows=${String(t.rows).padEnd(6)} ` +
        `distinct=${String(t.distinctAddresses).padEnd(6)} ` +
        `non-lowercase=${String(t.nonLowercaseRows).padEnd(4)} ` +
        `collate_nocase=${t.applied ? 'yes' : 'NO'} ` +
        `collisions=${t.collisions.length}`
    );
    for (const c of t.collisions) {
      lines.push(`      COLLISION ${c.folded} <- ${c.variants.join(' , ')}`);
    }
  }
  lines.push(
    result.clean
      ? '  RESULT: clean — safe to apply'
      : '  RESULT: COLLISIONS PRESENT — migration will refuse. Reconcile manually.'
  );
  return lines.join('\n');
}

/**
 * Rebuild one table with COLLATE NOCASE on its address column.
 *
 * Uses the standard SQLite pattern, since collation cannot be altered in place:
 * create the new table, copy, drop the old, rename, recreate indexes. Row counts
 * are captured before and after and any mismatch throws, which rolls the
 * enclosing transaction back and leaves the original table untouched.
 *
 * @private
 */
function rebuildTable(db, table, column) {
  const master = db
    .prepare("SELECT sql FROM sqlite_master WHERE type='table' AND name=?")
    .get(table);
  if (!master || !master.sql) {
    throw new Error(`nocase-migration: cannot read DDL for table ${table}`);
  }

  // Capture the indexes to recreate. Skip auto-generated ones (sqlite_autoindex_*),
  // which SQLite rebuilds itself from the PRIMARY KEY / UNIQUE constraints.
  const indexes = db
    .prepare(
      "SELECT name, sql FROM sqlite_master WHERE type='index' AND tbl_name=? AND sql IS NOT NULL"
    )
    .all(table);

  const columns = db
    .prepare(`PRAGMA table_info(${table})`)
    .all()
    .map((c) => c.name);
  if (!columns.includes(column)) {
    throw new Error(`nocase-migration: ${table} has no column ${column}`);
  }
  const columnList = columns.join(', ');

  const before = db.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get().n;

  // Add COLLATE NOCASE to the target column's definition. Anchor on the column
  // name at the start of its definition and insert after its type keyword, so
  // constraints such as PRIMARY KEY / NOT NULL stay in a legal position.
  const tmp = `${table}__nocase_tmp`;
  let newSql = master.sql.replace(
    /^\s*CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?["'`[]?\w+["'`\]]?/i,
    `CREATE TABLE ${tmp}`
  );
  const colRe = new RegExp(`(\\b${column}\\b\\s+(?:TEXT|VARCHAR\\([^)]*\\)|CHAR\\([^)]*\\)))`, 'i');
  if (!colRe.test(newSql)) {
    throw new Error(
      `nocase-migration: could not locate a TEXT definition for ${table}.${column} in its DDL; refusing to rewrite`
    );
  }
  newSql = newSql.replace(colRe, '$1 COLLATE NOCASE');

  db.exec(newSql);
  db.exec(`INSERT INTO ${tmp} (${columnList}) SELECT ${columnList} FROM ${table};`);

  const copied = db.prepare(`SELECT COUNT(*) AS n FROM ${tmp}`).get().n;
  if (copied !== before) {
    // Throwing rolls back the enclosing transaction; the original table is intact.
    throw new Error(
      `nocase-migration: row count mismatch on ${table} (before=${before}, copied=${copied}); aborting`
    );
  }

  db.exec(`DROP TABLE ${table};`);
  db.exec(`ALTER TABLE ${tmp} RENAME TO ${table};`);

  for (const idx of indexes) {
    db.exec(`${idx.sql};`);
  }

  const after = db.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get().n;
  if (after !== before) {
    throw new Error(
      `nocase-migration: post-rebuild row count mismatch on ${table} (before=${before}, after=${after}); aborting`
    );
  }

  return { table, rows: before, indexes: indexes.length };
}

/**
 * Apply COLLATE NOCASE to the address columns of the given tables.
 *
 * Idempotent: tables that already have the collation, or are not present in this
 * database, are skipped. Refuses outright (throws) if any table contains rows
 * that would collide once folded — merging balances is a money decision and is
 * deliberately not automated here.
 *
 * @param {import('node:sqlite').DatabaseSync} db
 * @param {string[]} tables - Tables owned by the calling store.
 * @returns {{skipped: string[], migrated: Array<{table:string, rows:number}>}}
 */
function applyNocase(db, tables) {
  const todo = [];
  const skipped = [];

  for (const table of tables) {
    const spec = ADDRESS_TABLES[table];
    if (!spec) throw new Error(`nocase-migration: unknown table ${table}`);
    if (!tableExists(db, table) || hasNocase(db, table, spec.column)) {
      skipped.push(table);
      continue;
    }
    todo.push({ table, column: spec.column });
  }

  if (todo.length === 0) return { skipped, migrated: [] };

  // Survey before touching anything. Report all colliding tables at once rather
  // than failing on the first, so an operator sees the whole problem.
  const problems = [];
  for (const { table, column } of todo) {
    for (const c of surveyCollisions(db, table, column)) {
      problems.push(`${table}: "${c.folded}" <- ${c.variants.map((v) => JSON.stringify(v)).join(', ')}`);
    }
  }
  if (problems.length > 0) {
    throw new Error(
      'nocase-migration refuses to run: addresses differing only by case already exist, ' +
        'and folding them would merge distinct rows. This is a money operation and must be ' +
        'reconciled by a human.\n  ' +
        problems.join('\n  ')
    );
  }

  const migrated = [];
  // foreign_keys must be off for the drop/rename dance, and the pragma is a
  // no-op inside a transaction — so it is toggled outside one.
  const fkRow = db.prepare('PRAGMA foreign_keys').get();
  const fkWasOn = !!(fkRow && Object.values(fkRow)[0]);
  if (fkWasOn) db.exec('PRAGMA foreign_keys = OFF;');

  try {
    db.exec('BEGIN IMMEDIATE;');
    try {
      for (const { table, column } of todo) {
        migrated.push(rebuildTable(db, table, column));
      }
      // Catch any FK/schema damage the rebuild might have caused before committing.
      const violations = db.prepare('PRAGMA foreign_key_check').all();
      if (violations.length > 0) {
        throw new Error(
          `nocase-migration: ${violations.length} foreign key violation(s) after rebuild; aborting`
        );
      }
      db.exec('COMMIT;');
    } catch (err) {
      try { db.exec('ROLLBACK;'); } catch { /* already rolled back */ }
      throw err;
    }
  } finally {
    if (fkWasOn) db.exec('PRAGMA foreign_keys = ON;');
  }

  return { skipped, migrated };
}

module.exports = {
  ADDRESS_TABLES,
  applyNocase,
  survey,
  formatSurvey,
  hasNocase,
};
