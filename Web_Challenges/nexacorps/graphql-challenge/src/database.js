const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const path = require('path');

const DB_PATH = process.env.NODE_ENV === 'production'
  ? '/data/challenge.db'
  : path.join(__dirname, '..', 'challenge.db');

const db = new Database(DB_PATH);

// WAL mode for better concurrency
db.pragma('journal_mode = WAL');

function initDB() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      email TEXT,
      display_name TEXT,
      bio TEXT,
      role TEXT NOT NULL DEFAULT 'employee'
    );

    CREATE TABLE IF NOT EXISTS employees (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      department TEXT NOT NULL,
      salary REAL NOT NULL
    );

    CREATE TABLE IF NOT EXISTS secrets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      key TEXT NOT NULL,
      value TEXT NOT NULL
    );
  `);

  // Only seed if the database is empty
  const count = db.prepare('SELECT COUNT(*) as c FROM users').get().c;
  if (count > 0) return;

  // Admin account — strong password, not guessable
  const adminHash = bcrypt.hashSync('CorpAdmin2024!', 12);
  db.prepare(`INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin')`)
    .run('admin', adminHash);

  // Regular employees for realism
  const employees = [
    ['Alice Johnson', 'Engineering', 95000],
    ['Bob Smith', 'Marketing', 72000],
    ['Carol White', 'HR', 68000],
    ['David Brown', 'Finance', 88000],
    ['Eve Davis', 'Engineering', 102000],
  ];
  const empStmt = db.prepare('INSERT INTO employees (name, department, salary) VALUES (?, ?, ?)');
  for (const [name, dept, salary] of employees) {
    empStmt.run(name, dept, salary);
  }

  // The flag
  db.prepare(`INSERT INTO secrets (key, value) VALUES ('flag', 'Pioneers25{gr4phql_1ntr0sp3ct10n_byp4ss_m4ss_4ss1gnm3nt_4nd_un10n_sql_1nj3ct10n_ch41n3d}')`)
    .run();

  console.log('[db] Database initialized and seeded.');
}

module.exports = { db, initDB };
