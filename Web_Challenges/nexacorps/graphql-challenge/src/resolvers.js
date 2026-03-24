const bcrypt = require('bcryptjs');
const { GraphQLError } = require('graphql');
const { db } = require('./database');
const { signToken } = require('./auth');

// ─── Auth Guards ─────────────────────────────────────────────────────────────

function requireAuth(user) {
  if (!user) {
    throw new GraphQLError('You must be logged in.', {
      extensions: { code: 'UNAUTHENTICATED' },
    });
  }
}

function requireAdmin(user) {
  requireAuth(user);
  if (user.role !== 'admin') {
    throw new GraphQLError('Admin privileges required.', {
      extensions: { code: 'FORBIDDEN' },
    });
  }
}

// ─── WAF: "Enterprise Security Layer" ────────────────────────────────────────
// Looks robust, but has a bypass via UNION ALL SELECT (the \s+ regex doesn't
// match when ALL sits between UNION and SELECT). Players also need to close the
// trailing %' without comments — solved with a WHERE ... LIKE trick.

function wafSanitize(input) {
  // Each blocked pattern returns a distinct error so players can map the WAF
  if (/--/.test(input)) {
    throw new GraphQLError('WAF: SQL single-line comments (--) are not allowed.', {
      extensions: { code: 'WAF_BLOCK' },
    });
  }
  if (/\/\*/.test(input)) {
    throw new GraphQLError('WAF: SQL block comments (/*) are not allowed.', {
      extensions: { code: 'WAF_BLOCK' },
    });
  }
  if (/;/.test(input)) {
    throw new GraphQLError('WAF: semicolons are not allowed.', {
      extensions: { code: 'WAF_BLOCK' },
    });
  }
  if (/union\s+select/i.test(input)) {
    throw new GraphQLError('WAF: UNION SELECT pattern is not allowed.', {
      extensions: { code: 'WAF_BLOCK' },
    });
  }

  return input;
}

// ─── Resolvers ───────────────────────────────────────────────────────────────

const resolvers = {
  Query: {
    me: (_, __, { user }) => {
      requireAuth(user);
      return db.prepare('SELECT * FROM users WHERE id = ?').get(user.userId);
    },

    getEmployees: (_, __, { user }) => {
      requireAuth(user);
      return db.prepare('SELECT id, name, department, salary FROM employees').all();
    },

    // ⚠️  VULNERABILITY: Raw SQL concatenation with a bypassable WAF
    searchEmployees: (_, { query }, { user }) => {
      requireAdmin(user);
      const sanitized = wafSanitize(query);
      try {
        const sql = `SELECT * FROM employees WHERE name LIKE '%${sanitized}%'`;
        return db.prepare(sql).all();
      } catch (err) {
        // Leaks SQLite error messages — helps players debug column count, etc.
        throw new GraphQLError(`Database error: ${err.message}`, {
          extensions: { code: 'INTERNAL_ERROR' },
        });
      }
    },

    adminPanel: (_, __, { user }) => {
      requireAdmin(user);
      const totalUsers = db.prepare('SELECT COUNT(*) AS c FROM users').get().c;
      const totalEmployees = db.prepare('SELECT COUNT(*) AS c FROM employees').get().c;
      return {
        totalUsers,
        totalEmployees,
        systemVersion: 'GraphCorp Portal v2.4.1',
      };
    },
  },

  Mutation: {
    login: async (_, { username, password }) => {
      const row = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
      if (!row || !bcrypt.compareSync(password, row.password_hash)) {
        throw new GraphQLError('Invalid username or password.', {
          extensions: { code: 'UNAUTHENTICATED' },
        });
      }
      const token = signToken({ userId: row.id, username: row.username, role: row.role });
      return { token, user: row };
    },

    register: async (_, { username, password, email }) => {
      if (username.length < 3 || password.length < 6) {
        throw new GraphQLError('Username must be ≥ 3 chars, password ≥ 6 chars.', {
          extensions: { code: 'BAD_USER_INPUT' },
        });
      }
      const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
      if (existing) {
        throw new GraphQLError('Username already taken.', {
          extensions: { code: 'BAD_USER_INPUT' },
        });
      }
      const hash = bcrypt.hashSync(password, 12);
      const result = db
        .prepare('INSERT INTO users (username, password_hash, email, role) VALUES (?, ?, ?, ?)')
        .run(username, hash, email || null, 'employee');
      const row = db.prepare('SELECT * FROM users WHERE id = ?').get(result.lastInsertRowid);
      const token = signToken({ userId: row.id, username: row.username, role: row.role });
      return { token, user: row };
    },

    // ⚠️  VULNERABILITY: Mass assignment — `role` field was accidentally left in
    //     UpdateProfileInput and is processed without authorization check.
    updateProfile: (_, { input }, { user }) => {
      requireAuth(user);
      const { displayName, bio, email, role } = input;

      if (role !== undefined) {
        db.prepare('UPDATE users SET role = ? WHERE id = ?').run(role, user.userId);
      }
      if (displayName !== undefined) {
        db.prepare('UPDATE users SET display_name = ? WHERE id = ?').run(displayName, user.userId);
      }
      if (bio !== undefined) {
        db.prepare('UPDATE users SET bio = ? WHERE id = ?').run(bio, user.userId);
      }
      if (email !== undefined) {
        db.prepare('UPDATE users SET email = ? WHERE id = ?').run(email, user.userId);
      }

      const updated = db.prepare('SELECT * FROM users WHERE id = ?').get(user.userId);
      // Re-issue a token with the (possibly updated) role so the change takes effect immediately
      const newToken = signToken({ userId: updated.id, username: updated.username, role: updated.role });
      return { token: newToken, user: updated };
    },
  },

  // ─── Field Resolvers ───────────────────────────────────────────────────────

  User: {
    displayName: (row) => row.display_name,
  },

  Employee: {
    salary: (row, _, { user }) => (user?.role === 'admin' ? row.salary : null),
  },
};

module.exports = { resolvers };
