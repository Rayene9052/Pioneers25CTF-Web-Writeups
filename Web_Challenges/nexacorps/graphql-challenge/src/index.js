const express = require('express');
const { json } = require('body-parser');
const cors = require('cors');
const path = require('path');
const { ApolloServer } = require('@apollo/server');
const { expressMiddleware } = require('@apollo/server/express4');

const { typeDefs } = require('./schema');
const { resolvers } = require('./resolvers');
const { initDB } = require('./database');
const { getUserFromRequest } = require('./auth');

async function start() {
  initDB();

  const app = express();

  app.use(cors());
  app.use(json());

  // Serve the frontend
  app.use(express.static(path.join(__dirname, '..', 'public')));

  const server = new ApolloServer({
    typeDefs,
    resolvers,
    introspection: true, // Blocked per-request below unless X-Dev-Mode: 1
    includeStacktraceInErrorResponses: false,
  });

  await server.start();

  // ─── Introspection Gate ─────────────────────────────────────────────────────
  // Introspection is only allowed when the X-Dev-Mode: 1 header is present.
  // This simulates a server that has "disabled" introspection in production
  // but still exposes a debug bypass.
  app.use('/graphql', (req, res, next) => {
    const query = (req.body?.query || '') + (req.body?.operationName || '');
    const isIntrospection = query.includes('__schema') || query.includes('__type');

    if (isIntrospection && req.headers['x-dev-mode'] !== '1') {
      return res.status(200).json({
        errors: [
          {
            message:
              'GraphQL introspection is not allowed, except in development mode.',
            extensions: { code: 'FORBIDDEN' },
          },
        ],
      });
    }
    next();
  });

  app.use(
    '/graphql',
    expressMiddleware(server, {
      context: async ({ req }) => {
        const user = getUserFromRequest(req);
        return { user };
      },
    })
  );

  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`[graphcorp] Server listening on http://0.0.0.0:${PORT}`);
  });
}

start().catch((err) => {
  console.error('[graphcorp] Fatal error:', err);
  process.exit(1);
});
