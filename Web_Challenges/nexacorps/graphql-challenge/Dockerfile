FROM node:20-alpine

WORKDIR /app

# Install build dependencies for native addons (better-sqlite3)
RUN apk add --no-cache python3 make g++

COPY package*.json ./
RUN npm install --omit=dev

COPY src/ ./src/
COPY public/ ./public/

# Storage volume for SQLite database
RUN mkdir -p /data

EXPOSE 3000

CMD ["node", "src/index.js"]
