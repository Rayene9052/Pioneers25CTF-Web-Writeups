FROM node:20-alpine

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install --omit=dev

COPY server.js ./
COPY views ./views
COPY public ./public

EXPOSE 8080
CMD ["node", "server.js"]