FROM node:20-alpine

RUN apk add --no-cache chromium

ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true
ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium-browser

WORKDIR /app

COPY package.json ./
RUN npm install --production

COPY . .

RUN adduser -D ctfuser
USER ctfuser

EXPOSE 3000

CMD ["node", "server.js"]
