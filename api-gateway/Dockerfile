FROM node:20-alpine

ENV NODE_ENV=production
ENV PORT=5000

WORKDIR /app

COPY api-gateway/package.json api-gateway/package-lock.json ./

RUN npm ci --omit=dev

COPY api-gateway/ ./

RUN chown -R node:node /app

USER node

EXPOSE 5000

CMD ["npm", "start"]