FROM node:22-alpine AS builder

WORKDIR /app

COPY package*.json ./

RUN npm ci --production --omit=dev && \
    npm cache clean --force

FROM node:22-alpine

WORKDIR /app

# Copy only production dependencies from builder
COPY --from=builder /app/node_modules ./node_modules

# Copy application files
COPY src ./src
COPY views ./views
COPY public ./public
COPY package.json ./

ARG BUILD_VERSION=dev
ENV BUILD_VERSION=$BUILD_VERSION
ENV NODE_ENV=production
ENV PORT=3000

# Run as non-root user
USER node

EXPOSE 3000

CMD ["node", "src/server.js"]
