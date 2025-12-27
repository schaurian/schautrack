FROM node:22-alpine AS builder

WORKDIR /app

COPY package*.json ./

RUN npm install --omit=dev && \
    npm cache clean --force && \
    rm -rf /root/.npm

FROM node:22-alpine

RUN apk add --no-cache dumb-init

WORKDIR /app

# Copy only production dependencies from builder
COPY --from=builder /app/node_modules ./node_modules

# Copy all application files (everything is in src now)
COPY --chown=node:node src ./src
COPY --chown=node:node package.json ./

ARG BUILD_VERSION=dev
ENV BUILD_VERSION=$BUILD_VERSION \
    NODE_ENV=production \
    PORT=3000 \
    TZ=UTC

# Run as non-root user
USER node

EXPOSE 3000

# Use dumb-init to handle signals properly
CMD ["dumb-init", "node", "src/server.js"]
