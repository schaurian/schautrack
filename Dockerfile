FROM node:24-alpine AS client

WORKDIR /app/client

COPY client/package*.json ./

RUN npm ci && \
    npm cache clean --force

COPY client/ ./

RUN npm run build

FROM golang:1.26-alpine AS server

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ cmd/
COPY internal/ internal/

ARG BUILD_VERSION=dev
RUN CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=${BUILD_VERSION}" -o /server ./cmd/server

FROM alpine:3.23

RUN apk add --no-cache ca-certificates tzdata && \
    adduser -D -u 1000 appuser

WORKDIR /app

COPY --from=server /server ./server
COPY --from=client /app/client/dist ./client/dist
COPY public ./public

ARG BUILD_VERSION=dev
ENV BUILD_VERSION=$BUILD_VERSION \
    PORT=3000 \
    TZ=UTC

USER appuser

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=10s \
    CMD wget -q --spider http://localhost:3000/api/health || exit 1

CMD ["./server"]
