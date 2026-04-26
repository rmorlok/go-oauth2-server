# Build stage
FROM golang:1.25.7 AS builder

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    ca-certificates \
    gcc \
    libc6-dev \
    libsqlite3-dev \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build the server binary (CGO enabled for sqlite3)
ENV CGO_ENABLED=1
RUN go build -o /out/go-oauth2-server .

# Runtime stage
FROM debian:bookworm-slim

LABEL maintainer="Richard Knop <risoknop@gmail.com>"

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    ca-certificates \
    libsqlite3-0 \
  && rm -rf /var/lib/apt/lists/*

# Create a new unprivileged user
RUN useradd --system --user-group --home /home/app --shell /usr/sbin/nologin app

WORKDIR /app

COPY --from=builder /out/go-oauth2-server /usr/local/bin/go-oauth2-server
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
COPY --chown=app:app oauth/fixtures ./oauth/fixtures
COPY --chown=app:app web ./web
COPY --chown=app:app public ./public

RUN chmod +x /usr/local/bin/docker-entrypoint.sh \
  && chown app:app /usr/local/bin/go-oauth2-server /usr/local/bin/docker-entrypoint.sh

USER app

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

EXPOSE 8080
