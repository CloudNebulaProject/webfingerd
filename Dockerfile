# Multi-stage build for webfingerd
# Build stage
FROM rust:1.87-bookworm AS builder

WORKDIR /build

# Copy manifests and lock
COPY Cargo.toml Cargo.lock ./
COPY migration/Cargo.toml ./migration/

# Create dummy sources for dependency caching
RUN mkdir src && echo "fn main() {}" > src/main.rs && echo "" > src/lib.rs \
    && mkdir -p migration/src && echo "" > migration/src/lib.rs

# Build dependencies only (cached layer)
ARG TARGETPLATFORM
RUN --mount=type=cache,target=/usr/local/cargo/registry,id=cargo-registry-${TARGETPLATFORM} \
    --mount=type=cache,target=/build/target,id=build-target-${TARGETPLATFORM} \
    cargo build --release 2>/dev/null || true

# Copy actual source code
COPY src ./src
COPY migration/src ./migration/src
COPY templates ./templates

# Build release binary
RUN --mount=type=cache,target=/usr/local/cargo/registry,id=cargo-registry-${TARGETPLATFORM} \
    --mount=type=cache,target=/build/target,id=build-target-${TARGETPLATFORM} \
    cargo build --release && \
    cp target/release/webfingerd /webfingerd

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -r -u 1000 -s /bin/false webfingerd && \
    mkdir -p /app/data && \
    chown -R webfingerd:webfingerd /app

WORKDIR /app

COPY --from=builder /webfingerd /usr/local/bin/webfingerd

RUN chown -R webfingerd:webfingerd /app

USER webfingerd

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD ["sh", "-c", "wget -q --spider http://localhost:8080/healthz || exit 1"]

ENTRYPOINT ["/usr/local/bin/webfingerd"]
