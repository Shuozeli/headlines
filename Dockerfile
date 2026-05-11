# syntax=docker/dockerfile:1.6
#
# Multi-stage build for the headlines demo container.
#
# Stage 1: build the `headlines-server` binary against debian:bookworm
# (matches our libpq target). Stage 2: copy the binary, demo data, and
# migrations onto a slim runtime image.

FROM rust:1.90 AS builder
WORKDIR /build
# `libprotobuf-dev` lays down the well-known proto includes
# (`/usr/include/google/protobuf/timestamp.proto`, etc.) that protoc needs
# to resolve the `google.protobuf.*` imports our schema uses.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        protobuf-compiler libprotobuf-dev libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy the workspace. We invalidate the cache on any source change.
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY proto ./proto
COPY db ./db
COPY migrations ./migrations
COPY gen ./gen
COPY buf.yaml buf.gen.yaml ./

# Build the release binary. The AUTH_TABLE build-script guard requires
# DATABASE_URL to be unset at build time (it's only consulted by the
# diesel CLI workflow), which is the default in this layer.
RUN cargo build --release --bin headlines-server

# ----------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpq5 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /build/target/release/headlines-server /usr/local/bin/headlines-server
COPY demo /app/demo
COPY migrations /app/migrations

ENV HEADLINES_DEMO_PATH=/app/demo
EXPOSE 50051 8080
ENTRYPOINT ["/usr/local/bin/headlines-server"]
