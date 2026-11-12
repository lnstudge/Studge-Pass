# Multi-stage build — keeps the final image minimal and runs as a non-root user.
#
# Stage 1: builder — compiles in release mode with the standard Rust toolchain.
# Stage 2: runtime — copies only the binary and runs as nobody.
#
# Build:
#   docker build -t studge-relay .
#
# Run (development, SQLite database in a named volume):
#   docker run --rm -p 8787:8787 \
#     -v studge-data:/data \
#     studge-relay
#
# The relay binds to 0.0.0.0:8787 inside the container (the config sets
# listen = "0.0.0.0:8787"). The host-side port is 8787; put Caddy in front
# for HTTPS (see docker-compose.yml).

ARG RUST_VERSION=1.87
FROM rust:${RUST_VERSION}-bookworm AS builder

WORKDIR /build

# Cache dependencies before copying source (speeds up re-builds).
COPY Cargo.toml Cargo.lock ./
COPY core/Cargo.toml       core/Cargo.toml
COPY core-wasm/Cargo.toml  core-wasm/Cargo.toml
COPY relay/Cargo.toml      relay/Cargo.toml
COPY cli/Cargo.toml        cli/Cargo.toml
COPY test-harness/Cargo.toml test-harness/Cargo.toml

# Create empty lib/main stubs so `cargo fetch` succeeds.
RUN mkdir -p core/src core-wasm/src relay/src cli/src test-harness/src \
 && echo 'pub fn _stub() {}' > core/src/lib.rs \
 && echo 'pub fn _stub() {}' > core-wasm/src/lib.rs \
 && echo 'fn main() {}' > relay/src/main.rs \
 && echo 'fn main() {}' > cli/src/main.rs \
 && echo 'pub fn _stub() {}' > test-harness/src/lib.rs

RUN cargo fetch --locked

# Now copy real source and build only the relay binary.
COPY core/        core/
COPY core-wasm/   core-wasm/
COPY relay/       relay/
COPY cli/         cli/
COPY test-harness/ test-harness/

RUN cargo build --release -p studge-relay --locked

# ── runtime stage ─────────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

# libgcc is the only system dependency; SQLite is compiled into the binary.
RUN apt-get update && apt-get install -y --no-install-recommends libgcc-s1 \
 && rm -rf /var/lib/apt/lists/*

# Create a non-root user and the data directory.
RUN useradd --system --no-create-home --uid 65534 nobody 2>/dev/null || true
RUN mkdir /data && chown nobody:nogroup /data

COPY --from=builder /build/target/release/studge-relay /usr/local/bin/studge-relay

# Default configuration: bind to all interfaces on 8787, put data in /data.
ENV STUDGE_RELAY_LISTEN=0.0.0.0:8787
ENV STUDGE_RELAY_DATABASE_PATH=/data/relay.db
ENV STUDGE_RELAY_SERVER_SETUP_PATH=/data/setup.bin

USER nobody
EXPOSE 8787

ENTRYPOINT ["/usr/local/bin/studge-relay"]
