# Build needs a C compiler (rusqlite bundled SQLite); the default rust image has one.
FROM docker.io/library/rust:1.100.0-trixie@sha256:e19840879045c951c905d0eaa9887f3439c62000e429963371b376bac8d38c31 AS build
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

# Runtime needs gpg (openpgp) and must match the build's glibc — no alpine/musl.
FROM docker.io/library/debian:trixie-slim@sha256:d7e12182ce18b85b93007c1dedf31f2d29e01ccf3182cc4017c709b6259bc132
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates gnupg \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /build/target/release/vaultwarden-backup /usr/local/bin/vaultwarden-backup
ENTRYPOINT ["vaultwarden-backup"]