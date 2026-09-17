# Build needs a C compiler (rusqlite bundled SQLite); the default rust image has one.
FROM docker.io/library/rust:1.98-trixie@sha256:bf5a9aa29062a6cb03c49bd59a46eb55e3cc770caf598a221a7866e500be3082 AS build
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