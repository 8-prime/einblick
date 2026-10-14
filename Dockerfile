FROM node:24-bookworm-slim AS frontend
WORKDIR /frontend
RUN corepack enable && corepack prepare pnpm@11.8.0 --activate
COPY frontend/package.json frontend/pnpm-lock.yaml frontend/pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile
COPY frontend/ ./
RUN pnpm check && pnpm build

FROM rust:1.96.1-slim-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl zstd pkg-config && rm -rf /var/lib/apt/lists/*
RUN rustup toolchain install nightly-2026-10-12 --profile minimal --component rust-src
RUN curl -fL https://github.com/aya-rs/bpf-linker/releases/download/v0.11.1/bpf-linker-x86_64-unknown-linux-musl.tar.zst -o /tmp/bpf-linker.tar.zst && tar --zstd -xf /tmp/bpf-linker.tar.zst -C /usr/local/bin && rm /tmp/bpf-linker.tar.zst
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY --from=frontend /frontend/dist frontend/dist/
RUN cargo +nightly-2026-10-12 build --locked --release --manifest-path crates/ebpf/Cargo.toml --target bpfel-unknown-none -Z build-std=core
RUN EINBLICK_EBPF_OBJECT=/build/crates/ebpf/target/bpfel-unknown-none/release/einblick-ebpf cargo build --locked --release

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates systemd \
    && journalctl --version \
    && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /data
COPY --from=build /build/target/release/einblick /usr/local/bin/einblick
WORKDIR /app
EXPOSE 9080
ENTRYPOINT ["/usr/local/bin/einblick"]
CMD ["--config", "/etc/einblick.toml"]
