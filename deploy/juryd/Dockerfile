FROM rust:1.90-bookworm AS builder
WORKDIR /source
COPY . .
RUN cargo build --locked --release -p jury-witness --bin juryd

FROM debian:bookworm-slim
RUN groupadd --gid 10001 juryd \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent juryd
COPY --from=builder /source/target/release/juryd /usr/local/bin/juryd
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/juryd"]
