FROM rust:1.90-bookworm AS builder
WORKDIR /source
COPY . .
RUN cargo build --locked --release -p jury-witness --bin juryd

FROM debian:bookworm-slim
LABEL org.opencontainers.image.title="juryd" \
    org.opencontainers.image.description="Pre-alpha Jury witness daemon; unsuitable for real secrets" \
    org.opencontainers.image.source="https://github.com/bpcakes/jury" \
    org.opencontainers.image.licenses="Elastic-2.0" \
    org.opencontainers.image.vendor="Banana Pancakes"
RUN groupadd --gid 10001 juryd \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent juryd
COPY --from=builder /source/target/release/juryd /usr/local/bin/juryd
COPY LICENSE.md NOTICE.md /usr/share/licenses/jury/
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/juryd"]
