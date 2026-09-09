FROM rust:1.90-bookworm@sha256:3914072ca0c3b8aad871db9169a651ccfce30cf58303e5d6f2db16d1d8a7e58f AS builder
WORKDIR /source
COPY . .
ARG SOURCE_REVISION
RUN SOURCE_REVISION="$SOURCE_REVISION" python3 -c "import os; from pathlib import Path; from scripts.linux_release_support import package_container_documentation; package_container_documentation(Path('/source'), Path('/jury-docs'), os.environ['SOURCE_REVISION'])"
RUN cargo build --locked --release -p jury-witness --bin juryd

FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171
ARG SOURCE_REVISION
LABEL org.opencontainers.image.title="juryd" \
    org.opencontainers.image.revision="$SOURCE_REVISION" \
    org.opencontainers.image.description="Self-hostable Jury witness and external-anchor services" \
    org.opencontainers.image.source="https://github.com/bpcakes/jury" \
    org.opencontainers.image.licenses="Elastic-2.0" \
    org.opencontainers.image.vendor="Banana Pancakes"
RUN groupadd --gid 10001 juryd \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent juryd
COPY --from=builder /source/target/release/juryd /usr/local/bin/juryd
COPY LICENSE.md NOTICE.md /usr/share/licenses/jury/
COPY --from=builder /jury-docs/ /usr/share/doc/jury/
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/juryd"]
