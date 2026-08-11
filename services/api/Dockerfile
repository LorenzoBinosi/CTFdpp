FROM rust:1.86-slim-bookworm AS build

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY services ./services
RUN cargo build --locked --release -p ctfzone-api

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --no-log-init --uid 10001 --shell /usr/sbin/nologin ctfzone \
    && mkdir -p /var/lib/ctfzone/uploads \
    && chown 10001:10001 /var/lib/ctfzone/uploads

COPY --from=build /build/target/release/ctfzone-api /usr/local/bin/ctfzone-api

USER 10001
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=6 \
    CMD curl --fail --silent --show-error http://127.0.0.1:8080/readyz >/dev/null
ENTRYPOINT ["/usr/local/bin/ctfzone-api"]
