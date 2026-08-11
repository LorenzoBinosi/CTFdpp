FROM rust:1.86-slim-bookworm AS build

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY services ./services
RUN cargo build --locked --release -p ctfzone-controller

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl openssh-client \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --no-log-init --uid 10002 --shell /usr/sbin/nologin ctfzone \
    && mkdir -p /var/lib/ctfzone-controller /etc/ctfzone \
    && chown -R 10002:10002 /var/lib/ctfzone-controller
COPY --from=build /build/target/release/ctfzone-controller /usr/local/bin/ctfzone-controller

USER 10002
EXPOSE 8090
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=6 \
    CMD curl --fail --silent --show-error http://127.0.0.1:8090/readyz >/dev/null
ENTRYPOINT ["/usr/local/bin/ctfzone-controller"]
