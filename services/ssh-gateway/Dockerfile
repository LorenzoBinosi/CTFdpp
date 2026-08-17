FROM rust:1.86-slim-bookworm AS build

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY services ./services
RUN cargo build --locked --release -p ctfzone-ssh-gateway

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl openssh-client \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10003 ctfzone \
    && useradd --no-log-init --uid 10003 --gid 10003 --shell /usr/sbin/nologin ctfzone \
    && mkdir -p /var/lib/ctfzone-ssh-gateway/identities \
    && chmod 0700 /var/lib/ctfzone-ssh-gateway/identities \
    && chown -R 10003:10003 /var/lib/ctfzone-ssh-gateway

COPY --from=build /build/target/release/ctfzone-ssh-gateway /usr/local/bin/ctfzone-ssh-gateway

USER 10003:10003
EXPOSE 8091
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=6 \
    CMD curl --fail --silent --show-error http://127.0.0.1:8091/readyz >/dev/null
ENTRYPOINT ["/usr/local/bin/ctfzone-ssh-gateway"]
