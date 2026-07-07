FROM python:3.11-slim-bookworm AS build

WORKDIR /opt/CTFdpp

# hadolint ignore=DL3008
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        libffi-dev \
        libssl-dev \
        git \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && python -m venv /opt/venv

ENV PATH="/opt/venv/bin:$PATH"

COPY . /opt/CTFdpp

RUN pip install --no-cache-dir -r requirements/requirements.txt


FROM python:3.11-slim-bookworm AS release
WORKDIR /opt/CTFdpp

# hadolint ignore=DL3008
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libffi8 \
        libssl3 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY --chown=1001:1001 . /opt/CTFdpp

RUN useradd \
    --no-log-init \
    --shell /bin/bash \
    -u 1001 \
    ctfdpp \
    && mkdir -p /var/log/CTFdpp /var/uploads \
    && chown -R 1001:1001 /var/log/CTFdpp /var/uploads /opt/CTFdpp \
    && chmod +x /opt/CTFdpp/deploy/docker-entrypoint.sh

COPY --chown=1001:1001 --from=build /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

USER 1001
EXPOSE 8000
ENTRYPOINT ["/opt/CTFdpp/deploy/docker-entrypoint.sh"]
