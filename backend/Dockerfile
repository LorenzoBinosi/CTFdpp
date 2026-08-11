FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /opt/ctfzone-web

RUN groupadd --gid 10001 ctfzone \
    && useradd --no-log-init --uid 10001 --gid 10001 \
        --home-dir /opt/ctfzone-web --shell /usr/sbin/nologin ctfzone

COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir --requirement requirements.txt

COPY --chown=10001:10001 ctfzone_web ./ctfzone_web
COPY --chown=10001:10001 entrypoint.sh ./entrypoint.sh
RUN chmod 0555 ./entrypoint.sh

USER 10001:10001
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2)"

ENTRYPOINT ["./entrypoint.sh"]
