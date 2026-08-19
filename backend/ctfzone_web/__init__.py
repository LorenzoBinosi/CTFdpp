"""CTFZone's replaceable Python web frontend.

The package deliberately has no database dependency. It renders the browser
experience and talks to the Rust API over HTTP.
"""

from __future__ import annotations

import ipaddress
import math
import os
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlsplit

from flask import Flask, request
from werkzeug.middleware.proxy_fix import ProxyFix

from .api import ApiClient
from .frontends import FrontendRegistry, assets
from .views import web


# The Rust transition route has a proven 59-second worst-case window:
# authentication (4s), execute pre-commit work including pool acquisition
# (45s), PostgreSQL-capped COMMIT (8s), and activity recording (2s).
TRANSITION_API_MAX_SECONDS = 59.0
TRANSITION_TIMEOUT_HEADROOM_SECONDS = 5.0


def create_app(test_config: dict | None = None) -> Flask:
    # Frontend files are served only through the explicitly isolated asset
    # routes below.  Disabling Flask's implicit /static route prevents a player
    # frontend from accidentally reaching administration assets (and vice
    # versa) through Flask's implicit shared directory.
    app = Flask(__name__, static_folder=None, template_folder=None)
    app.config.from_mapping(
        API_BASE_URL=os.getenv("API_BASE_URL", "http://api:8080"),
        API_TIMEOUT_SECONDS=float(os.getenv("API_TIMEOUT_SECONDS", "5")),
        API_STORAGE_TIMEOUT_SECONDS=float(
            os.getenv("API_STORAGE_TIMEOUT_SECONDS", "60")
        ),
        API_EMAIL_TIMEOUT_SECONDS=float(
            os.getenv("API_EMAIL_TIMEOUT_SECONDS", "20")
        ),
        API_TRANSITION_TIMEOUT_SECONDS=float(
            os.getenv("API_TRANSITION_TIMEOUT_SECONDS", "65")
        ),
        GUNICORN_WORKER_TIMEOUT_SECONDS=float(os.getenv("TIMEOUT", "75")),
        BACKEND_SERVICE_TOKEN=os.getenv("BACKEND_SERVICE_TOKEN"),
        FRONTENDS_ROOT=os.getenv(
            "FRONTENDS_ROOT", str(Path(__file__).resolve().parent / "frontends")
        ),
        MAX_CONTENT_LENGTH=int(
            os.getenv("MAX_PROXY_BODY_BYTES", str(6 * 1024 * 1024))
        ),
        OBJECT_STORAGE_PUBLIC_URL=os.getenv("OBJECT_STORAGE_PUBLIC_URL", ""),
        PERMANENT_SESSION_LIFETIME=timedelta(
            seconds=int(os.getenv("BROWSER_SESSION_LIFETIME_SECONDS", "604800"))
        ),
        SECRET_KEY=os.getenv("SECRET_KEY"),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_NAME=os.getenv(
            "BROWSER_SESSION_COOKIE_NAME", "ctfzone_browser_session"
        ),
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.getenv("BROWSER_SESSION_COOKIE_SECURE", "true")
        .strip()
        .casefold()
        not in {"0", "false", "no", "off"},
        # Assets use stable, unfingerprinted names. Revalidate them with their
        # ETags so a normal refresh cannot retain an older CSS/JS bundle.
        SEND_FILE_MAX_AGE_DEFAULT=0,
    )
    if test_config:
        app.config.update(test_config)

    if not app.config.get("SECRET_KEY"):
        raise RuntimeError("SECRET_KEY is required to sign browser sessions")
    if not app.config.get("BACKEND_SERVICE_TOKEN"):
        raise RuntimeError(
            "BACKEND_SERVICE_TOKEN is required for the private Rust API boundary"
        )
    _validate_transition_timeout_hierarchy(app)

    storage_url = str(app.config.get("OBJECT_STORAGE_PUBLIC_URL") or "").strip()
    storage_origin = ""
    if storage_url:
        parsed_storage = urlsplit(storage_url)
        if (
            parsed_storage.scheme not in {"http", "https"}
            or not parsed_storage.hostname
            or parsed_storage.username
            or parsed_storage.password
            or parsed_storage.query
            or parsed_storage.fragment
            or parsed_storage.path not in {"", "/"}
        ):
            raise RuntimeError(
                "OBJECT_STORAGE_PUBLIC_URL must be an HTTP(S) origin without a path"
            )
        storage_origin = f"{parsed_storage.scheme}://{parsed_storage.netloc}"
    app.config["OBJECT_STORAGE_ORIGIN"] = storage_origin

    # The container is reachable only through the trusted Caddy hop. Respect its
    # canonical host/scheme when enforcing same-origin browser requests.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    app.extensions["ctfzone_api"] = app.config.get("API_CLIENT") or ApiClient(
        app.config["API_BASE_URL"],
        app.config["BACKEND_SERVICE_TOKEN"],
        app.config["API_TIMEOUT_SECONDS"],
    )
    frontend_registry = FrontendRegistry.discover(app.config["FRONTENDS_ROOT"])
    app.extensions["ctfzone_frontends"] = frontend_registry
    app.jinja_loader = frontend_registry.template_loader()
    app.register_blueprint(assets)
    app.register_blueprint(web)

    @app.context_processor
    def frontend_asset_context():
        return {"frontend_asset_version": frontend_registry.asset_version}

    @app.after_request
    def secure_response(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
        connect_sources = ["'self'"]
        websocket_origin = _same_origin_websocket_source(request.scheme, request.host)
        if websocket_origin:
            connect_sources.append(websocket_origin)
        if app.config["OBJECT_STORAGE_ORIGIN"]:
            connect_sources.append(app.config["OBJECT_STORAGE_ORIGIN"])
        image_sources = ["'self'", "data:"]
        if app.config["OBJECT_STORAGE_ORIGIN"]:
            image_sources.append(app.config["OBJECT_STORAGE_ORIGIN"])
        style_sources = ["'self'"]
        # xterm creates runtime <style> elements for its viewport, cell
        # dimensions and theme, and also applies per-cell style attributes.
        # Limit the required exception to the one page that hosts the terminal;
        # scripts remain self-only and terminal bytes never enter HTML or CSS.
        if request.path == "/admin/machines":
            style_sources.append("'unsafe-inline'")
        response.headers.setdefault(
            "Content-Security-Policy",
            f"default-src 'self'; img-src {' '.join(image_sources)}; style-src {' '.join(style_sources)}; "
            f"script-src 'self'; connect-src {' '.join(connect_sources)}; frame-ancestors 'self'; "
            "form-action 'self'; base-uri 'self'",
        )
        if response.mimetype == "text/html":
            response.headers["Cache-Control"] = "private, no-store"
        return response

    return app


def _same_origin_websocket_source(scheme: str, raw_host: str) -> str:
    """Serialize the trusted request origin as one exact CSP WebSocket source."""

    if scheme not in {"http", "https"} or not isinstance(raw_host, str):
        return ""
    if not raw_host or len(raw_host) > 261 or not raw_host.isascii():
        return ""
    try:
        parsed = urlsplit(f"//{raw_host}")
        port = parsed.port
    except ValueError:
        return ""
    hostname = parsed.hostname
    if (
        not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or parsed.netloc != raw_host
    ):
        return ""

    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        dns_name = hostname[:-1] if hostname.endswith(".") else hostname
        labels = dns_name.split(".")
        if (
            not dns_name
            or len(dns_name) > 253
            or any(
                not (1 <= len(label) <= 63)
                or not label[0].isalnum()
                or not label[-1].isalnum()
                or any(not character.isalnum() and character != "-" for character in label)
                for label in labels
            )
        ):
            return ""
        serialized_host = hostname.lower()
    else:
        serialized_host = (
            f"[{address.compressed}]" if address.version == 6 else address.compressed
        )

    if port is not None:
        serialized_host += f":{port}"
    websocket_scheme = "wss" if scheme == "https" else "ws"
    return f"{websocket_scheme}://{serialized_host}"


def _validate_transition_timeout_hierarchy(app: Flask) -> None:
    bff_timeout = float(app.config["API_TRANSITION_TIMEOUT_SECONDS"])
    worker_timeout = float(app.config["GUNICORN_WORKER_TIMEOUT_SECONDS"])
    for name, value in (
        ("API_TRANSITION_TIMEOUT_SECONDS", bff_timeout),
        ("GUNICORN_WORKER_TIMEOUT_SECONDS", worker_timeout),
    ):
        if not math.isfinite(value) or value <= 0:
            raise RuntimeError(f"{name} must be a positive finite number")

    minimum_bff_timeout = (
        TRANSITION_API_MAX_SECONDS + TRANSITION_TIMEOUT_HEADROOM_SECONDS
    )
    if bff_timeout < minimum_bff_timeout:
        raise RuntimeError(
            "API_TRANSITION_TIMEOUT_SECONDS must be at least "
            f"{minimum_bff_timeout:g} seconds: the Rust API can use "
            f"{TRANSITION_API_MAX_SECONDS:g} seconds and requires "
            f"{TRANSITION_TIMEOUT_HEADROOM_SECONDS:g} seconds of proxy headroom"
        )

    minimum_worker_timeout = bff_timeout + TRANSITION_TIMEOUT_HEADROOM_SECONDS
    if worker_timeout < minimum_worker_timeout:
        raise RuntimeError(
            "GUNICORN_WORKER_TIMEOUT_SECONDS must be at least "
            f"{minimum_worker_timeout:g} seconds: it must exceed the transition "
            f"BFF timeout by {TRANSITION_TIMEOUT_HEADROOM_SECONDS:g} seconds"
        )


__all__ = ["create_app"]
