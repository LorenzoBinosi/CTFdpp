"""CTFZone's replaceable Python web frontend.

The package deliberately has no database dependency. It renders the browser
experience and talks to the Rust API over HTTP.
"""

from __future__ import annotations

import os
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlsplit

from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix

from .api import ApiClient
from .frontends import FrontendRegistry, assets
from .views import web


def create_app(test_config: dict | None = None) -> Flask:
    # Frontend files are served only through the explicitly isolated asset
    # routes below.  Disabling Flask's implicit /static route prevents a player
    # frontend from accidentally reaching administration assets (and vice
    # versa) through a legacy shared directory.
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
        connect_sources = "'self'"
        if app.config["OBJECT_STORAGE_ORIGIN"]:
            connect_sources += " " + app.config["OBJECT_STORAGE_ORIGIN"]
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self'; "
            f"script-src 'self'; connect-src {connect_sources}; frame-ancestors 'self'; "
            "form-action 'self'; base-uri 'self'",
        )
        if response.mimetype == "text/html":
            response.headers["Cache-Control"] = "private, no-store"
        return response

    return app


__all__ = ["create_app"]
