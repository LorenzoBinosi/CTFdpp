"""CTFZone's replaceable Python web frontend.

The package deliberately has no database dependency. It renders the browser
experience and talks to the Rust API over HTTP.
"""

from __future__ import annotations

import os

from flask import Flask

from .api import ApiClient
from .views import web


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__, static_folder="static", template_folder="templates")
    app.config.from_mapping(
        API_BASE_URL=os.getenv("API_BASE_URL", "http://api:8080"),
        API_TIMEOUT_SECONDS=float(os.getenv("API_TIMEOUT_SECONDS", "5")),
        MAX_CONTENT_LENGTH=int(os.getenv("MAX_PROXY_BODY_BYTES", str(16 * 1024 * 1024))),
        # Assets use stable names in this no-build frontend, so keep their cache
        # short and rely on ETags instead of trapping browsers on an old bundle.
        SEND_FILE_MAX_AGE_DEFAULT=3600,
    )
    if test_config:
        app.config.update(test_config)

    app.extensions["ctfzone_api"] = app.config.get("API_CLIENT") or ApiClient(
        app.config["API_BASE_URL"], app.config["API_TIMEOUT_SECONDS"]
    )
    app.register_blueprint(web)

    @app.after_request
    def secure_response(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self'; "
            "script-src 'self'; connect-src 'self'; frame-ancestors 'self'; "
            "form-action 'self'; base-uri 'self'",
        )
        if response.mimetype == "text/html":
            response.headers["Cache-Control"] = "private, no-store"
        return response

    return app


__all__ = ["create_app"]
