"""HTML routes and the constrained browser-to-API proxy."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import secrets
import unicodedata
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlencode, urlsplit
from uuid import UUID

from flask import (
    Blueprint,
    Response,
    abort,
    current_app,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from .api import ApiClient, ApiUnavailable
from .frontends import FrontendRegistry
from .markdown import render_html, render_markdown

web = Blueprint("web", __name__)

_CSRF_SESSION_KEY = "csrf_token"
_RUST_SESSION_KEY = "rust_session_id"
_PLAYER_FRONTEND_SESSION_KEY = "player_frontend"
_SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}
_REGISTRATION_ACCESS_MODES = {
    "open",
    "domain_rules",
    "access_code",
    "email_allowlist",
}
_RESPONSE_HEADERS = (
    "cache-control",
    "content-disposition",
    "content-language",
    "content-range",
    "content-type",
    "etag",
    "last-modified",
    "location",
    "retry-after",
)

_AUTH_ERRORS = {
    "invalid_credentials": "The username, email, or password is incorrect.",
    "account_disabled": "This account is disabled.",
    "password_change_required": "A password change is required before signing in.",
    "external_account": "This account uses an external authentication provider.",
    "invalid_input": "Please check the information you entered.",
    "password_too_short": "The password does not meet the minimum length.",
    "identity_taken": "That username or email address is already registered.",
    "email_not_allowed": "That email address is not allowed for this event.",
    "invalid_registration_code": "The registration code is not valid.",
    "user_limit_reached": "Registration has reached its participant limit.",
    "setup_complete": "CTFZone has already been configured.",
    "setup_failed": "CTFZone could not complete initial setup.",
    "unknown_player_frontend": "Select an installed player frontend.",
}

_MISSING = object()

def _api() -> ApiClient:
    return current_app.extensions["ctfzone_api"]


def _frontends() -> FrontendRegistry:
    return current_app.extensions["ctfzone_frontends"]


def _session_id() -> str | None:
    # Flask signs this HttpOnly cookie value. The opaque UUID is not a standalone
    # Rust credential: the private API also requires BACKEND_SERVICE_TOKEN, which
    # is injected only by ApiClient and never returned to the browser.
    value = session.get(_RUST_SESSION_KEY)
    return value if isinstance(value, str) and value else None


def _csrf_token(*, rotate: bool = False) -> str:
    value = session.get(_CSRF_SESSION_KEY)
    if rotate or not isinstance(value, str) or len(value) < 32:
        value = secrets.token_urlsafe(32)
        session[_CSRF_SESSION_KEY] = value
    return value


def _clear_session() -> None:
    session.clear()


def _origin_key(value: str) -> tuple[str, str, int] | None:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return None
    scheme = parsed.scheme.casefold()
    hostname = (parsed.hostname or "").casefold()
    if (
        scheme not in {"http", "https"}
        or not hostname
        or parsed.username
        or parsed.password
    ):
        return None
    return scheme, hostname, port or (443 if scheme == "https" else 80)


def _csrf_failure(message: str) -> tuple[Response, int]:
    if request.path.startswith("/bff/"):
        return jsonify({"success": False, "message": message}), 403
    return Response(message, status=403, content_type="text/plain"), 403


@web.before_request
def protect_browser_boundary() -> tuple[Response, int] | None:
    if request.method in _SAFE_METHODS:
        return None

    fetch_site = request.headers.get("Sec-Fetch-Site")
    if fetch_site and fetch_site.casefold() != "same-origin":
        return _csrf_failure("Cross-origin request rejected")
    source = request.headers.get("Origin") or request.headers.get("Referer")
    if not source or _origin_key(source) != _origin_key(request.url_root):
        return _csrf_failure("A same-origin request is required")

    expected = session.get(_CSRF_SESSION_KEY)
    supplied = request.headers.get("csrf-token")
    if (
        not supplied
        and not request.path.startswith("/bff/")
        and request.mimetype in {
            "application/x-www-form-urlencoded",
            "multipart/form-data",
        }
    ):
        # Preserve the original bytes for the subsequent trusted API call.
        request.get_data(cache=True)
        supplied = request.form.get("_csrf_token")
    if (
        not isinstance(expected, str)
        or not isinstance(supplied, str)
        or not hmac.compare_digest(expected, supplied)
    ):
        return _csrf_failure("Invalid CSRF token")
    return None


def _read_data(path: str, default: Any = None) -> tuple[int, Any]:
    try:
        status, payload = _api().get_json(path, request, session_id=_session_id())
    except ApiUnavailable:
        return 503, default
    if status == 401:
        _clear_session()
    return status, ApiClient.unwrap(payload, default)


def _safe_page_endpoint(value: Any) -> str | None:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 128:
        return None
    if value != value.casefold() or value.startswith("/") or value.endswith("/"):
        return None
    segments = value.split("/")
    if any(
        not segment
        or not segment[0].isascii()
        or not segment[0].isalnum()
        or any(not (character.isascii() and (character.isalnum() or character in "_-")) for character in segment)
        for segment in segments
    ):
        return None
    return value


def _normalize_navigation(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    navigation: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in value:
        if not isinstance(raw, dict):
            continue
        endpoint = _safe_page_endpoint(raw.get("endpoint"))
        label = raw.get("label")
        page_id = raw.get("id")
        if (
            endpoint is None
            or endpoint in seen
            or not isinstance(label, str)
            or not label.strip()
            or len(label.encode("utf-8")) > 80
            or any(unicodedata.category(character).startswith("C") for character in label)
            or not isinstance(page_id, int)
            or isinstance(page_id, bool)
            or page_id < 1
        ):
            continue
        system_key = raw.get("system_key")
        if system_key not in {None, "challenges", "scoreboard"}:
            continue
        seen.add(endpoint)
        navigation.append(
            {
                "id": page_id,
                "label": label.strip(),
                "endpoint": endpoint,
                "href": f"/{endpoint}",
                "system_key": system_key,
            }
        )
    return navigation


def _normalize_admin_page(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    page_id = value.get("id")
    label = value.get("label")
    endpoint = value.get("endpoint")
    content = value.get("content")
    page_type = value.get("page_type")
    system_key = value.get("system_key")
    visibility = value.get("visibility")
    navigation_order = value.get("navigation_order")
    revision = value.get("revision")
    endpoint_valid = endpoint == "" if page_type == "home" else _safe_page_endpoint(endpoint) == endpoint
    if (
        not isinstance(page_id, int)
        or isinstance(page_id, bool)
        or page_id < 1
        or not isinstance(label, str)
        or not label.strip()
        or len(label.encode("utf-8")) > 80
        or not endpoint_valid
        or not isinstance(content, str)
        or len(content.encode("utf-8")) > 262_144
        or page_type not in {"home", "system", "custom"}
        or system_key not in {None, "home", "challenges", "scoreboard"}
        or visibility not in {"public", "private", "invisible"}
        or not isinstance(navigation_order, int)
        or isinstance(navigation_order, bool)
        or not 0 <= navigation_order <= 10_000
        or not isinstance(revision, int)
        or isinstance(revision, bool)
        or revision < 1
    ):
        return None
    return {
        "id": page_id,
        "label": label.strip(),
        "endpoint": endpoint,
        "href": "/" if endpoint == "" else f"/{endpoint}",
        "content": content,
        "page_type": page_type,
        "system_key": system_key,
        "visibility": visibility,
        "navigation_order": navigation_order,
        "revision": revision,
    }


def _normalize_bootstrap(data: Any, status: int = 200) -> dict[str, Any]:
    if status >= 500 or not isinstance(data, dict):
        data = {}

    site = data.get("site") if isinstance(data.get("site"), dict) else {}
    player_frontend = _frontends().resolve(site.get("player_frontend"))
    registration_access_mode = site.get("registration_access_mode")
    if (
        not isinstance(registration_access_mode, str)
        or registration_access_mode not in _REGISTRATION_ACCESS_MODES
    ):
        registration_access_mode = "open"
    site = {
        "name": site.get("name") or "CTFZone",
        "description": site.get("description") or "Capture the flag. Own the zone.",
        "user_mode": "teams" if site.get("user_mode") == "teams" else "users",
        # Invalid or missing policy metadata must not expose a create action
        # that the participant endpoint may reject.
        "team_creation": site.get("team_creation") is True,
        "team_size": site.get("team_size")
        if isinstance(site.get("team_size"), int)
        and not isinstance(site.get("team_size"), bool)
        and site.get("team_size") >= 0
        else 0,
        "num_teams": site.get("num_teams")
        if isinstance(site.get("num_teams"), int)
        and not isinstance(site.get("num_teams"), bool)
        and site.get("num_teams") >= 0
        else 0,
        "start": site.get("start"),
        "end": site.get("end"),
        "paused": bool(site.get("paused", False)),
        "challenge_visibility": site.get("challenge_visibility") or "private",
        "score_visibility": site.get("score_visibility") or "public",
        "account_visibility": site.get("account_visibility") or "public",
        "registration_visibility": site.get("registration_visibility") or "public",
        "registration_access_mode": registration_access_mode,
        # Only a registry result is retained. A stale or hostile database value
        # can therefore never become part of a template or filesystem path.
        "player_frontend": player_frontend.identifier,
    }
    # Challenge fragments intentionally make one API request and do not fetch a
    # second bootstrap document. Remember the already validated selection in
    # the signed browser session so those fragments use the surrounding page's
    # frontend. Direct fragment requests safely fall back to the default.
    if session.get(_PLAYER_FRONTEND_SESSION_KEY) != player_frontend.identifier:
        session[_PLAYER_FRONTEND_SESSION_KEY] = player_frontend.identifier
    user = data.get("user") if isinstance(data.get("user"), dict) else None
    authenticated = bool(data.get("authenticated") and user and _session_id())
    navigation = _normalize_navigation(data.get("navigation"))

    return {
        "available": status < 500,
        "setup_required": bool(data.get("setup_required", False)),
        "authenticated": authenticated,
        "csrf_token": _csrf_token(),
        "user": user,
        "site": site,
        "navigation": navigation,
    }


def _bootstrap() -> dict[str, Any]:
    status, data = _read_data("/api/v1/bootstrap", {})
    return _normalize_bootstrap(data, status)


def _context_from_bootstrap(
    page: str, bootstrap: dict[str, Any], **extra: Any
) -> dict[str, Any]:
    return {
        "page": page,
        "page_endpoint": page,
        "bootstrap": bootstrap,
        "site": bootstrap["site"],
        "user": bootstrap["user"],
        "navigation": bootstrap["navigation"],
        "csrf_token": bootstrap["csrf_token"],
        "storage_origin": current_app.config["OBJECT_STORAGE_ORIGIN"],
        **extra,
    }


def _page_context(page: str, **extra: Any) -> dict[str, Any]:
    return _context_from_bootstrap(page, _bootstrap(), **extra)


def _render_player(
    template: str, *, frontend_id: Any = None, **context: Any
) -> str:
    site = context.get("site") if isinstance(context.get("site"), dict) else {}
    requested = frontend_id or site.get("player_frontend") or session.get(
        _PLAYER_FRONTEND_SESSION_KEY
    )
    frontend = _frontends().resolve(requested)

    def player_template(name: str) -> str:
        return _frontends().template_name(frontend, name)

    def player_asset(name: str) -> str:
        return url_for(
            "frontend_assets.player_asset",
            frontend_id=frontend.identifier,
            filename=name,
            v=_frontends().asset_version,
        )

    return render_template(
        _frontends().template_name(frontend, template),
        **context,
        player_frontend_manifest=frontend.public_manifest(),
        player_template=player_template,
        player_asset=player_asset,
    )


def _error_message() -> str | None:
    code = request.args.get("ctfzone_error") or request.args.get("error")
    if not code:
        return None
    return _AUTH_ERRORS.get(code, code.replace("_", " ").capitalize())


def _copy_upstream(response: Any) -> Response:
    outgoing = Response(response.content, status=response.status_code)
    for name in _RESPONSE_HEADERS:
        value = response.headers.get(name)
        if value is not None:
            outgoing.headers[name] = value
    return outgoing


def _proxy(path: str) -> Response:
    storage_completion = path.startswith("/api/v1/storage/objects/") and path.endswith(
        "/complete"
    )
    email_delivery = (
        request.method == "POST"
        and path == "/api/v1/users/me/verification-email"
    )
    mode_transition = (
        request.method == "POST"
        and path == "/api/v1/configs/user-mode-transition"
    ) or (
        request.method == "GET"
        and path == "/api/v1/views/admin/user-mode-transition"
    )
    timeout_seconds = None
    if storage_completion:
        timeout_seconds = current_app.config["API_STORAGE_TIMEOUT_SECONDS"]
    elif email_delivery:
        timeout_seconds = current_app.config["API_EMAIL_TIMEOUT_SECONDS"]
    elif mode_transition:
        timeout_seconds = current_app.config["API_TRANSITION_TIMEOUT_SECONDS"]
    try:
        if timeout_seconds is None:
            upstream = _api().request_from_browser(
                request, path, session_id=_session_id()
            )
        else:
            upstream = _api().request_from_browser(
                request,
                path,
                session_id=_session_id(),
                timeout_seconds=timeout_seconds,
            )
    except ApiUnavailable as error:
        return jsonify({"success": False, "message": str(error)}), 502
    if upstream.status_code == 401:
        _clear_session()
    return _copy_upstream(upstream)


def _form_post(path: str, *, query_override: str | None = None) -> Any:
    pairs = [
        (key, value)
        for key, values in request.form.lists()
        if key != "_csrf_token"
        for value in values
    ]
    query = (
        request.query_string.decode("ascii", errors="ignore")
        if query_override is None
        else query_override
    )
    target = f"{path}?{query}" if query else path
    return _api().request(
        "POST",
        target,
        incoming=request,
        session_id=_session_id(),
        content=urlencode(pairs).encode(),
        headers={"content-type": "application/x-www-form-urlencoded"},
    )


def _error_code(payload: Any, fallback: str) -> str:
    if not isinstance(payload, dict):
        return fallback
    error = payload.get("error")
    candidates = (
        payload.get("code"),
        error.get("code") if isinstance(error, dict) else error,
        payload.get("message"),
    )
    for candidate in candidates:
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()[:160]
    return fallback


def _safe_destination(value: Any, fallback: str) -> str:
    if not isinstance(value, str) or not value.startswith("/"):
        return fallback
    parsed = urlsplit(value)
    if (
        parsed.scheme
        or parsed.netloc
        or value.startswith("//")
        or "\\" in value
        or "\r" in value
        or "\n" in value
        or any(unicodedata.category(character) == "Cc" for character in value)
    ):
        return fallback
    return value


def _auth_post(
    path: str,
    failure_endpoint: str,
    fallback: str = "/",
    *,
    destination_override: str | None = None,
) -> Response:
    if path == "/setup":
        selected_frontend = request.form.get("player_frontend")
        if (
            selected_frontend is not None
            and _frontends().get(selected_frontend) is None
        ):
            return redirect(
                url_for(failure_endpoint, error="unknown_player_frontend"), code=303
            )
    try:
        query_override = (
            urlencode({"next": destination_override})
            if destination_override is not None
            else None
        )
        upstream = _form_post(path, query_override=query_override)
    except ApiUnavailable:
        error = "setup_failed" if path == "/setup" else "temporarily_unavailable"
        parameters = {"error": error}
        if destination_override is not None:
            parameters["next"] = destination_override
        return redirect(url_for(failure_endpoint, **parameters), code=303)
    try:
        payload = upstream.json()
    except ValueError:
        payload = {}
    data = ApiClient.unwrap(payload, {})
    session_id = data.get("session_id") if isinstance(data, dict) else None
    if upstream.is_success and isinstance(session_id, str) and session_id:
        destination = destination_override or _safe_destination(
            data.get("redirect"), fallback
        )
        _clear_session()
        session[_RUST_SESSION_KEY] = session_id
        session.permanent = True
        _csrf_token(rotate=True)
        return redirect(destination, code=303)

    if upstream.status_code == 401:
        _clear_session()
    error = _error_code(payload, "setup_failed" if path == "/setup" else "invalid_credentials")
    parameters: dict[str, str] = {"error": error}
    if destination_override is not None:
        parameters["next"] = destination_override
    elif failure_endpoint == "web.login" and request.args.get("next"):
        parameters["next"] = request.args["next"]
    return redirect(url_for(failure_endpoint, **parameters), code=303)


@web.get("/healthz")
def healthz() -> Response:
    return jsonify({"status": "ok", "service": "backend", "mode": "bff"})


@web.get("/")
def index() -> Response | tuple[str, int] | str:
    bootstrap = _bootstrap()
    if bootstrap["setup_required"]:
        return redirect(url_for("web.setup"), code=302)
    return _content_page("/api/v1/pages/root", "", bootstrap=bootstrap)


def _normalize_content_page(value: Any, expected_endpoint: str) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    page_id = value.get("id")
    label = value.get("label")
    endpoint = value.get("endpoint")
    content = value.get("content")
    page_type = value.get("page_type")
    system_key = value.get("system_key")
    if (
        not isinstance(page_id, int)
        or isinstance(page_id, bool)
        or page_id < 1
        or not isinstance(label, str)
        or not label.strip()
        or len(label.encode("utf-8")) > 80
        or any(unicodedata.category(character).startswith("C") for character in label)
        or endpoint != expected_endpoint
        or not isinstance(content, str)
        or len(content.encode("utf-8")) > 262_144
        or "\0" in content
        or page_type not in {"home", "custom"}
        or system_key not in {None, "home"}
    ):
        return None
    return {
        "id": page_id,
        "label": label.strip(),
        "endpoint": endpoint,
        "content_html": render_html(content),
        "page_type": page_type,
    }


def _content_page(
    api_path: str,
    endpoint: str,
    *,
    bootstrap: dict[str, Any] | None = None,
) -> Response | tuple[str, int] | str:
    bootstrap = bootstrap or _bootstrap()
    status, value = _read_data(api_path, None)
    if status == 403 and not bootstrap["authenticated"]:
        return redirect(url_for("web.login", next=request.path), code=302)
    if status in {400, 403, 404}:
        abort(404)
    page_data = _normalize_content_page(value, endpoint) if status < 400 else None
    context = _context_from_bootstrap(endpoint, bootstrap)
    context.update(
        content_page=page_data,
        page_error=(
            "This page is temporarily unavailable."
            if status >= 500 or page_data is None
            else None
        ),
    )
    rendered = _render_player("page.html", **context)
    return (rendered, 503) if context["page_error"] else rendered


@web.route("/login", methods=["GET", "POST"])
def login() -> Response | str:
    if request.method == "POST":
        return _auth_post("/login", "web.login")
    return _render_player(
        "login.html",
        **_page_context("login", error=_error_message(), next=request.args.get("next", "")),
    )


@web.route("/register", methods=["GET", "POST"])
def register() -> Response | str:
    if request.method == "POST":
        return _auth_post("/register", "web.register")
    return _render_player(
        "register.html", **_page_context("register", error=_error_message())
    )


@web.route("/confirm", methods=["GET", "POST"])
def confirm_email() -> Response | str:
    """Confirm an email without allowing the raw token into a request URL.

    Verification links carry the token in the URL fragment. Browsers do not
    send fragments to servers; the selected player frontend moves it into this
    same-origin POST only after removing the fragment from browser history.
    """

    context = _page_context("confirm")
    confirmation_state: str | None = None
    confirmation_message: str | None = None
    if request.method == "POST":
        token = request.form.get("token", "")
        if not token or len(token) > 4096:
            confirmation_state = "error"
            confirmation_message = "This verification link is invalid or incomplete."
        else:
            try:
                upstream = _api().request(
                    "POST",
                    "/api/v1/email-verifications/confirm",
                    incoming=request,
                    # Confirmation is intentionally public. A stale, revoked,
                    # or restricted browser session must not prevent a valid
                    # email bearer token from being consumed.
                    session_id=None,
                    content=json.dumps({"token": token}).encode(),
                    headers={"content-type": "application/json"},
                )
                try:
                    payload = upstream.json()
                except ValueError:
                    payload = {}
                if upstream.is_success:
                    confirmation_state = "success"
                    confirmation_message = (
                        "Your email address is verified. You can now continue to the event."
                    )
                else:
                    confirmation_state = "error"
                    confirmation_message = _response_message(payload, upstream.status_code)
            except ApiUnavailable:
                confirmation_state = "error"
                confirmation_message = (
                    "Verification is temporarily unavailable. Please try again shortly."
                )
    context.update(
        confirmation_state=confirmation_state,
        confirmation_message=confirmation_message,
    )
    return _render_player("confirm.html", **context)


@web.route("/setup", methods=["GET", "POST"])
def setup() -> Response | str:
    if request.method in {"GET", "HEAD"}:
        context = _page_context("setup", error=_error_message())
        context["installed_player_frontends"] = _frontends().public_manifests()
        if not context["bootstrap"]["available"]:
            context["notice"] = (
                "Setup status is temporarily unavailable because the API did not answer."
            )
        elif not context["bootstrap"]["setup_required"]:
            context["notice"] = "Setup is only available on an empty CTFZone installation."
        return render_template(
            "admin/setup.html",
            **context,
            admin_module="setup",
            admin_title="Initial setup",
        )

    return _auth_post("/setup", "web.setup")


@web.post("/logout")
def logout() -> Response:
    current_session = _session_id()
    if current_session:
        try:
            _api().request(
                "POST", "/logout", incoming=request, session_id=current_session
            )
        except ApiUnavailable:
            pass
    _clear_session()
    return redirect(url_for("web.index"), code=303)


def _tag_values(challenge: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for tag in challenge.get("tags") or []:
        value = tag.get("value") if isinstance(tag, dict) else tag
        if value:
            values.append(str(value))
    return values


def _uuid_string(value: Any) -> str | None:
    try:
        return str(UUID(str(value)))
    except (TypeError, ValueError, AttributeError):
        return None


_CATEGORY_LOGO_KEYS = frozenset(
    {"web", "pwn", "crypto", "rev", "misc", "coding", "forensics"}
)


def _category_logo_key(value: Any) -> str | None:
    return value if isinstance(value, str) and value in _CATEGORY_LOGO_KEYS else None


def _category_logo_color(value: Any) -> str | None:
    if not isinstance(value, str) or len(value) != 7 or not value.startswith("#"):
        return None
    try:
        int(value[1:], 16)
    except ValueError:
        return None
    return value.lower()


def _category_icon_url(category_id: Any, object_id: Any) -> str | None:
    normalized_object_id = _uuid_string(object_id)
    if (
        not isinstance(category_id, int)
        or isinstance(category_id, bool)
        or category_id < 1
        or normalized_object_id is None
    ):
        return None
    return url_for(
        "web.category_icon",
        category_id=category_id,
        object_id=normalized_object_id,
    )


def _normalize_categories(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    categories: list[dict[str, Any]] = []
    for raw in value:
        if (
            not isinstance(raw, dict)
            or not isinstance(raw.get("id"), int)
            or isinstance(raw.get("id"), bool)
            or not isinstance(raw.get("name"), str)
        ):
            continue
        name = raw["name"]
        challenge_count = raw.get("challenge_count")
        icon_object_id = _uuid_string(raw.get("icon_object_id"))
        category = dict(raw)
        category.update(
            name=name,
            logo_key=_category_logo_key(raw.get("logo_key")),
            logo_color=_category_logo_color(raw.get("logo_color")),
            icon_object_id=icon_object_id,
            icon_url=_category_icon_url(raw["id"], icon_object_id),
            challenge_count=(
                challenge_count
                if isinstance(challenge_count, int)
                and not isinstance(challenge_count, bool)
                and challenge_count >= 0
                else 0
            ),
        )
        categories.append(category)
    return categories


def _decorate_challenges(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    challenges: list[dict[str, Any]] = []
    for raw in value:
        if not isinstance(raw, dict):
            continue
        challenge = dict(raw)
        tags = _tag_values(challenge)
        tag_keys = {tag.casefold() for tag in tags}
        category = str(challenge.get("category") or "misc")
        category_id = challenge.get("category_id")
        category_key = (
            f"id:{category_id}"
            if isinstance(category_id, int)
            and not isinstance(category_id, bool)
            and category_id > 0
            else f"name:{category.casefold()}"
        )
        difficulty = next(
            (tag for tag in tags if tag.casefold() in {"easy", "medium", "hard", "insane"}),
            None,
        )
        challenge.update(
            category=category,
            category_key=category_key,
            category_logo_key=_category_logo_key(
                challenge.get("category_logo_key")
            ),
            category_logo_color=_category_logo_color(
                challenge.get("category_logo_color")
            ),
            category_icon_object_id=_uuid_string(
                challenge.get("category_icon_object_id")
            ),
            tags=tags,
            tag_keys=" ".join(sorted(tag_keys)),
            difficulty=difficulty,
            runtime_available=bool(challenge.get("runtime_available") or "instance" in tag_keys),
        )
        challenge["category_icon_url"] = _category_icon_url(
            category_id, challenge["category_icon_object_id"]
        )
        challenges.append(challenge)
    return challenges


def _decorate_detail(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    challenge = dict(value)
    challenge["category_logo_key"] = _category_logo_key(
        challenge.get("category_logo_key")
    )
    challenge["category_logo_color"] = _category_logo_color(
        challenge.get("category_logo_color")
    )
    challenge["category_icon_object_id"] = _uuid_string(
        challenge.get("category_icon_object_id")
    )
    challenge["category_icon_url"] = _category_icon_url(
        challenge.get("category_id"), challenge["category_icon_object_id"]
    )
    tags = _tag_values(challenge)
    challenge["tags"] = tags
    challenge["difficulty"] = next(
        (tag for tag in tags if tag.casefold() in {"easy", "medium", "hard", "insane"}),
        None,
    )
    challenge["description_html"] = render_markdown(challenge.get("description"))
    challenge["attribution_html"] = render_markdown(challenge.get("attribution"))

    hints: list[dict[str, Any]] = []
    for raw in challenge.get("hints") or []:
        if isinstance(raw, dict):
            hint = dict(raw)
            hint["content_html"] = render_markdown(hint.get("content"))
            hints.append(hint)
    challenge["hints"] = hints

    files: list[dict[str, str]] = []
    for raw in challenge.get("files") or []:
        if not isinstance(raw, dict):
            continue
        object_id = raw.get("object_id")
        try:
            normalized_id = str(UUID(str(object_id)))
        except (TypeError, ValueError, AttributeError):
            continue
        name = raw.get("filename") or raw.get("name") or "download"
        files.append(
            {
                "name": str(name),
                "url": url_for("web.download_object", object_id=normalized_id),
            }
        )
    challenge["files"] = files
    return challenge


@web.get("/challenges")
def challenges() -> str:
    selected_id = request.args.get("challenge", type=int)
    aggregate_path = "/api/v1/views/challenges"
    if selected_id is not None:
        aggregate_path += "?" + urlencode({"selected": selected_id})
    status, aggregate = _read_data(aggregate_path, {})
    aggregate = aggregate if isinstance(aggregate, dict) else {}
    if 400 <= status < 500:
        # Visibility, event-time, verification, and first-boot policy may
        # legitimately deny the challenge list. Preserve the independent site
        # shell/setup state instead of turning an expected section denial into
        # an empty, anonymous-looking page. The fallback costs one extra
        # internal request only on this denied path.
        bootstrap_status, bootstrap_data = _read_data("/api/v1/bootstrap", {})
        bootstrap = _normalize_bootstrap(bootstrap_data, bootstrap_status)
        aggregate = {}
    else:
        bootstrap = _normalize_bootstrap(aggregate.get("bootstrap"), status)
    if status in {401, 403} and not bootstrap.get("setup_required"):
        visibility = bootstrap.get("site", {}).get("challenge_visibility")
        if visibility == "private" and not bootstrap.get("authenticated"):
            return redirect(url_for("web.login", next=request.full_path.rstrip("?")))
        abort(404)
    context = _context_from_bootstrap("challenges", bootstrap)
    challenge_list = _decorate_challenges(aggregate.get("challenges", []))
    selected = _decorate_detail(aggregate.get("selected"))
    if selected is not None:
        selected_id = int(selected["id"])
    panel_error = (
        "Challenge details are temporarily unavailable."
        if selected_id is not None and selected is None and status >= 500
        else None
    )

    category_index: dict[str, dict[str, Any]] = {}
    for challenge in challenge_list:
        key = challenge["category_key"]
        category = category_index.setdefault(
            key,
            {
                "key": key,
                "name": challenge["category"],
                "count": 0,
                "logo_key": challenge["category_logo_key"],
                "logo_color": challenge["category_logo_color"],
                "icon_object_id": challenge["category_icon_object_id"],
                "icon_url": challenge["category_icon_url"],
            },
        )
        category["count"] += 1
    categories = sorted(
        category_index.values(), key=lambda category: category["name"].casefold()
    )
    context.update(
        challenges=challenge_list,
        categories=categories,
        selected=selected,
        selected_id=selected_id,
        panel_error=panel_error,
        api_error=status >= 500,
    )
    return _render_player("challenges.html", **context)


@web.get("/bff/fragments/challenges/<int:challenge_id>")
def challenge_fragment(challenge_id: int) -> tuple[str, int] | str:
    frontend_id = request.args.get("frontend")
    if frontend_id is not None and _frontends().get(frontend_id) is None:
        abort(404)
    status, detail = _read_data(f"/api/v1/challenges/{challenge_id}", {})
    challenge = _decorate_detail(detail) if status < 400 else None
    authenticated = bool(_session_id())
    bootstrap = {"authenticated": authenticated}
    html = _render_player(
        "partials/challenge_panel.html",
        frontend_id=frontend_id,
        challenge=challenge,
        bootstrap=bootstrap,
        user={} if authenticated else None,
        fragment_error=None if challenge else _response_message(detail, status),
    )
    return (html, status) if status >= 400 else html


def _response_message(payload: Any, status: int) -> str:
    if isinstance(payload, dict) and payload.get("message"):
        return str(payload["message"])
    if status == 401:
        return "Your session has expired. Please sign in again."
    if status == 403:
        return "This challenge is not available to your account."
    if status == 404:
        return "Challenge not found."
    return "Challenge details are temporarily unavailable."


@web.get("/scoreboard")
def scoreboard() -> str:
    context = _page_context("scoreboard")
    status, standings = _read_data("/api/v1/scoreboard", [])
    if status in {401, 403} and not context["bootstrap"].get("setup_required"):
        bootstrap = context["bootstrap"]
        visibility = bootstrap.get("site", {}).get("score_visibility")
        if visibility == "private" and not bootstrap.get("authenticated"):
            return redirect(url_for("web.login", next=request.path))
        abort(404)
    context.update(standings=standings if isinstance(standings, list) else [], api_error=status >= 500)
    return _render_player("scoreboard.html", **context)


@web.get("/team")
def team() -> str:
    context = _page_context("team")
    team_data: dict[str, Any] | None = None
    team_error: str | None = None
    user = context.get("user") if isinstance(context.get("user"), dict) else {}
    if (
        context["bootstrap"]["authenticated"]
        and context["site"]["user_mode"] == "teams"
        and user.get("type") != "admin"
        and user.get("team_id") is not None
    ):
        status, value = _read_data("/api/v1/teams/me", {})
        if status < 400 and isinstance(value, dict):
            team_data = value
        else:
            team_error = (
                "Your session has expired. Please sign in again."
                if status == 401
                else "Team details are temporarily unavailable. Please try again."
            )
    context.update(team=team_data, team_error=team_error)
    return _render_player("team.html", **context)


def _public_profile(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    profile = dict(value)
    website = str(profile.get("website") or "").strip()
    parsed = urlsplit(website)
    profile["website_url"] = (
        website if parsed.scheme in {"http", "https"} and parsed.netloc else None
    )
    profile["fields"] = [
        field for field in profile.get("fields") or [] if isinstance(field, dict)
    ]
    profile["members"] = [
        member for member in profile.get("members") or [] if isinstance(member, dict)
    ]
    return profile


@web.get("/profile")
def profile_alias() -> Response | tuple[str, int] | str:
    """Render the signed-in account's private profile in every user mode."""

    context = _page_context("profile")
    if not context["bootstrap"]["authenticated"] or not context["user"]:
        return redirect(url_for("web.login", next=url_for("web.profile_alias")), code=302)

    status, value = _read_data("/api/v1/users/me", {})
    if status == 401:
        return redirect(url_for("web.login", next=url_for("web.profile_alias")), code=302)
    profile = _public_profile(value) if status < 400 else None
    if profile is not None:
        # Bootstrap owns authentication-sensitive account state. In particular,
        # its score follows the configured participant mode, while /users/me
        # supplies the private profile fields rendered below.
        for key in ("id", "name", "email", "verified", "type", "team_id", "score", "place"):
            if key in context["user"]:
                profile[key] = context["user"][key]
    context.update(
        profile=profile,
        profile_kind="user",
        profile_is_self=True,
        profile_error=(
            "Your profile is temporarily unavailable."
            if status >= 500
            else "Your profile is unavailable."
            if status >= 400
            else None
        ),
    )
    rendered = _render_player("profile.html", **context)
    return (rendered, status) if status >= 400 else rendered


def _profile_page(kind: str, account_id: int) -> Response | tuple[str, int] | str:
    context = _page_context("profile")
    status, value = _read_data(f"/api/v1/{kind}s/{account_id}", {})
    if status == 401:
        return redirect(url_for("web.login", next=request.path), code=302)
    profile = _public_profile(value) if status < 400 else None
    context.update(
        profile=profile,
        profile_kind=kind,
        profile_is_self=False,
        profile_error=(
            "This profile is not visible to your account."
            if status == 403
            else "This profile does not exist."
            if status == 404
            else "Profile data is temporarily unavailable."
            if status >= 500
            else "This profile is unavailable."
            if status >= 400
            else None
        ),
    )
    rendered = _render_player("profile.html", **context)
    return (rendered, status) if status >= 400 else rendered


@web.get("/users/<int:user_id>")
def user_profile(user_id: int) -> Response | tuple[str, int] | str:
    return _profile_page("user", user_id)


@web.get("/teams/<int:team_id>")
def team_profile(team_id: int) -> Response | tuple[str, int] | str:
    return _profile_page("team", team_id)


@web.get("/<path:endpoint>")
def custom_page(endpoint: str) -> Response | tuple[str, int] | str:
    endpoint = _safe_page_endpoint(endpoint)
    if endpoint is None:
        abort(404)
    return _content_page(
        f"/api/v1/pages/by-route/{endpoint}",
        endpoint,
    )


def _admin_context(module: str, title: str) -> tuple[dict[str, Any] | None, Response | tuple[str, int] | None]:
    context = _page_context("admin")
    context.update(admin_module=module, admin_title=title)
    if not context["bootstrap"]["authenticated"]:
        return None, redirect(url_for("web.login"), code=302)
    if not context["user"] or context["user"].get("type") != "admin":
        return None, (
            render_template(
                "admin/forbidden.html",
                **context,
                message="Administrator access is required for this area.",
            ),
            403,
        )
    return context, None


def _admin_read(path: str, default: Any) -> tuple[Any, bool]:
    status, value = _read_data(path, default)
    return value, status >= 400


def _admin_paginated_read(
    path: str, *, page: int, per_page: int
) -> tuple[list[Any], dict[str, int | None], bool]:
    """Read one collection response while retaining its pagination metadata."""

    try:
        status, payload = _api().get_json(path, request, session_id=_session_id())
    except ApiUnavailable:
        return [], {"page": page, "pages": 0, "per_page": per_page, "total": 0, "prev": None, "next": None}, True
    if status == 401:
        _clear_session()
    data = ApiClient.unwrap(payload, [])
    items = data if isinstance(data, list) else []
    raw_meta = payload.get("meta") if isinstance(payload, dict) else None
    raw_pagination = raw_meta.get("pagination") if isinstance(raw_meta, dict) else None
    pagination = raw_pagination if isinstance(raw_pagination, dict) else {}

    def integer(name: str, fallback: int, minimum: int = 0) -> int:
        value = pagination.get(name)
        return value if isinstance(value, int) and not isinstance(value, bool) and value >= minimum else fallback

    current_page = integer("page", page, 1)
    pages = integer("pages", 1 if items else 0)
    total = integer("total", len(items))
    effective_per_page = integer("per_page", per_page, 1)
    api_prev = pagination.get("prev")
    api_next = pagination.get("next")
    normalized = {
        "page": current_page,
        "pages": pages,
        "per_page": effective_per_page,
        "total": total,
        "prev": api_prev
        if isinstance(api_prev, int) and not isinstance(api_prev, bool) and api_prev > 0
        else (current_page - 1 if current_page > 1 else None),
        "next": api_next
        if isinstance(api_next, int) and not isinstance(api_next, bool) and api_next > current_page
        else (current_page + 1 if pages and current_page < pages else None),
    }
    return items, normalized, status >= 400


_CONFIG_FIELD_TYPES = {
    "boolean",
    "datetime",
    "integer",
    "json",
    "number",
    "secret",
    "select",
    "string",
    "text",
}


def _configuration_value(setting: dict[str, Any]) -> Any:
    """Return the typed effective value without ever exposing a secret."""

    if setting.get("sensitive") or setting.get("type") == "secret":
        return None
    # The API's effective value is authoritative for controls: ``value`` may be
    # null when the row is absent even though a typed default is active.
    for name in ("effective", "value", "default"):
        if name in setting and setting[name] is not None:
            return setting[name]
    return None


def _configuration_input_value(value: Any, field_type: str) -> str:
    if value is None or value == "":
        return ""
    if field_type == "boolean":
        if isinstance(value, str):
            return "true" if value.strip().casefold() in {"1", "true", "yes", "on"} else "false"
        return "true" if bool(value) else "false"
    if field_type == "datetime":
        try:
            timestamp = float(value)
            if timestamp <= 0:
                return ""
            return datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime(
                "%Y-%m-%dT%H:%M"
            )
        except (OverflowError, TypeError, ValueError):
            return ""
    if field_type == "json":
        import json

        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return str(value)


def _configuration_dependency(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict) or not isinstance(value.get("key"), str):
        return None
    expected = value.get("values")
    if not isinstance(expected, list):
        expected = [value.get("value", value.get("equals"))]
    expected = [item for item in expected if item is not None]
    if not expected:
        return None
    return {
        "key": value["key"],
        "values": expected,
        "negate": bool(value.get("negate", False)),
    }


def _configuration_group(value: Any) -> dict[str, str] | None:
    """Normalize optional API-owned presentation groups without inventing taxonomy."""

    if not isinstance(value, dict):
        return None
    identifier = value.get("id")
    if not isinstance(identifier, str) or not identifier:
        return None
    return {
        "id": identifier,
        "title": str(value.get("title") or identifier.replace("_", " ").title()),
        "description": str(value.get("description") or ""),
    }


def _normalize_configuration_catalog(value: Any) -> dict[str, Any]:
    """Make the API-owned catalog safe and convenient for the admin template."""

    catalog = value if isinstance(value, dict) else {}
    sections: list[dict[str, Any]] = []
    raw_sections = catalog.get("sections")
    if not isinstance(raw_sections, list):
        raw_sections = []
    installed_frontends = _frontends().public_manifests()
    frontend_options = [
        {
            "value": frontend["id"],
            "label": (
                f"{frontend['name']} ({frontend['version']})"
                if frontend.get("version")
                else frontend["name"]
            ),
        }
        for frontend in installed_frontends
    ]
    seen_keys: set[str] = set()
    for section_index, raw_section in enumerate(raw_sections):
        if not isinstance(raw_section, dict):
            continue
        groups: list[dict[str, Any]] = []
        group_indexes: dict[str, int] = {}
        raw_groups = raw_section.get("groups")
        if not isinstance(raw_groups, list):
            raw_groups = []
        for raw_group in raw_groups:
            group = _configuration_group(raw_group)
            if group and group["id"] not in group_indexes:
                group_indexes[group["id"]] = len(groups)
                groups.append({**group, "settings": [], "depends_on": None})
        settings: list[dict[str, Any]] = []
        raw_settings = raw_section.get("settings")
        if not isinstance(raw_settings, list):
            raw_settings = []
        for raw_setting in raw_settings:
            if not isinstance(raw_setting, dict):
                continue
            key = raw_setting.get("key")
            if not isinstance(key, str) or not key or key in seen_keys:
                continue
            seen_keys.add(key)
            field_type = str(raw_setting.get("type") or "string").casefold()
            if raw_setting.get("sensitive"):
                field_type = "secret"
            if field_type not in _CONFIG_FIELD_TYPES:
                field_type = "string"
            options = raw_setting.get("options")
            if key == "player_frontend":
                options = frontend_options
                field_type = "select"
            elif key == "user_mode" and not isinstance(options, list):
                options = [
                    {"value": "users", "label": "Individual users"},
                    {"value": "teams", "label": "Teams"},
                ]
                field_type = "select"
            normalized_options: list[dict[str, str]] = []
            if isinstance(options, list):
                for option in options:
                    if isinstance(option, dict) and "value" in option:
                        option_value = option["value"]
                        normalized_options.append(
                            {
                                "value": str(option_value),
                                "label": str(option.get("label", option_value)),
                            }
                        )
            typed_value = _configuration_value(raw_setting)
            read_only = bool(raw_setting.get("read_only"))
            warning = raw_setting.get("warning")
            if key == "verify_emails" and not warning:
                warning = (
                    "When enabled, unverified participants must confirm their email. "
                    "Every signed-in account can request its verification link from Profile."
                )
            danger = raw_setting.get("danger")
            if key == "user_mode" and not danger:
                danger = (
                    "Switching account mode requires a destructive transition that clears "
                    "competition history. The exact impact is previewed before confirmation."
                )
            if key == "player_frontend":
                requested_frontend = typed_value
                typed_value = _frontends().resolve(requested_frontend).identifier
                if requested_frontend != typed_value and not warning:
                    warning = (
                        f"The configured frontend {requested_frontend!s} is not installed; "
                        f"{typed_value} is active as the safe fallback."
                    )
            setting = {
                    "key": key,
                    "label": str(raw_setting.get("label") or key.replace("_", " ").title()),
                    "help": str(raw_setting.get("help") or ""),
                    "type": field_type,
                    "value": typed_value,
                    "input_value": _configuration_input_value(typed_value, field_type),
                    "options": normalized_options,
                    "required": bool(raw_setting.get("required")),
                    "read_only": read_only,
                    "configured": bool(raw_setting.get("configured")),
                    "warning": str(warning) if warning else None,
                    "danger": str(danger) if danger else None,
                    "depends_on": _configuration_dependency(raw_setting.get("depends_on")),
                    "force_dirty": key == "player_frontend"
                    and requested_frontend != typed_value,
                }
            settings.append(setting)
            group = _configuration_group(raw_setting.get("group"))
            if group:
                group_index = group_indexes.get(group["id"])
                if group_index is None:
                    group_index = len(groups)
                    group_indexes[group["id"]] = group_index
                    groups.append({**group, "settings": [], "depends_on": None})
                groups[group_index]["settings"].append(setting)
        for group in groups:
            dependencies = [setting["depends_on"] for setting in group["settings"]]
            if dependencies and dependencies[0] is not None and all(
                dependency == dependencies[0] for dependency in dependencies
            ):
                group["depends_on"] = dependencies[0]
        if not settings:
            continue
        identifier = raw_section.get("id")
        if not isinstance(identifier, str) or not identifier:
            identifier = f"section-{section_index + 1}"
        sections.append(
            {
                "id": identifier,
                "title": str(raw_section.get("title") or identifier.replace("_", " ").title()),
                "description": str(raw_section.get("description") or ""),
                "settings": settings,
                "groups": groups,
                "ungrouped_settings": [
                    setting
                    for setting in settings
                    if not any(setting in group["settings"] for group in groups)
                ],
            }
        )
    registration_emails = catalog.get("registration_emails")
    if not isinstance(registration_emails, list):
        registration_emails = []
    registration_emails = [
        entry
        for entry in registration_emails
        if isinstance(entry, dict)
        and isinstance(entry.get("id"), int)
        and isinstance(entry.get("email"), str)
    ]
    # Treat the internal response as untrusted input and cap it again before
    # rendering. The API applies the same bound before serialization.
    preview_limit = 200
    declared_count = catalog.get("registration_email_count")
    registration_email_count = (
        declared_count
        if isinstance(declared_count, int) and declared_count >= len(registration_emails)
        else len(registration_emails)
    )
    registration_emails_truncated = bool(
        catalog.get("registration_emails_truncated")
        or registration_email_count > preview_limit
        or len(registration_emails) > preview_limit
    )
    return {
        "sections": sections,
        "registration_emails": registration_emails[:preview_limit],
        "registration_email_count": registration_email_count,
        "registration_emails_truncated": registration_emails_truncated,
    }


@web.get("/admin")
def admin_overview() -> Response | tuple[str, int] | str:
    context, gate = _admin_context("overview", "Overview")
    if gate:
        return gate
    status, aggregate = _read_data("/api/v1/views/admin/overview", {})
    if status == 401:
        return redirect(url_for("web.login"), code=302)
    aggregate = aggregate if isinstance(aggregate, dict) else {}
    stats = aggregate.get("stats") if isinstance(aggregate.get("stats"), dict) else {}
    recent = aggregate.get("recent_submissions")
    context.update(
        stats={
            "challenges": stats.get("challenges", 0),
            "users": stats.get("users", 0),
            "teams": stats.get("teams", 0),
        },
        recent_submissions=recent if isinstance(recent, list) else [],
        module_error=status >= 400,
    )
    return render_template("admin/overview.html", **context)


@web.get("/admin/challenges")
def admin_challenges() -> Response | tuple[str, int] | str:
    context, gate = _admin_context("challenges", "Challenges")
    if gate:
        return gate
    data, error = _admin_read("/api/v1/challenges?view=admin", [])
    context.update(challenges=_decorate_challenges(data), module_error=error)
    return render_template("admin/challenges.html", **context)


@web.get("/admin/categories")
def admin_categories() -> Response | tuple[str, int] | str:
    context, gate = _admin_context("categories", "Categories")
    if gate:
        return gate
    data, error = _admin_read("/api/v1/admin/challenge-categories", [])
    context.update(
        categories=_normalize_categories(data),
        module_error=error,
    )
    return render_template("admin/categories.html", **context)


@web.get("/admin/pages")
def admin_pages() -> Response | tuple[str, int] | str:
    context, gate = _admin_context("pages", "Pages")
    if gate:
        return gate
    data, error = _admin_read("/api/v1/pages", [])
    pages = []
    if isinstance(data, list):
        pages = [page for value in data if (page := _normalize_admin_page(value))]
    context.update(pages=pages, module_error=error)
    return render_template("admin/pages.html", **context)


@web.get("/admin/challenges/new")
def admin_challenge_new() -> Response | tuple[str, int] | str:
    context, gate = _admin_context("challenges", "New challenge")
    if gate:
        return gate
    category_data, category_error = _admin_read(
        "/api/v1/admin/challenge-categories", []
    )
    runtime_gate_data, runtime_gate_error = _admin_read(
        "/api/v1/admin/runtime/settings/private-challenges", {}
    )
    context.update(
        challenge=None,
        form_mode="create",
        categories=_normalize_categories(category_data),
        category_error=category_error,
        private_challenge_gate_enabled=bool(
            isinstance(runtime_gate_data, dict)
            and runtime_gate_data.get("enabled") is True
        ),
        private_challenge_gate_error=runtime_gate_error,
        module_error=False,
    )
    return render_template("admin/challenge_form.html", **context)


@web.get("/admin/challenges/<int:challenge_id>")
def admin_challenge_edit(challenge_id: int) -> Response | tuple[str, int] | str:
    context, gate = _admin_context("challenges", "Edit challenge")
    if gate:
        return gate
    data, error = _admin_read(f"/api/v1/challenges/{challenge_id}", {})
    challenge = data if isinstance(data, dict) else None
    if not challenge and not error:
        abort(404)
    category_data, category_error = _admin_read(
        "/api/v1/admin/challenge-categories", []
    )
    runtime_gate_data: Any = {}
    runtime_gate_error = False
    if (
        challenge
        and challenge.get("challenge_type") == "jeopardy"
        and challenge.get("exposure") == "private"
    ):
        runtime_gate_data, runtime_gate_error = _admin_read(
            "/api/v1/admin/runtime/settings/private-challenges", {}
        )
    context.update(
        challenge=challenge,
        form_mode="edit",
        categories=_normalize_categories(category_data),
        category_error=category_error,
        private_challenge_gate_enabled=bool(
            isinstance(runtime_gate_data, dict)
            and runtime_gate_data.get("enabled") is True
        ),
        private_challenge_gate_error=runtime_gate_error,
        module_error=error,
    )
    return render_template("admin/challenge_form.html", **context)


@web.get("/admin/config")
def admin_config() -> Response | tuple[str, int] | str:
    context, gate = _admin_context("config", "Configuration")
    if gate:
        return gate
    data, error = _admin_read("/api/v1/views/admin/configuration", {})
    catalog = _normalize_configuration_catalog(data)
    context.update(
        config_sections=catalog["sections"],
        registration_emails=catalog["registration_emails"],
        registration_email_count=catalog["registration_email_count"],
        registration_emails_truncated=catalog["registration_emails_truncated"],
        module_error=error,
    )
    return render_template("admin/config.html", **context)


def _normalize_ssh_public_key(value: Any) -> str | None:
    """Accept only a canonical, single-line Ed25519 public key."""

    if (
        not isinstance(value, str)
        or not (32 <= len(value) <= 1024)
        or not value.isascii()
    ):
        return None
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        return None
    fields = value.split()
    if len(fields) != 2 or fields[0] != "ssh-ed25519":
        return None
    encoded = fields[1]
    if len(encoded) > 256:
        return None
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        return None
    expected_prefix = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20"
    if len(decoded) != len(expected_prefix) + 32 or not decoded.startswith(expected_prefix):
        return None
    return f"ssh-ed25519 {encoded}"


def _safe_ssh_fingerprint(value: Any) -> str | None:
    """Accept the standard, bounded OpenSSH SHA-256 fingerprint form."""

    if not isinstance(value, str) or not value.startswith("SHA256:"):
        return None
    encoded = value.removeprefix("SHA256:")
    if len(encoded) != 43 or not encoded.isascii():
        return None
    if not all(character.isalnum() or character in "+/" for character in encoded):
        return None
    return value


def _ssh_public_key_fingerprint(public_key: str | None) -> str | None:
    """Derive the OpenSSH SHA-256 fingerprint from a normalized public key."""

    if public_key is None:
        return None
    try:
        decoded = base64.b64decode(public_key.split()[1], validate=True)
    except (binascii.Error, IndexError, ValueError):
        return None
    digest = base64.b64encode(hashlib.sha256(decoded).digest()).decode("ascii")
    return f"SHA256:{digest.rstrip('=')}"


def _safe_ssh_timestamp(value: Any) -> str | None:
    """Keep bounded ISO-like timestamps out of the generic host payload."""

    if (
        not isinstance(value, str)
        or not (20 <= len(value) <= 40)
        or not value.isascii()
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        return None
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return value


def _normalize_ssh_host(value: Any) -> dict[str, Any] | None:
    """Return only validated, public fields for the browser SSH console."""

    if not isinstance(value, dict):
        return None
    try:
        host_id = str(UUID(str(value.get("id"))))
    except (TypeError, ValueError, AttributeError):
        return None

    raw_name = value.get("name")
    name_valid = (
        isinstance(raw_name, str)
        and 1 <= len(raw_name) <= 100
        and raw_name.isascii()
        and not any(ord(character) < 32 or ord(character) == 127 for character in raw_name)
    )
    name = raw_name if name_valid else "invalid"
    raw_hostname = value.get("hostname")
    hostname_valid = (
        isinstance(raw_hostname, str)
        and 1 <= len(raw_hostname) <= 253
        and raw_hostname.isascii()
        and not raw_hostname.startswith("-")
        and all(
            character.isalnum() or character in ".:_-"
            for character in raw_hostname
        )
    )
    hostname = raw_hostname if hostname_valid else "invalid"
    raw_ssh_user = value.get("ssh_user")
    ssh_user_characters = (
        list(raw_ssh_user) if isinstance(raw_ssh_user, str) else []
    )
    ssh_user_valid = (
        isinstance(raw_ssh_user, str)
        and 1 <= len(raw_ssh_user) <= 32
        and raw_ssh_user.isascii()
        and raw_ssh_user not in {"root", "toor"}
        and (raw_ssh_user[0].islower() or raw_ssh_user[0] == "_")
        and all(
            character.islower() or character.isdigit() or character in "_-"
            for character in ssh_user_characters[1:]
        )
    )
    ssh_user = raw_ssh_user if ssh_user_valid else "invalid"
    raw_port = value.get("ssh_port")
    ssh_port_valid = (
        isinstance(raw_port, int)
        and not isinstance(raw_port, bool)
        and 1 <= raw_port <= 65535
    )
    ssh_port = raw_port if ssh_port_valid else 0
    target_valid = (
        name_valid
        and hostname_valid
        and ssh_user_valid
        and ssh_port_valid
        and name == ssh_user
    )

    public_key = _normalize_ssh_public_key(value.get("ssh_public_key"))
    access_key_fingerprint = _safe_ssh_fingerprint(value.get("ssh_key_fingerprint"))
    key_states = {
        "pending": "key_pending",
        "ready": "key_ready",
        "failed": "key_failed",
    }
    key_state = key_states.get(value.get("identity_state"), "unknown")
    raw_key_error = value.get("identity_error_code")
    key_error = None
    if raw_key_error is not None:
        key_error = (
            raw_key_error
            if isinstance(raw_key_error, str)
            and 1 <= len(raw_key_error) <= 64
            and raw_key_error.isascii()
            and all(
                character.islower()
                or character.isdigit()
                or character in "_-"
                for character in raw_key_error
            )
            else "unknown_error"
        )
    raw_authorized_keys_line = value.get("authorized_keys_line")
    authorized_keys_line = (
        raw_authorized_keys_line
        if public_key is not None
        and raw_authorized_keys_line == f"restrict,pty {public_key}"
        else None
    )
    key_ready = (
        key_state == "key_ready"
        and key_error is None
        and public_key is not None
        and access_key_fingerprint is not None
        and access_key_fingerprint == _ssh_public_key_fingerprint(public_key)
        and authorized_keys_line is not None
        and target_valid
    )

    trusted_host_public_key = _normalize_ssh_public_key(
        value.get("trusted_host_public_key")
    )
    trusted_host_key_fingerprint = _safe_ssh_fingerprint(
        value.get("trusted_host_key_fingerprint")
    )
    host_key_states = {
        "untrusted": "untrusted",
        "candidate": "untrusted",
        "trusted": "trusted",
    }
    host_key_state = host_key_states.get(value.get("host_key_state"), "untrusted")
    host_key_trusted = (
        host_key_state == "trusted"
        and trusted_host_public_key is not None
        and trusted_host_key_fingerprint is not None
        and trusted_host_key_fingerprint
        == _ssh_public_key_fingerprint(trusted_host_public_key)
    )

    raw_revision = value.get("revision")
    revision = (
        raw_revision
        if isinstance(raw_revision, int)
        and not isinstance(raw_revision, bool)
        and raw_revision > 0
        else 0
    )
    enabled = value.get("enabled") is True
    connect_ready = key_ready and host_key_trusted and enabled
    return {
        "id": host_id,
        "name": name,
        "hostname": hostname,
        "ssh_port": ssh_port,
        "ssh_user": ssh_user,
        "target_valid": target_valid,
        "key_state": key_state,
        "key_ready": key_ready,
        "ssh_public_key": public_key,
        "authorized_keys_line": authorized_keys_line,
        "ssh_key_fingerprint": access_key_fingerprint,
        "key_error": key_error,
        "host_key_state": host_key_state,
        "host_key_trusted": host_key_trusted,
        "host_key_fingerprint": trusted_host_key_fingerprint,
        "enabled": enabled,
        "connect_ready": connect_ready,
        "authorized_key_cleanup_required": value.get(
            "authorized_key_cleanup_required"
        )
        is True,
        "revision": revision,
        "created_at": _safe_ssh_timestamp(value.get("created_at")),
        "updated_at": _safe_ssh_timestamp(value.get("updated_at")),
    }


@web.get("/admin/machines")
def admin_machines() -> Response | tuple[str, int] | str:
    context, gate = _admin_context("machines", "SSH connections")
    if gate:
        return gate
    values, error = _admin_read("/api/v1/admin/ssh/hosts", [])
    machines = []
    if isinstance(values, list):
        machines = [
            machine
            for value in values
            if (machine := _normalize_ssh_host(value)) is not None
        ]
    context.update(machines=machines, module_error=error)
    return render_template("admin/machines.html", **context)


def _admin_records(
    module: str,
    title: str,
    path: str,
    columns: list[tuple[str, str]],
) -> Response | tuple[str, int] | str:
    context, gate = _admin_context(module, title)
    if gate:
        return gate
    data, error = _admin_read(path, [])
    context.update(
        records=data if isinstance(data, list) else [],
        columns=columns,
        module_error=error,
    )
    return render_template("admin/records.html", **context)


@web.get("/admin/users")
def admin_users() -> Response | tuple[str, int] | str:
    context, gate = _admin_context("users", "Users")
    if gate:
        return gate
    query = request.args.get("q", "").strip()[:254]
    field = request.args.get("field", "name")
    if field not in {"name", "email"}:
        field = "name"
    page = request.args.get("page", default=1, type=int) or 1
    page = min(max(page, 1), 1_000_000)
    per_page = 50
    parameters: list[tuple[str, str]] = [
        ("view", "admin"),
        ("per_page", str(per_page)),
        ("page", str(page)),
    ]
    if query:
        parameters.extend((("q", query), ("field", field)))
    path = "/api/v1/users?" + urlencode(parameters)
    users, pagination, error = _admin_paginated_read(
        path, page=page, per_page=per_page
    )
    context.update(
        users=users,
        user_query=query,
        user_query_field=field,
        pagination=pagination,
        module_error=error,
    )
    return render_template("admin/users.html", **context)


@web.get("/admin/users/<int:user_id>")
def admin_user_edit(user_id: int) -> Response | tuple[str, int] | str:
    context, gate = _admin_context("users", "Edit user")
    if gate:
        return gate
    data, error = _admin_read(f"/api/v1/users/{user_id}?view=admin", {})
    user_record = data if isinstance(data, dict) else None
    if not user_record and not error:
        abort(404)
    context.update(user_record=user_record, module_error=error)
    return render_template("admin/user_form.html", **context)


@web.get("/admin/teams")
def admin_teams() -> Response | tuple[str, int] | str:
    return _admin_records(
        "teams",
        "Teams",
        "/api/v1/teams?view=admin&per_page=100",
        [("id", "ID"), ("name", "Name"), ("email", "Email"), ("captain_id", "Captain"), ("banned", "Banned")],
    )


@web.get("/admin/submissions")
def admin_submissions() -> Response | tuple[str, int] | str:
    return _admin_records(
        "submissions",
        "Submissions",
        "/api/v1/submissions?per_page=100",
        [("id", "ID"), ("challenge_id", "Challenge"), ("user_id", "User"), ("submission_type", "Result"), ("date", "Time"), ("provided", "Provided")],
    )


@web.get("/admin/session-management")
def admin_sessions() -> Response | tuple[str, int] | str:
    context, gate = _admin_context("sessions", "Sessions")
    if gate:
        return gate
    users, users_error = _admin_read("/api/v1/sessions/users?q=", [])
    selected_user_id = request.args.get("user_id", type=int)
    session_data: dict[str, Any] | None = None
    session_error = False
    if selected_user_id is not None:
        value, session_error = _admin_read(
            f"/api/v1/sessions?user_id={selected_user_id}", {}
        )
        if isinstance(value, dict):
            session_data = value
    context.update(
        session_users=users if isinstance(users, list) else [],
        selected_user_id=selected_user_id,
        session_data=session_data,
        module_error=users_error and session_error,
    )
    return render_template("admin/sessions.html", **context)


@web.route(
    "/bff/api/v1/", defaults={"subpath": ""},
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
)
@web.route(
    "/bff/api/v1/<path:subpath>",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
)
def api_proxy(subpath: str) -> Response:
    if (
        request.method == "POST"
        and subpath == "storage/uploads"
        and not request.is_json
    ):
        return (
            jsonify(
                {
                    "success": False,
                    "message": "Upload initiation accepts JSON metadata only; send file bytes directly to object storage.",
                }
            ),
            415,
        )
    frontend_error = _validate_player_frontend_mutation(subpath)
    if frontend_error is not None:
        return frontend_error
    return _proxy("/api/v1" + (f"/{subpath}" if subpath else ""))


def _validate_player_frontend_mutation(subpath: str) -> tuple[Response, int] | None:
    if request.method not in {"POST", "PUT", "PATCH"} or not request.is_json:
        return None
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return None

    selected: Any = _MISSING
    if subpath == "configs/player_frontend":
        selected = payload.get("value", _MISSING)
    elif subpath == "configs" and request.method == "PATCH":
        selected = payload.get("player_frontend", _MISSING)
    elif (
        subpath == "configs"
        and request.method == "POST"
        and payload.get("key") == "player_frontend"
    ):
        selected = payload.get("value", _MISSING)

    if selected is _MISSING or _frontends().get(selected) is not None:
        return None
    return (
        jsonify(
            {
                "success": False,
                "message": "Unknown player frontend",
                "available": [
                    manifest["id"]
                    for manifest in _frontends().public_manifests()
                ],
            }
        ),
        400,
    )


def _validated_storage_url(value: Any) -> str | None:
    configured_origin = current_app.config["OBJECT_STORAGE_ORIGIN"]
    if not configured_origin or not isinstance(value, str):
        return None
    try:
        parsed = urlsplit(value)
    except ValueError:
        return None
    if (
        parsed.fragment
        or parsed.username
        or parsed.password
        or "\r" in value
        or "\n" in value
        or _origin_key(value) != _origin_key(configured_origin)
    ):
        return None
    return value


@web.get("/category-icons/<int:category_id>/<uuid:object_id>")
def category_icon(category_id: int, object_id: UUID) -> Response:
    if category_id < 1:
        abort(404)
    status, grant = _read_data(
        f"/api/v1/challenge-categories/{category_id}/icon/{object_id}", {}
    )
    if status in {401, 403, 404}:
        abort(404)
    if status >= 400:
        return Response("Category icon is temporarily unavailable", status=502)
    if not isinstance(grant, dict) or grant.get("method") != "GET":
        return Response("Category icon authorization is invalid", status=502)
    destination = _validated_storage_url(grant.get("url"))
    if destination is None:
        return Response("Category icon authorization is invalid", status=502)
    outgoing = redirect(destination, code=303)
    outgoing.headers["Cache-Control"] = "private, no-store"
    outgoing.headers["Referrer-Policy"] = "no-referrer"
    return outgoing


@web.get("/downloads/<uuid:object_id>")
def download_object(object_id: UUID) -> Response:
    status, grant = _read_data(
        f"/api/v1/storage/objects/{object_id}/download", {}
    )
    if status == 401:
        return redirect(url_for("web.login", next=request.path), code=302)
    if status == 403:
        abort(403)
    if status == 404:
        abort(404)
    if status >= 400:
        return Response("Download authorization is temporarily unavailable", status=502)
    destination = _validated_storage_url(
        grant.get("url") if isinstance(grant, dict) else None
    )
    if destination is None:
        return Response("Download authorization is invalid", status=502)
    outgoing = redirect(destination, code=303)
    outgoing.headers["Cache-Control"] = "private, no-store"
    outgoing.headers["Referrer-Policy"] = "no-referrer"
    return outgoing
