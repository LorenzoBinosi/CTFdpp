"""HTML routes and the constrained browser-to-API proxy."""

from __future__ import annotations

from collections import Counter
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import quote, urlencode, urlsplit

from flask import (
    Blueprint,
    Response,
    abort,
    current_app,
    jsonify,
    redirect,
    render_template,
    request,
    stream_with_context,
    url_for,
)

from .api import ApiClient, ApiUnavailable
from .markdown import render_markdown

web = Blueprint("web", __name__)

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
}


def _api() -> ApiClient:
    return current_app.extensions["ctfzone_api"]


def _read_data(path: str, default: Any = None) -> tuple[int, Any]:
    try:
        status, payload = _api().get_json(path, request)
    except ApiUnavailable:
        return 503, default
    return status, ApiClient.unwrap(payload, default)


def _bootstrap() -> dict[str, Any]:
    status, data = _read_data("/api/v1/bootstrap", {})
    if status >= 500 or not isinstance(data, dict):
        data = {}

    site = data.get("site") if isinstance(data.get("site"), dict) else {}
    site = {
        "name": site.get("name") or "CTFZone",
        "description": site.get("description") or "Capture the flag. Own the zone.",
        "user_mode": site.get("user_mode") or "users",
        "start": site.get("start"),
        "end": site.get("end"),
        "paused": bool(site.get("paused", False)),
        "challenge_visibility": site.get("challenge_visibility") or "private",
        "score_visibility": site.get("score_visibility") or "public",
        "account_visibility": site.get("account_visibility") or "public",
        "registration_visibility": site.get("registration_visibility") or "public",
    }
    user = data.get("user") if isinstance(data.get("user"), dict) else None
    authenticated = bool(data.get("authenticated") and user)

    # The account endpoint enriches the compact bootstrap identity with score/place.
    if authenticated:
        user_status, account = _read_data("/api/v1/users/me", {})
        if user_status < 400 and isinstance(account, dict):
            user = {**user, **account}

    return {
        "available": status < 500,
        "setup_required": bool(data.get("setup_required", False)),
        "authenticated": authenticated,
        "csrf_token": data.get("csrf_token") or "",
        "user": user,
        "site": site,
    }


def _page_context(page: str, **extra: Any) -> dict[str, Any]:
    bootstrap = _bootstrap()
    return {
        "page": page,
        "bootstrap": bootstrap,
        "site": bootstrap["site"],
        "user": bootstrap["user"],
        "csrf_token": bootstrap["csrf_token"],
        **extra,
    }


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
    for cookie in response.headers.get_list("set-cookie"):
        outgoing.headers.add("set-cookie", cookie)
    return outgoing


def _proxy(path: str) -> Response:
    try:
        upstream = _api().request_from_browser(request, path)
    except ApiUnavailable as error:
        return jsonify({"success": False, "message": str(error)}), 502
    return _copy_upstream(upstream)


@web.get("/healthz")
def healthz() -> Response:
    return jsonify({"status": "ok", "service": "backend", "mode": "bff"})


@web.get("/")
def index() -> Response:
    return redirect(url_for("web.challenges"), code=302)


@web.route("/login", methods=["GET", "POST"])
def login() -> Response | str:
    if request.method == "POST":
        return _proxy("/login")
    return render_template(
        "login.html",
        **_page_context("login", error=_error_message(), next=request.args.get("next", "")),
    )


@web.route("/register", methods=["GET", "POST"])
def register() -> Response | str:
    if request.method == "POST":
        return _proxy("/register")
    return render_template(
        "register.html", **_page_context("register", error=_error_message())
    )


@web.route("/setup", methods=["GET", "POST"])
def setup() -> Response | str:
    if request.method in {"GET", "HEAD"}:
        context = _page_context("setup", error=_error_message())
        if not context["bootstrap"]["setup_required"]:
            context["notice"] = "Setup is only available on an empty CTFZone installation."
        return render_template("setup.html", **context)

    try:
        upstream = _api().request_from_browser(request, "/setup")
    except ApiUnavailable:
        return redirect(url_for("web.setup", error="setup_failed"), code=303)
    content_type = upstream.headers.get("content-type", "")
    if "application/json" in content_type:
        try:
            payload = upstream.json()
        except ValueError:
            payload = {}
        if upstream.is_success and payload.get("success", True):
            destination = "/challenges" if upstream.headers.get_list("set-cookie") else "/login"
            outgoing = redirect(destination, code=303)
            for cookie in upstream.headers.get_list("set-cookie"):
                outgoing.headers.add("set-cookie", cookie)
            return outgoing
        message = payload.get("message") or "setup_failed"
        return redirect(url_for("web.setup") + "?" + urlencode({"error": message}), code=303)
    return _copy_upstream(upstream)


@web.route("/logout", methods=["GET", "POST"])
def logout() -> Response:
    return _proxy("/logout")


def _tag_values(challenge: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for tag in challenge.get("tags") or []:
        value = tag.get("value") if isinstance(tag, dict) else tag
        if value:
            values.append(str(value))
    return values


def _category_icon(category: str) -> str:
    lowered = category.lower()
    if any(value in lowered for value in ("web", "http")):
        return "globe"
    if any(value in lowered for value in ("pwn", "binary", "exploit")):
        return "skull"
    if "crypto" in lowered:
        return "lock"
    if any(value in lowered for value in ("rev", "reverse")):
        return "bug"
    if any(value in lowered for value in ("forensic", "network")):
        return "search"
    return "puzzle"


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
        difficulty = next(
            (tag for tag in tags if tag.casefold() in {"easy", "medium", "hard", "insane"}),
            None,
        )
        challenge.update(
            category=category,
            category_key=category.casefold(),
            category_icon=_category_icon(category),
            tags=tags,
            tag_keys=" ".join(sorted(tag_keys)),
            difficulty=difficulty,
            runtime_available=bool(challenge.get("runtime_available") or "instance" in tag_keys),
        )
        challenges.append(challenge)
    return challenges


def _decorate_detail(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    challenge = dict(value)
    challenge["category_icon"] = _category_icon(str(challenge.get("category") or "misc"))
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
        if isinstance(raw, str):
            url = raw
            name = PurePosixPath(raw).name or "download"
        elif isinstance(raw, dict):
            location = raw.get("location")
            url = raw.get("url") or (f"/files/{quote(str(location))}" if location else "")
            name = raw.get("name") or (PurePosixPath(str(location)).name if location else "download")
        else:
            continue
        if not url:
            continue
        if url.startswith("/files/"):
            url = "/bff" + url
        files.append({"name": str(name), "url": str(url)})
    challenge["files"] = files
    return challenge


@web.get("/challenges")
def challenges() -> str:
    context = _page_context("challenges")
    status, data = _read_data("/api/v1/challenges", [])
    challenge_list = _decorate_challenges(data)
    selected_id = request.args.get("challenge", type=int)
    if selected_id is None and challenge_list:
        selected_id = int(challenge_list[0]["id"])
    selected = None
    panel_error = None
    if selected_id is not None:
        detail_status, detail = _read_data(f"/api/v1/challenges/{selected_id}", {})
        if detail_status < 400:
            selected = _decorate_detail(detail)
        elif detail_status not in {401, 403, 404}:
            panel_error = "Challenge details are temporarily unavailable."

    counts = Counter(challenge["category"] for challenge in challenge_list)
    categories = [
        {"name": name, "count": count, "icon": _category_icon(name)}
        for name, count in sorted(counts.items(), key=lambda item: item[0].casefold())
    ]
    context.update(
        challenges=challenge_list,
        categories=categories,
        selected=selected,
        selected_id=selected_id,
        panel_error=panel_error,
        api_error=status >= 500,
    )
    return render_template("challenges.html", **context)


@web.get("/bff/fragments/challenges/<int:challenge_id>")
def challenge_fragment(challenge_id: int) -> tuple[str, int] | str:
    status, detail = _read_data(f"/api/v1/challenges/{challenge_id}", {})
    challenge = _decorate_detail(detail) if status < 400 else None
    bootstrap = _bootstrap()
    html = render_template(
        "partials/challenge_panel.html",
        challenge=challenge,
        bootstrap=bootstrap,
        user=bootstrap["user"],
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
    context.update(standings=standings if isinstance(standings, list) else [], api_error=status >= 500)
    return render_template("scoreboard.html", **context)


@web.get("/team")
def team() -> str:
    context = _page_context("team")
    team_data: dict[str, Any] | None = None
    if context["bootstrap"]["authenticated"]:
        status, value = _read_data("/api/v1/teams/me", {})
        if status < 400 and isinstance(value, dict):
            team_data = value
    context["team"] = team_data
    return render_template("team.html", **context)


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
def profile_alias() -> Response:
    context = _page_context("profile")
    if not context["bootstrap"]["authenticated"] or not context["user"]:
        return redirect(url_for("web.login", next=url_for("web.profile_alias")), code=302)
    if context["site"]["user_mode"] == "teams":
        team_id = context["user"].get("team_id")
        if team_id:
            return redirect(url_for("web.team_profile", team_id=team_id), code=302)
        return redirect(url_for("web.team"), code=302)
    return redirect(
        url_for("web.user_profile", user_id=context["user"]["id"]), code=302
    )


def _profile_page(kind: str, account_id: int) -> Response | tuple[str, int] | str:
    context = _page_context("profile")
    status, value = _read_data(f"/api/v1/{kind}s/{account_id}", {})
    if status == 401:
        return redirect(url_for("web.login", next=request.path), code=302)
    profile = _public_profile(value) if status < 400 else None
    context.update(
        profile=profile,
        profile_kind=kind,
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
    rendered = render_template("profile.html", **context)
    return (rendered, status) if status >= 400 else rendered


@web.get("/users/<int:user_id>")
def user_profile(user_id: int) -> Response | tuple[str, int] | str:
    return _profile_page("user", user_id)


@web.get("/teams/<int:team_id>")
def team_profile(team_id: int) -> Response | tuple[str, int] | str:
    return _profile_page("team", team_id)


@web.get("/rules")
def rules() -> str:
    context = _page_context("rules")
    page_data = None
    for path in ("/api/v1/pages/by-route/rules", "/api/v1/pages/route/rules"):
        status, value = _read_data(path, None)
        if status < 400 and isinstance(value, dict):
            page_data = value
            break
        if status != 404:
            break
    raw = page_data.get("content") if page_data else None
    if not raw:
        raw = (
            "# Rules\n\n"
            "- Only attack systems explicitly listed as challenge targets.\n"
            "- Do not disrupt the platform, other participants, or shared infrastructure.\n"
            "- Do not share flags or solutions while the event is running.\n"
            "- Report platform issues privately to the organizers.\n\n"
            "Good luck, have fun, and leave the infrastructure better than you found it."
        )
    context.update(rules_title=(page_data or {}).get("title") or "Rules", rules_html=render_markdown(raw))
    return render_template("rules.html", **context)


def _admin_context(module: str, title: str) -> tuple[dict[str, Any] | None, Response | tuple[str, int] | None]:
    context = _page_context("admin")
    context.update(admin_module=module, admin_title=title)
    if not context["bootstrap"]["authenticated"]:
        destination = request.full_path.rstrip("?")
        return None, redirect(url_for("web.login", next=destination), code=302)
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


@web.get("/admin")
def admin_overview() -> Response | tuple[str, int] | str:
    context, gate = _admin_context("overview", "Overview")
    if gate:
        return gate
    challenges_data, challenges_error = _admin_read("/api/v1/challenges?view=admin", [])
    users, users_error = _admin_read("/api/v1/users?view=admin&per_page=100", [])
    if context["site"]["user_mode"] == "teams":
        teams, teams_error = _admin_read("/api/v1/teams?view=admin&per_page=100", [])
    else:
        teams, teams_error = [], False
    runtime_data, runtime_error = _admin_read("/api/v1/admin/runtime/instances?per_page=20", {})
    submissions, submissions_error = _admin_read("/api/v1/submissions?per_page=8", [])
    runtime_items = runtime_data.get("items", []) if isinstance(runtime_data, dict) else []
    runtime_total = (
        runtime_data.get("pagination", {}).get("total", len(runtime_items))
        if isinstance(runtime_data, dict)
        else 0
    )
    context.update(
        stats={
            "challenges": len(challenges_data) if isinstance(challenges_data, list) else 0,
            "users": len(users) if isinstance(users, list) else 0,
            "teams": len(teams) if isinstance(teams, list) else 0,
            "instances": runtime_total,
        },
        recent_submissions=submissions if isinstance(submissions, list) else [],
        module_error=any(
            (challenges_error, users_error, teams_error, runtime_error, submissions_error)
        ),
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


@web.get("/admin/challenges/new")
def admin_challenge_new() -> Response | tuple[str, int] | str:
    context, gate = _admin_context("challenges", "New challenge")
    if gate:
        return gate
    context.update(challenge=None, form_mode="create", module_error=False)
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
    context.update(challenge=challenge, form_mode="edit", module_error=error)
    return render_template("admin/challenge_form.html", **context)


@web.get("/admin/config")
def admin_config() -> Response | tuple[str, int] | str:
    context, gate = _admin_context("config", "Configuration")
    if gate:
        return gate
    data, error = _admin_read("/api/v1/configs", [])
    configs = sorted(
        (
            item
            for item in data
            if isinstance(item, dict)
            and item.get("key")
            and item.get("key") != "setup"
        )
        if isinstance(data, list)
        else [],
        key=lambda item: str(item["key"]).casefold(),
    )
    context.update(configs=configs, module_error=error)
    return render_template("admin/config.html", **context)


@web.get("/admin/runtime")
def admin_runtime() -> Response | tuple[str, int] | str:
    context, gate = _admin_context("runtime", "Managed instances")
    if gate:
        return gate
    setting, setting_error = _admin_read(
        "/api/v1/admin/runtime/settings/private-challenges", {}
    )
    instance_data, instances_error = _admin_read(
        "/api/v1/admin/runtime/instances?per_page=100", {}
    )
    servers, servers_error = _admin_read("/api/v1/admin/runtime/servers", [])
    instances = instance_data.get("items", []) if isinstance(instance_data, dict) else []
    context.update(
        runtime_setting=setting if isinstance(setting, dict) else {},
        instances=instances,
        servers=servers if isinstance(servers, list) else [],
        module_error=setting_error and instances_error and servers_error,
    )
    return render_template("admin/runtime.html", **context)


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
    return _admin_records(
        "users",
        "Users",
        "/api/v1/users?view=admin&per_page=100",
        [("id", "ID"), ("name", "Name"), ("team_id", "Team"), ("affiliation", "Affiliation"), ("country", "Country")],
    )


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


@web.get("/admin/sessions")
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


@web.get("/admin/<path:legacy_path>")
def admin_placeholder(legacy_path: str) -> Response | tuple[str, int] | str:
    label = legacy_path.replace("-", " ").replace("_", " ").replace("/", " / ").title()
    context, gate = _admin_context("placeholder", label or "Administration")
    if gate:
        return gate
    context.update(legacy_path=legacy_path)
    return render_template("admin/placeholder.html", **context)


@web.route(
    "/bff/api/v1/", defaults={"subpath": ""},
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
)
@web.route(
    "/bff/api/v1/<path:subpath>",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
)
def api_proxy(subpath: str) -> Response:
    return _proxy("/api/v1" + (f"/{subpath}" if subpath else ""))


@web.get("/bff/files/<path:file_path>")
def file_proxy(file_path: str) -> Response:
    if any(part == ".." for part in PurePosixPath(file_path).parts):
        abort(404)
    try:
        upstream = _api().open_download(f"/files/{quote(file_path, safe='/')}", request)
    except ApiUnavailable as error:
        return Response(str(error), status=502, content_type="text/plain")

    @stream_with_context
    def body():
        try:
            yield from upstream.iter_raw()
        finally:
            upstream.close()

    outgoing = Response(body(), status=upstream.status_code, direct_passthrough=True)
    for name in _RESPONSE_HEADERS:
        value = upstream.headers.get(name)
        if value is not None:
            outgoing.headers[name] = value
    content_length = upstream.headers.get("content-length")
    if content_length:
        outgoing.headers["content-length"] = content_length
    return outgoing
