import copy
import json
import re
import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx

import ctfzone_web
from ctfzone_web import create_app
from ctfzone_web.frontends import FrontendConfigurationError, FrontendRegistry
from ctfzone_web.views import _safe_destination


SESSION_ID = "00000000-0000-4000-8000-000000000007"
OBJECT_ID = "11111111-1111-4111-8111-111111111111"
CSRF_TOKEN = "test-nonce-that-is-long-enough-for-python-csrf"
APP_CONFIG = {
    "TESTING": True,
    "SECRET_KEY": "test-only-browser-session-signing-key",
    "BACKEND_SERVICE_TOKEN": "test-backend-service-token",
    "OBJECT_STORAGE_PUBLIC_URL": "https://files.example.test",
    "SESSION_COOKIE_SECURE": False,
}

BOOTSTRAP = {
    "success": True,
    "data": {
        "setup_required": False,
        "authenticated": True,
        "user": {
            "id": 1,
            "name": "operator",
            "email": "operator@example.test",
            "type": "user",
            "team_id": None,
            "verified": True,
            "score": 150,
            "place": "1st",
        },
        "site": {
            "name": "CTFZone",
            "user_mode": "users",
            "registration_visibility": "public",
            "player_frontend": "terminal",
        },
    },
}

CHALLENGE_LIST = [
    {
        "id": 7,
        "name": "Cookie Jar",
        "value": 150,
        "category": "web",
        "solves": 4,
        "solved_by_me": False,
        "state": "visible",
        "type": "standard",
        "runtime_available": True,
        "tags": [{"value": "easy"}, {"value": "instance"}],
    }
]

CHALLENGE_DETAIL = {
    "id": 7,
    "name": "Cookie Jar",
    "description": "Find **the flag** <script>bad()</script>",
    "value": 150,
    "category": "web",
    "solves": 4,
    "solved_by_me": False,
    "tags": [{"value": "easy"}],
    "hints": [],
    "files": [
        {
            "id": 19,
            "object_id": OBJECT_ID,
            "name": "starter.zip",
            "content_type": "application/zip",
            "size": 4096,
            "sha256": None,
        },
        {"name": "legacy.txt", "url": "https://evil.example/legacy.txt"},
    ],
    "runtime": {"available": False},
}


class FakeApi:
    def __init__(self, bootstrap=None, responses=None):
        self.browser_request = None
        self.calls = []
        self.bootstrap = copy.deepcopy(BOOTSTRAP if bootstrap is None else bootstrap)
        admin_overview = {
            "success": True,
            "data": {
                "bootstrap": copy.deepcopy(self.bootstrap["data"]),
                "stats": {"challenges": 1, "users": 1, "teams": 0, "instances": 1},
                "recent_submissions": [
                    {
                        "id": 91,
                        "challenge_id": 7,
                        "user_id": 1,
                        "submission_type": "correct",
                        "date": "2026-08-11T10:30:00Z",
                    }
                ],
            },
        }
        challenge_view = {
            "success": True,
            "data": {
                "bootstrap": copy.deepcopy(self.bootstrap["data"]),
                "challenges": copy.deepcopy(CHALLENGE_LIST),
                "selected": copy.deepcopy(CHALLENGE_DETAIL),
            },
        }
        self.responses = {
            "/api/v1/bootstrap": (200, self.bootstrap),
            "/api/v1/views/challenges": (200, challenge_view),
            "/api/v1/views/challenges?selected=7": (200, challenge_view),
            "/api/v1/views/admin/overview": (200, admin_overview),
            "/api/v1/challenges/7": (
                200,
                {"success": True, "data": copy.deepcopy(CHALLENGE_DETAIL)},
            ),
            f"/api/v1/storage/objects/{OBJECT_ID}/download": (
                200,
                {
                    "success": True,
                    "data": {
                        "method": "GET",
                        "url": (
                            "https://files.example.test/ctfzone/challenge/"
                            f"{OBJECT_ID}/starter.zip?X-Amz-Signature=test"
                        ),
                        "expires_at": "2026-08-11T11:00:00Z",
                    },
                },
            ),
            "/api/v1/challenges?view=admin": (
                200,
                {"success": True, "data": copy.deepcopy(CHALLENGE_LIST)},
            ),
            "/api/v1/users?view=admin&per_page=50&page=1": (
                200,
                {
                    "success": True,
                    "meta": {
                        "pagination": {
                            "page": 1,
                            "next": None,
                            "prev": None,
                            "pages": 1,
                            "per_page": 50,
                            "total": 1,
                        }
                    },
                    "data": [
                        {
                            "id": 1,
                            "name": "operator",
                            "email": "operator@example.test",
                            "type": "user",
                            "hidden": False,
                            "verified": True,
                        }
                    ],
                },
            ),
            "/api/v1/teams?view=admin&per_page=100": (
                200,
                {
                    "success": True,
                    "data": [
                        {
                            "id": 3,
                            "name": "Blue Team",
                            "email": "blue@example.test",
                            "captain_id": 1,
                            "banned": False,
                        }
                    ],
                },
            ),
            "/api/v1/users/1": (
                200,
                {
                    "success": True,
                    "data": {
                        "id": 1,
                        "name": "operator",
                        "affiliation": "CTFZone",
                        "country": "IT",
                        "score": 150,
                        "place": "1st",
                        "team_id": None,
                        "fields": [],
                    },
                },
            ),
            "/api/v1/users/me": (
                200,
                {
                    "success": True,
                    "data": {
                        "id": 1,
                        "name": "operator",
                        "email": "operator@example.test",
                        "affiliation": "CTFZone",
                        "country": "IT",
                        "website": None,
                        "score": 25,
                        "place": "9th",
                        "team_id": None,
                        "fields": [],
                    },
                },
            ),
            "/api/v1/users/1?view=admin": (
                200,
                {
                    "success": True,
                    "data": {
                        "id": 1,
                        "name": "operator",
                        "email": "operator@example.test",
                        "type": "user",
                        "hidden": False,
                        "verified": False,
                    },
                },
            ),
            "/api/v1/teams/3": (
                200,
                {
                    "success": True,
                    "data": {
                        "id": 3,
                        "name": "Blue Team",
                        "affiliation": "CTFZone",
                        "score": 300,
                        "place": "1st",
                        "captain_id": 1,
                        "members": [{"id": 1, "name": "operator"}],
                        "fields": [],
                    },
                },
            ),
            "/api/v1/scoreboard": (200, {"success": True, "data": []}),
            "/api/v1/teams/me": (404, {"message": "No team"}),
            "/api/v1/pages/by-route/rules": (404, {"message": "Not found"}),
            "/api/v1/pages/route/rules": (404, {"message": "Not found"}),
        }
        if responses:
            self.responses.update(copy.deepcopy(responses))

    def get_json(self, path, _incoming, *, session_id=None):
        self.calls.append(("GET", path, session_id))
        return copy.deepcopy(self.responses.get(path, (404, {"message": "Not found"})))

    def request(
        self,
        method,
        path,
        *,
        incoming=None,
        session_id=None,
        content=None,
        headers=None,
    ):
        self.calls.append((method, path, session_id))
        self.browser_request = (method, path, content or b"")
        auth_path = path.split("?", 1)[0]
        if auth_path in {"/setup", "/login", "/register"}:
            requested_destination = parse_qs(urlsplit(path).query).get("next", [None])[0]
            payload = {
                "success": True,
                "data": {
                    "session_id": SESSION_ID,
                    "redirect": (
                        "/admin"
                        if auth_path == "/setup"
                        else requested_destination or "/challenges"
                    ),
                },
            }
        elif path == "/logout":
            payload = {"success": True, "data": {"revoked": True}}
        else:
            payload = {"success": True}
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            content=json.dumps(payload),
            request=httpx.Request(method, f"http://api.test{path}"),
        )

    def request_from_browser(
        self, incoming, path, *, session_id=None, timeout_seconds=None
    ):
        content = incoming.get_data()
        self.calls.append((incoming.method, path, session_id))
        self.browser_request = (incoming.method, path, content)
        self.browser_timeout = timeout_seconds
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            content=json.dumps({"success": True, "data": {"status": "correct"}}),
            request=httpx.Request(incoming.method, f"http://api.test{path}"),
        )


def make_app(api, **config):
    return create_app({**APP_CONFIG, "API_CLIENT": api, **config})


def seed_browser_session(client, *, authenticated=True, csrf=CSRF_TOKEN):
    with client.session_transaction() as browser_session:
        browser_session["csrf_token"] = csrf
        if authenticated:
            browser_session["rust_session_id"] = SESSION_ID


def unsafe_headers(csrf=CSRF_TOKEN, origin="http://localhost"):
    return {"Origin": origin, "Sec-Fetch-Site": "same-origin", "csrf-token": csrf}


PLAYER_TEMPLATE_NAMES = (
    "base.html",
    "login.html",
    "register.html",
    "confirm.html",
    "challenges.html",
    "scoreboard.html",
    "team.html",
    "profile.html",
    "rules.html",
    "partials/challenge_panel.html",
)
ADMIN_TEMPLATE_NAMES = (
    "base.html",
    "setup.html",
    "forbidden.html",
    "overview.html",
    "challenges.html",
    "challenge_form.html",
    "users.html",
    "user_form.html",
    "config.html",
    "runtime.html",
    "records.html",
    "sessions.html",
    "placeholder.html",
)


def make_frontend_tree(root: Path, *identifiers: str) -> Path:
    frontend_root = root / "frontends"
    (frontend_root / "admin" / "templates").mkdir(parents=True)
    for template in ADMIN_TEMPLATE_NAMES:
        (frontend_root / "admin" / "templates" / template).write_text(
            f"admin={template}", encoding="utf-8"
        )
    for asset in ("css/admin.css", "js/admin.js"):
        target = frontend_root / "admin" / "static" / asset
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(asset, encoding="utf-8")
    for asset in ("js/api.js", "js/storage.js", "js/ui.js"):
        target = frontend_root / "shared" / "static" / asset
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(asset, encoding="utf-8")
    for identifier in identifiers:
        frontend = frontend_root / "player" / identifier
        (frontend / "templates" / "partials").mkdir(parents=True)
        (frontend / "static").mkdir(parents=True)
        (frontend / "manifest.json").write_text(
            json.dumps(
                {
                    "id": identifier,
                    "name": identifier.replace("-", " ").title(),
                    "description": f"Test frontend {identifier}",
                    "version": "1.0.0",
                    "assets": ["marker.txt"],
                }
            ),
            encoding="utf-8",
        )
        for template in PLAYER_TEMPLATE_NAMES:
            (frontend / "templates" / template).write_text(
                (
                    f"frontend={identifier};template={template};"
                    "site={{ site.name if site is defined else '' }};"
                    "asset={{ player_asset('marker.txt') if player_asset is defined else '' }}"
                ),
                encoding="utf-8",
            )
        (frontend / "static" / "marker.txt").write_text(identifier, encoding="utf-8")
    return frontend_root


class FrontendRegistryTests(unittest.TestCase):
    def test_registry_resolves_only_installed_safe_identifiers(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = make_frontend_tree(Path(temporary), "terminal", "plain")
            registry = FrontendRegistry.discover(root)

            self.assertEqual(registry.resolve("plain").identifier, "plain")
            initial_asset_version = registry.asset_version
            (root / "player" / "plain" / "static" / "marker.txt").write_text(
                "plain-updated", encoding="utf-8"
            )
            self.assertNotEqual(
                FrontendRegistry.discover(root).asset_version,
                initial_asset_version,
            )
            for unknown in (None, "missing", "../plain", "terminal/../../admin"):
                with self.subTest(unknown=unknown):
                    self.assertEqual(
                        registry.resolve(unknown).identifier,
                        "terminal",
                    )
            with self.assertRaises(FrontendConfigurationError):
                registry.template_name(registry.default, "../base.html")

    def test_registry_fails_closed_for_invalid_manifest_or_missing_contract(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = make_frontend_tree(Path(temporary), "terminal")
            (root / "player" / "terminal" / "manifest.json").write_text(
                '{"id":"other","name":"Wrong"}', encoding="utf-8"
            )
            with self.assertRaisesRegex(
                FrontendConfigurationError, "must match directory"
            ):
                FrontendRegistry.discover(root)

        with tempfile.TemporaryDirectory() as temporary:
            root = make_frontend_tree(Path(temporary), "terminal")
            (root / "player" / "terminal" / "templates" / "rules.html").unlink()
            with self.assertRaisesRegex(FrontendConfigurationError, "rules.html"):
                FrontendRegistry.discover(root)

        with tempfile.TemporaryDirectory() as temporary:
            root = make_frontend_tree(Path(temporary), "terminal")
            (root / "player" / "terminal" / "static" / "marker.txt").unlink()
            with self.assertRaisesRegex(FrontendConfigurationError, "marker.txt"):
                FrontendRegistry.discover(root)

        with tempfile.TemporaryDirectory() as temporary:
            root = make_frontend_tree(Path(temporary), "terminal")
            (root / "admin" / "static" / "css" / "admin.css").unlink()
            with self.assertRaisesRegex(FrontendConfigurationError, "admin.css"):
                FrontendRegistry.discover(root)

        with tempfile.TemporaryDirectory() as temporary:
            root = make_frontend_tree(Path(temporary), "terminal")
            (root / "shared" / "static" / "js" / "api.js").unlink()
            with self.assertRaisesRegex(FrontendConfigurationError, "api.js"):
                FrontendRegistry.discover(root)

    def test_registry_rejects_manifest_asset_symlink_outside_frontend_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = make_frontend_tree(Path(temporary), "terminal")
            outside = Path(temporary) / "outside.txt"
            outside.write_text("must-not-be-served", encoding="utf-8")
            marker = root / "player" / "terminal" / "static" / "marker.txt"
            marker.unlink()
            marker.symlink_to(outside)

            with self.assertRaisesRegex(
                FrontendConfigurationError, "outside its registered frontend root"
            ):
                FrontendRegistry.discover(root)


class AppTests(unittest.TestCase):
    def setUp(self):
        self.api = FakeApi()
        self.app = make_app(self.api)
        self.client = self.app.test_client()
        seed_browser_session(self.client)

    def client_for_role(self, role):
        bootstrap = copy.deepcopy(BOOTSTRAP)
        if role is None:
            bootstrap["data"]["authenticated"] = False
            bootstrap["data"]["user"] = None
        else:
            bootstrap["data"]["user"]["type"] = role
        api = FakeApi(bootstrap=bootstrap)
        app = make_app(api)
        client = app.test_client()
        seed_browser_session(client, authenticated=role is not None)
        client.fake_api = api
        return client

    def test_auth_redirect_rejects_backslash_and_control_normalization(self):
        fallback = "/challenges"
        self.assertEqual(_safe_destination("/scoreboard", fallback), "/scoreboard")
        for unsafe in ("/\\evil.example", "/\\/evil.example", "/team\x00evil"):
            with self.subTest(unsafe=repr(unsafe)):
                self.assertEqual(_safe_destination(unsafe, fallback), fallback)

    def test_health_does_not_require_the_api(self):
        response = self.client.get("/healthz")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["mode"], "bff")

    def test_root_uses_one_bootstrap_call_and_prioritizes_first_boot_setup(self):
        bootstrap = copy.deepcopy(BOOTSTRAP)
        bootstrap["data"]["setup_required"] = True
        bootstrap["data"]["authenticated"] = False
        bootstrap["data"]["user"] = None
        api = FakeApi(bootstrap=bootstrap)
        client = make_app(api).test_client()

        response = client.get("/")

        self.assertEqual(response.status_code, 302)
        self.assertEqual(urlsplit(response.headers["Location"]).path, "/setup")
        self.assertEqual(
            api.calls,
            [("GET", "/api/v1/bootstrap", None)],
        )

        self.api.calls.clear()
        response = self.client.get("/")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(urlsplit(response.headers["Location"]).path, "/challenges")
        self.assertEqual(
            self.api.calls,
            [("GET", "/api/v1/bootstrap", SESSION_ID)],
        )

    def test_player_frontend_selection_uses_registry_and_falls_back_safely(self):
        with tempfile.TemporaryDirectory() as temporary:
            frontend_root = make_frontend_tree(
                Path(temporary), "terminal", "plain"
            )
            for requested, expected in (
                ("plain", "plain"),
                ("missing", "terminal"),
                ("../../admin", "terminal"),
            ):
                with self.subTest(requested=requested):
                    bootstrap = copy.deepcopy(BOOTSTRAP)
                    bootstrap["data"]["site"]["name"] = "Event <script>"
                    bootstrap["data"]["site"]["player_frontend"] = requested
                    api = FakeApi(bootstrap=bootstrap)
                    client = make_app(
                        api, FRONTENDS_ROOT=str(frontend_root)
                    ).test_client()
                    seed_browser_session(client)

                    body = client.get("/challenges").get_data(as_text=True)

                    self.assertIn(f"frontend={expected}", body)
                    self.assertIn("site=Event &lt;script&gt;", body)
                    self.assertIn(
                        f"asset=/assets/player/{expected}/marker.txt", body
                    )

    def test_frontend_assets_are_namespaced_and_legacy_static_is_disabled(self):
        with tempfile.TemporaryDirectory() as temporary:
            frontend_root = make_frontend_tree(
                Path(temporary), "terminal", "plain"
            )
            (frontend_root / "admin" / "static" / "marker.txt").write_text(
                "admin", encoding="utf-8"
            )
            (frontend_root / "shared" / "static" / "marker.txt").write_text(
                "shared", encoding="utf-8"
            )
            client = make_app(
                FakeApi(), FRONTENDS_ROOT=str(frontend_root)
            ).test_client()

            expected = {
                "/assets/admin/marker.txt": "admin",
                "/assets/shared/marker.txt": "shared",
                "/assets/player/terminal/marker.txt": "terminal",
                "/assets/player/plain/marker.txt": "plain",
            }
            for path, body in expected.items():
                with self.subTest(path=path):
                    response = client.get(path)
                    self.assertEqual(response.status_code, 200)
                    self.assertEqual(response.get_data(as_text=True), body)
                    self.assertIn("max-age=0", response.headers["Cache-Control"])
                    response.close()
            for path in (
                "/static/js/app.js",
                "/assets/player/unknown/marker.txt",
                "/assets/admin/not-present.txt",
            ):
                with self.subTest(path=path):
                    self.assertEqual(client.get(path).status_code, 404)

            outside = Path(temporary) / "outside.txt"
            outside.write_text("must-not-leak", encoding="utf-8")
            (frontend_root / "player" / "terminal" / "static" / "escape.txt").symlink_to(
                outside
            )
            self.assertEqual(
                client.get("/assets/player/terminal/escape.txt").status_code, 404
            )

    def test_real_player_and_admin_shells_use_event_name_and_isolated_assets(self):
        bootstrap = copy.deepcopy(BOOTSTRAP)
        bootstrap["data"]["site"]["name"] = "Null Sector <Final>"
        bootstrap["data"]["user"]["type"] = "admin"
        api = FakeApi(bootstrap=bootstrap)
        client = make_app(api).test_client()
        seed_browser_session(client)

        player = client.get("/challenges").get_data(as_text=True)
        self.assertIn(
            '<span class="brand-primary">Null Sector &lt;Final&gt;</span>',
            player,
        )
        self.assertIn('/assets/player/terminal/css/player.css', player)
        self.assertNotIn('/assets/admin/css/admin.css', player)

        admin = client.get("/admin").get_data(as_text=True)
        self.assertIn(
            '<span class="admin-brand-name">Null Sector &lt;Final&gt;</span>',
            admin,
        )
        self.assertIn('/assets/admin/css/admin.css', admin)
        self.assertRegex(
            admin,
            r'/assets/admin/js/admin\.js\?v=[0-9a-f]{16}',
        )
        self.assertNotIn('/assets/player/terminal/', admin)

    def test_admin_shell_uses_task_grouped_svg_navigation_and_contextual_header(self):
        client = self.client_for_role("admin")

        response = client.get("/admin/challenges")
        body = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn('<aside class="admin-sidebar" data-admin-sidebar>', body)
        self.assertIn('<nav aria-label="Administration navigation">', body)

        group_markers = [
            '<p class="admin-nav-label">Monitor</p>',
            '<p class="admin-nav-label">Competition</p>',
            '<p class="admin-nav-label">System</p>',
        ]
        group_positions = [body.index(marker) for marker in group_markers]
        self.assertEqual(group_positions, sorted(group_positions))

        for icon in (
            "home",
            "check",
            "clock",
            "flag",
            "user",
            "team",
            "server",
            "settings",
        ):
            with self.subTest(icon=icon):
                self.assertIn(f'<symbol id="admin-icon-{icon}"', body)
                self.assertIn(f'<use href="#admin-icon-{icon}"></use>', body)

        self.assertIn(
            '<div class="admin-breadcrumb"><span>Administration</span><i>/</i>'
            '<strong>Challenges</strong></div>',
            body,
        )
        self.assertIn(
            '<a class="active" href="/admin/challenges" aria-current="page">',
            body,
        )
        self.assertIn('href="/admin/session-management"', body)
        self.assertIn('href="/challenges">View portal', body)
        self.assertIn(
            'aria-label="Toggle administration navigation" aria-expanded="false" '
            'data-admin-menu',
            body,
        )

        admin_script = (
            Path(ctfzone_web.__file__).parent
            / "frontends"
            / "admin"
            / "static"
            / "js"
            / "admin.js"
        ).read_text(encoding="utf-8")
        self.assertIn('sidebar.toggleAttribute("inert", hidden)', admin_script)
        self.assertIn('sidebar.setAttribute("aria-hidden", "true")', admin_script)

    def test_setup_uses_the_standalone_admin_shell(self):
        setup_bootstrap = copy.deepcopy(BOOTSTRAP)
        setup_bootstrap["data"]["setup_required"] = True
        setup_bootstrap["data"]["authenticated"] = False
        setup_bootstrap["data"]["user"] = None
        setup_client = make_app(FakeApi(bootstrap=setup_bootstrap)).test_client()

        response = setup_client.get("/setup")
        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('class="admin-shell admin-shell-onboarding"', body)
        self.assertIn('class="admin-topbar admin-topbar-onboarding"', body)
        self.assertIn('class="admin-onboarding-brand"', body)
        self.assertIn("<h1>Initial setup</h1>", body)
        self.assertNotIn("data-admin-sidebar", body)
        self.assertNotIn("data-admin-menu", body)
        self.assertNotIn('aria-label="Administration navigation"', body)

    def test_first_boot_page_uses_admin_shell_and_lists_installed_frontends(self):
        bootstrap = copy.deepcopy(BOOTSTRAP)
        bootstrap["data"]["setup_required"] = True
        bootstrap["data"]["authenticated"] = False
        bootstrap["data"]["user"] = None
        client = make_app(FakeApi(bootstrap=bootstrap)).test_client()

        body = client.get("/setup").get_data(as_text=True)

        self.assertIn('/assets/admin/css/admin.css', body)
        self.assertNotIn('/assets/player/terminal/', body)
        self.assertIn('name="ctf_name"', body)
        self.assertIn('name="player_frontend"', body)
        self.assertIn('<option value="terminal"', body)

    def test_browser_and_service_secrets_are_required(self):
        with self.assertRaisesRegex(RuntimeError, "SECRET_KEY"):
            create_app(
                {
                    "TESTING": True,
                    "SECRET_KEY": None,
                    "BACKEND_SERVICE_TOKEN": "service-token",
                }
            )
        with self.assertRaisesRegex(RuntimeError, "BACKEND_SERVICE_TOKEN"):
            create_app(
                {
                    "TESTING": True,
                    "SECRET_KEY": "browser-signing-key",
                    "BACKEND_SERVICE_TOKEN": None,
                }
            )

    def test_challenge_board_is_server_rendered_escaped_and_within_budget(self):
        self.api.calls.clear()
        response = self.client.get("/challenges")
        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Cookie Jar", body)
        self.assertIn("<strong>the flag</strong>", body)
        self.assertNotIn("<script>bad()", body)
        self.assertIn("&lt;script&gt;bad()&lt;/script&gt;", body)
        self.assertIn(f'content="{CSRF_TOKEN}"', body)
        self.assertLessEqual(len(self.api.calls), 2)
        self.assertEqual(self.api.calls[0][1], "/api/v1/views/challenges")

    def test_private_first_boot_board_preserves_setup_shell(self):
        bootstrap = copy.deepcopy(BOOTSTRAP)
        bootstrap["data"]["setup_required"] = True
        bootstrap["data"]["authenticated"] = False
        bootstrap["data"]["user"] = None
        api = FakeApi(
            bootstrap=bootstrap,
            responses={
                "/api/v1/views/challenges": (
                    403,
                    {"success": False, "message": "Challenges are private"},
                )
            },
        )
        client = make_app(api).test_client()

        response = client.get("/challenges")
        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("This installation needs its first administrator", body)
        self.assertEqual(
            [call[1] for call in api.calls],
            ["/api/v1/views/challenges", "/api/v1/bootstrap"],
        )

    def test_challenge_files_are_same_origin_object_links_only(self):
        body = self.client.get("/challenges").get_data(as_text=True)
        self.assertIn(f'href="/downloads/{OBJECT_ID}"', body)
        self.assertIn("starter.zip", body)
        self.assertNotIn("evil.example", body)
        self.assertNotIn("legacy.txt", body)
        self.assertNotIn("/bff/files/", body)

    def test_download_authorization_redirects_only_to_configured_storage_origin(self):
        self.api.calls.clear()
        response = self.client.get(f"/downloads/{OBJECT_ID}")
        self.assertEqual(response.status_code, 303)
        self.assertEqual(
            response.headers["Location"],
            "https://files.example.test/ctfzone/challenge/"
            f"{OBJECT_ID}/starter.zip?X-Amz-Signature=test",
        )
        self.assertEqual(response.headers["Cache-Control"], "private, no-store")
        self.assertEqual(response.headers["Referrer-Policy"], "no-referrer")
        self.assertEqual(
            self.api.calls,
            [("GET", f"/api/v1/storage/objects/{OBJECT_ID}/download", SESSION_ID)],
        )

    def test_download_authorization_fails_closed_on_untrusted_or_missing_origin(self):
        path = f"/api/v1/storage/objects/{OBJECT_ID}/download"
        self.api.responses[path] = (
            200,
            {
                "success": True,
                "data": {
                    "url": "https://files.example.test.evil/download?signature=stolen"
                },
            },
        )
        response = self.client.get(f"/downloads/{OBJECT_ID}")
        self.assertEqual(response.status_code, 502)
        self.assertNotIn("Location", response.headers)

        api = FakeApi()
        app = create_app(
            {**APP_CONFIG, "API_CLIENT": api, "OBJECT_STORAGE_PUBLIC_URL": ""}
        )
        client = app.test_client()
        seed_browser_session(client)
        response = client.get(f"/downloads/{OBJECT_ID}")
        self.assertEqual(response.status_code, 502)
        self.assertNotIn("Location", response.headers)

    def test_legacy_bff_file_streaming_route_is_gone(self):
        self.assertEqual(self.client.get("/bff/files/starter.zip").status_code, 404)

    def test_challenge_fragment_makes_exactly_one_internal_call(self):
        self.api.calls.clear()
        response = self.client.get("/bff/fragments/challenges/7")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            self.api.calls,
            [("GET", "/api/v1/challenges/7", SESSION_ID)],
        )

    def test_challenge_fragment_uses_explicit_page_frontend_not_session_theme(self):
        with tempfile.TemporaryDirectory() as temporary:
            frontend_root = make_frontend_tree(
                Path(temporary), "terminal", "plain"
            )
            bootstrap = copy.deepcopy(BOOTSTRAP)
            bootstrap["data"]["site"]["player_frontend"] = "plain"
            api = FakeApi(bootstrap=bootstrap)
            client = make_app(
                api, FRONTENDS_ROOT=str(frontend_root)
            ).test_client()
            seed_browser_session(client)

            page = client.get("/challenges").get_data(as_text=True)
            self.assertIn("frontend=plain", page)
            api.calls.clear()

            fragment = client.get(
                "/bff/fragments/challenges/7?frontend=terminal"
            )
            self.assertEqual(fragment.status_code, 200)
            self.assertIn("frontend=terminal", fragment.get_data(as_text=True))
            self.assertIn(
                "template=partials/challenge_panel.html",
                fragment.get_data(as_text=True),
            )
            self.assertEqual(
                api.calls,
                [("GET", "/api/v1/challenges/7", SESSION_ID)],
            )

            api.calls.clear()
            self.assertEqual(
                client.get(
                    "/bff/fragments/challenges/7?frontend=not-installed"
                ).status_code,
                404,
            )
            self.assertEqual(api.calls, [])

    def test_api_proxy_enforces_csrf_and_keeps_the_bff_as_browser_channel(self):
        response = self.client.post(
            "/bff/api/v1/challenges/attempt",
            data=b'{"challenge_id":7,"submission":"flag"}',
            content_type="application/json",
            headers=unsafe_headers(),
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.api.browser_request[0:2], ("POST", "/api/v1/challenges/attempt"))
        self.assertEqual(self.api.calls[-1][2], SESSION_ID)

        missing = self.client.post(
            "/bff/api/v1/challenges/attempt",
            data=b"{}",
            content_type="application/json",
            headers={"Origin": "http://localhost"},
        )
        cross_site = self.client.post(
            "/bff/api/v1/challenges/attempt",
            data=b"{}",
            content_type="application/json",
            headers=unsafe_headers(origin="https://evil.example"),
        )
        self.assertEqual(missing.status_code, 403)
        self.assertEqual(cross_site.status_code, 403)

    def test_storage_upload_initiation_proxies_metadata_not_file_bytes(self):
        metadata = {
            "purpose": "challenge_asset",
            "filename": "starter.zip",
            "content_type": "application/zip",
            "size": 4096,
            "sha256": "a" * 64,
            "challenge_id": 7,
        }
        response = self.client.post(
            "/bff/api/v1/storage/uploads",
            data=json.dumps(metadata),
            content_type="application/json",
            headers=unsafe_headers(),
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            self.api.browser_request[0:2], ("POST", "/api/v1/storage/uploads")
        )
        self.assertEqual(json.loads(self.api.browser_request[2]), metadata)
        self.assertEqual(self.api.calls[-1][2], SESSION_ID)

        call_count = len(self.api.calls)
        rejected = self.client.post(
            "/bff/api/v1/storage/uploads",
            data=b"not-forwarded-file-bytes",
            content_type="multipart/form-data",
            headers=unsafe_headers(),
        )
        self.assertEqual(rejected.status_code, 415)
        self.assertEqual(len(self.api.calls), call_count)

        completed = self.client.post(
            f"/bff/api/v1/storage/objects/{OBJECT_ID}/complete",
            data=b"{}",
            content_type="application/json",
            headers=unsafe_headers(),
        )
        self.assertEqual(completed.status_code, 200)
        self.assertEqual(self.api.browser_timeout, 60.0)

    def test_portal_body_budget_covers_csv_import_but_rejects_larger_bodies(self):
        limit = 6 * 1024 * 1024
        self.assertEqual(self.app.config["MAX_CONTENT_LENGTH"], limit)

        boundary = b"ctfzone-boundary"
        multipart = (
            b"--"
            + boundary
            + b'\r\nContent-Disposition: form-data; name="file"; filename="emails.csv"'
            + b"\r\nContent-Type: text/csv\r\n\r\n"
            + b"x" * (5 * 1024 * 1024)
            + b"\r\n--"
            + boundary
            + b"--\r\n"
        )
        accepted = self.client.post(
            "/bff/api/v1/configs/registration-emails/import",
            data=multipart,
            content_type="multipart/form-data; boundary=ctfzone-boundary",
            headers=unsafe_headers(),
        )
        self.assertEqual(accepted.status_code, 200)
        self.assertEqual(
            self.api.browser_request[0:2],
            ("POST", "/api/v1/configs/registration-emails/import"),
        )
        accepted.close()

        call_count = len(self.api.calls)
        rejected = self.client.post(
            "/bff/api/v1/configs/registration-emails/import",
            data=b"x" * (limit + 1),
            content_type="application/octet-stream",
            headers=unsafe_headers(),
        )
        self.assertEqual(rejected.status_code, 413)
        self.assertEqual(len(self.api.calls), call_count)
        rejected.close()

    def test_upstream_unauthorized_clears_the_python_session(self):
        def unauthorized(incoming, path, *, session_id=None):
            return httpx.Response(
                401,
                json={"success": False, "message": "Session expired"},
                request=httpx.Request(incoming.method, f"http://api.test{path}"),
            )

        self.api.request_from_browser = unauthorized
        response = self.client.post(
            "/bff/api/v1/challenges/attempt",
            data=b"{}",
            content_type="application/json",
            headers=unsafe_headers(),
        )
        self.assertEqual(response.status_code, 401)
        with self.client.session_transaction() as browser_session:
            self.assertNotIn("rust_session_id", browser_session)
            self.assertNotIn("csrf_token", browser_session)

    def test_setup_page_is_present_but_unobtrusive_after_setup(self):
        response = self.client.get("/setup")
        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("only available on an empty", body)
        self.assertNotIn("Initialize platform</button>", body)

    def test_setup_head_is_rendered_without_becoming_an_upstream_post(self):
        response = self.client.head("/setup")
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(self.api.browser_request)

    def test_first_boot_setup_stores_server_session_and_does_not_forward_csrf(self):
        bootstrap = copy.deepcopy(BOOTSTRAP)
        bootstrap["data"]["setup_required"] = True
        bootstrap["data"]["authenticated"] = False
        bootstrap["data"]["user"] = None
        api = FakeApi(bootstrap=bootstrap)
        client = make_app(api).test_client()
        seed_browser_session(client, authenticated=False)

        page = client.get("/setup")
        body = page.get_data(as_text=True)
        self.assertEqual(page.status_code, 200)
        self.assertIn("SETUP_TOKEN", body)
        self.assertIn('name="setup_token" type="password"', body)

        response = client.post(
            "/setup",
            data={
                "_csrf_token": CSRF_TOKEN,
                "setup_token": "bootstrap-secret",
                "name": "first-admin",
                "email": "admin@example.test",
                "password": "correct horse battery staple",
                "ctf_name": "Example Invitational",
                "player_frontend": "terminal",
            },
            headers=unsafe_headers(),
        )
        self.assertEqual(response.status_code, 303)
        self.assertEqual(urlsplit(response.headers["Location"]).path, "/admin")
        self.assertNotIn(SESSION_ID, response.get_data(as_text=True))
        self.assertIn("HttpOnly", response.headers["Set-Cookie"])
        self.assertIn("SameSite=Lax", response.headers["Set-Cookie"])
        submitted = parse_qs(api.browser_request[2].decode())
        self.assertEqual(submitted["setup_token"], ["bootstrap-secret"])
        self.assertEqual(submitted["ctf_name"], ["Example Invitational"])
        self.assertEqual(submitted["player_frontend"], ["terminal"])
        self.assertNotIn("_csrf_token", submitted)
        with client.session_transaction() as browser_session:
            self.assertEqual(browser_session["rust_session_id"], SESSION_ID)
            self.assertNotEqual(browser_session["csrf_token"], CSRF_TOKEN)

    def test_setup_and_config_proxy_reject_unknown_player_frontends_locally(self):
        bootstrap = copy.deepcopy(BOOTSTRAP)
        bootstrap["data"]["setup_required"] = True
        bootstrap["data"]["authenticated"] = False
        bootstrap["data"]["user"] = None
        setup_api = FakeApi(bootstrap=bootstrap)
        setup_client = make_app(setup_api).test_client()
        seed_browser_session(setup_client, authenticated=False)

        response = setup_client.post(
            "/setup",
            data={
                "_csrf_token": CSRF_TOKEN,
                "setup_token": "bootstrap-secret",
                "name": "first-admin",
                "email": "admin@example.test",
                "password": "correct horse battery staple",
                "player_frontend": "../../admin",
            },
            headers=unsafe_headers(),
        )
        self.assertEqual(response.status_code, 303)
        self.assertIn("unknown_player_frontend", response.headers["Location"])
        self.assertIsNone(setup_api.browser_request)

        for method, path, payload in (
            ("PATCH", "/bff/api/v1/configs/player_frontend", {"value": "unknown"}),
            ("PATCH", "/bff/api/v1/configs", {"player_frontend": "../terminal"}),
            (
                "POST",
                "/bff/api/v1/configs",
                {"key": "player_frontend", "value": "not-installed"},
            ),
        ):
            with self.subTest(method=method, path=path, payload=payload):
                self.api.browser_request = None
                response = self.client.open(
                    path,
                    method=method,
                    data=json.dumps(payload),
                    content_type="application/json",
                    headers=unsafe_headers(),
                )
                self.assertEqual(response.status_code, 400)
                self.assertEqual(response.get_json()["message"], "Unknown player frontend")
                self.assertIsNone(self.api.browser_request)

        accepted = self.client.patch(
            "/bff/api/v1/configs/player_frontend",
            data=json.dumps({"value": "terminal"}),
            content_type="application/json",
            headers=unsafe_headers(),
        )
        self.assertEqual(accepted.status_code, 200)
        self.assertEqual(
            self.api.browser_request[0:2],
            ("PATCH", "/api/v1/configs/player_frontend"),
        )

    def test_admin_redirects_unauthenticated_users_to_login(self):
        response = self.client_for_role(None).get("/admin")
        self.assertEqual(response.status_code, 302)
        location = urlsplit(response.headers["Location"])
        self.assertEqual(location.path, "/login")
        self.assertFalse(location.query)

        response = self.client_for_role(None).get(
            "/admin/config?section=frontends"
        )
        location = urlsplit(response.headers["Location"])
        self.assertEqual(location.path, "/login")
        self.assertFalse(location.query)

    def test_legacy_admin_login_redirects_to_the_shared_login(self):
        client = self.client_for_role(None)
        response = client.get("/admin/login?next=/admin/config")
        self.assertEqual(response.status_code, 302)
        location = urlsplit(response.headers["Location"])
        self.assertEqual(location.path, "/login")
        self.assertFalse(location.query)

    def test_shared_login_posts_to_rust_contract(self):
        client = self.client_for_role(None)
        response = client.post(
            "/login",
            data={
                "_csrf_token": CSRF_TOKEN,
                "name": "operator",
                "password": "correct horse battery staple",
            },
            headers=unsafe_headers(),
        )
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["Location"], "/challenges")
        method, target, content = client.fake_api.browser_request
        self.assertEqual(method, "POST")
        self.assertEqual(target, "/login")
        submitted = parse_qs(content.decode())
        self.assertEqual(submitted["name"], ["operator"])
        self.assertNotIn("_csrf_token", submitted)

    def test_shared_login_uses_the_selected_player_frontend(self):
        client = self.client_for_role(None)
        body = client.get("/login").get_data(as_text=True)
        self.assertIn("ACCOUNT LOGIN", body)
        self.assertIn("/assets/player/terminal/css/player.css", body)
        self.assertNotIn("/assets/admin/css/admin.css", body)

    def test_email_confirmation_keeps_fragment_token_out_of_get_and_posts_json(self):
        token = "verification-secret-that-must-not-be-rendered"
        self.api.calls.clear()

        page = self.client.get("/confirm")
        body = page.get_data(as_text=True)
        self.assertEqual(page.status_code, 200)
        self.assertNotIn(token, body)
        self.assertIn('name="token" value="" disabled', body)
        self.assertIn("/assets/player/terminal/js/confirm.js", body)
        self.assertEqual(
            self.api.calls,
            [("GET", "/api/v1/bootstrap", SESSION_ID)],
        )

        confirmed = self.client.post(
            "/confirm",
            data={"_csrf_token": CSRF_TOKEN, "token": token},
            headers=unsafe_headers(),
        )
        confirmed_body = confirmed.get_data(as_text=True)
        self.assertEqual(confirmed.status_code, 200)
        self.assertIn("Your email address is verified", confirmed_body)
        self.assertNotIn(token, confirmed_body)
        self.assertEqual(
            self.api.browser_request[0:2],
            ("POST", "/api/v1/email-verifications/confirm"),
        )
        self.assertEqual(
            self.api.calls[-1],
            ("POST", "/api/v1/email-verifications/confirm", None),
        )
        self.assertEqual(json.loads(self.api.browser_request[2]), {"token": token})

        source = (
            Path(ctfzone_web.__file__).parent
            / "frontends"
            / "player"
            / "terminal"
            / "static"
            / "js"
            / "confirm.js"
        ).read_text(encoding="utf-8")
        self.assertIn("window.location.hash", source)
        self.assertIn("window.history.replaceState", source)
        self.assertNotIn("console.", source)

    def test_admin_rejects_authenticated_non_admin_users(self):
        response = self.client_for_role("user").get("/admin")
        self.assertEqual(response.status_code, 403)
        self.assertIn("Administrator access is required", response.get_data(as_text=True))

    def test_admin_overview_is_aggregated_and_within_budget(self):
        client = self.client_for_role("admin")
        client.fake_api.calls.clear()
        overview = client.get("/admin")
        body = overview.get_data(as_text=True)
        self.assertEqual(overview.status_code, 200)
        self.assertIn("Overview", body)
        self.assertIn('href="/admin/challenges"', body)
        self.assertLessEqual(len(client.fake_api.calls), 2)
        self.assertEqual(
            [call[1] for call in client.fake_api.calls],
            ["/api/v1/bootstrap", "/api/v1/views/admin/overview"],
        )

    def test_admin_challenge_list_renders_for_admins(self):
        client = self.client_for_role("admin")
        response = client.get("/admin/challenges")
        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Cookie Jar", body)
        self.assertIn('href="/admin/challenges/7"', body)

    def test_admin_user_list_and_editor_expose_only_supported_account_controls(self):
        client = self.client_for_role("admin")
        client.fake_api.calls.clear()

        listing = client.get("/admin/users")
        listing_body = listing.get_data(as_text=True)
        self.assertEqual(listing.status_code, 200)
        self.assertIn("operator@example.test", listing_body)
        self.assertIn('href="/admin/users/1"', listing_body)
        self.assertIn("Verified", listing_body)
        self.assertIn('placeholder="Search all users…"', listing_body)
        self.assertIn('placeholder="Filter this page…"', listing_body)
        self.assertIn("Page 1 of 1", listing_body)
        self.assertEqual(
            [call[1] for call in client.fake_api.calls],
            ["/api/v1/bootstrap", "/api/v1/users?view=admin&per_page=50&page=1"],
        )

        client.fake_api.calls.clear()
        editor = client.get("/admin/users/1")
        editor_body = editor.get_data(as_text=True)
        self.assertEqual(editor.status_code, 200)
        self.assertIn('data-user-form data-user-id="1"', editor_body)
        self.assertIn('class="admin-form admin-user-form"', editor_body)
        self.assertEqual(editor_body.count('class="admin-panel admin-user-card"'), 1)
        self.assertEqual(editor_body.count('class="admin-user-card-section'), 1)
        self.assertNotIn('class="admin-panel admin-form-section"', editor_body)
        self.assertIn('<select name="type" aria-describedby="user-role-help">', editor_body)
        self.assertIn('name="hidden" type="checkbox"', editor_body)
        self.assertIn("Account identity is read-only", editor_body)
        self.assertNotIn("Email verification", editor_body)
        self.assertNotIn("Send verification email", editor_body)
        self.assertNotIn('name="verified"', editor_body)
        self.assertEqual(
            [call[1] for call in client.fake_api.calls],
            ["/api/v1/bootstrap", "/api/v1/users/1?view=admin"],
        )

        source = (
            Path(ctfzone_web.__file__).parent
            / "frontends"
            / "admin"
            / "static"
            / "js"
            / "admin.js"
        ).read_text(encoding="utf-8")
        self.assertIn("body: { type: role.value, hidden: hidden.checked }", source)
        self.assertNotIn("data-send-verification", source)
        self.assertNotIn("/verification-email", source)
        self.assertIn("Changing this role revokes", source)
        self.assertIn('currentAdminChanged ? "/login" : "/admin/users"', source)

    def test_admin_user_directory_search_and_pagination_use_one_collection_read(self):
        client = self.client_for_role("admin")
        api_path = (
            "/api/v1/users?view=admin&per_page=50&page=2"
            "&q=alice%40example.test&field=email"
        )
        client.fake_api.responses[api_path] = (
            200,
            {
                "success": True,
                "meta": {
                    "pagination": {
                        "page": 2,
                        "next": 3,
                        "prev": 1,
                        "pages": 3,
                        "per_page": 50,
                        "total": 101,
                    }
                },
                "data": [
                    {
                        "id": 51,
                        "name": "alice",
                        "email": "alice@example.test",
                        "type": "user",
                        "hidden": False,
                        "verified": False,
                    }
                ],
            },
        )
        client.fake_api.calls.clear()

        response = client.get(
            "/admin/users?field=email&q=alice%40example.test&page=2"
        )
        body = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn('value="alice@example.test"', body)
        self.assertRegex(body, r'<option value="email" selected>Email</option>')
        self.assertIn("alice@example.test", body)
        self.assertIn("101 total", body)
        self.assertIn("Page 2 of 3", body)
        self.assertIn("page=1&amp;q=alice@example.test&amp;field=email", body)
        self.assertIn("page=3&amp;q=alice@example.test&amp;field=email", body)
        self.assertIn('data-admin-table-search', body)
        self.assertEqual(
            [call[1] for call in client.fake_api.calls],
            ["/api/v1/bootstrap", api_path],
        )

    def test_admin_config_has_a_registry_backed_player_frontend_selector(self):
        bootstrap = copy.deepcopy(BOOTSTRAP)
        bootstrap["data"]["user"]["type"] = "admin"
        api = FakeApi(
            bootstrap=bootstrap,
            responses={
                "/api/v1/views/admin/configuration": (
                    200,
                    {
                        "success": True,
                        "data": {
                            "sections": [
                                {
                                    "id": "site",
                                    "title": "Site and interface",
                                    "description": "Public identity and presentation.",
                                    "settings": [
                                        {
                                            "key": "ctf_name",
                                            "label": "Event name",
                                            "type": "string",
                                            "value": "CTFZone",
                                            "required": True,
                                        },
                                        {
                                            "key": "ctf_description",
                                            "label": "Description",
                                            "help": "Short event description shown by player frontends.",
                                            "type": "text",
                                            "value": "Example event",
                                        },
                                        {
                                            "key": "player_frontend",
                                            "label": "Player frontend",
                                            "type": "select",
                                            "value": "terminal",
                                        },
                                    ],
                                }
                            ],
                            "registration_emails": [],
                            "export_tables": [],
                        },
                    },
                )
            },
        )
        client = make_app(api).test_client()
        seed_browser_session(client)

        body = client.get("/admin/config").get_data(as_text=True)

        self.assertIn('data-config-key="player_frontend"', body)
        self.assertIn('value="terminal"', body)
        self.assertEqual(body.count('data-config-key="player_frontend"'), 2)
        self.assertIn('data-config-key="ctf_name"', body)
        self.assertIn('data-config-key="ctf_description"', body)
        self.assertIn("Short event description shown by player frontends.", body)
        self.assertNotIn("<code>ctf_name</code>", body)
        self.assertNotIn("<code>ctf_description</code>", body)
        admin_css = (
            Path(ctfzone_web.__file__).parent
            / "frontends"
            / "admin"
            / "static"
            / "css"
            / "admin.css"
        ).read_text(encoding="utf-8")
        self.assertIn("scrollbar-gutter: stable", admin_css)
        self.assertEqual(
            [call[1] for call in api.calls],
            ["/api/v1/bootstrap", "/api/v1/views/admin/configuration"],
        )

    def test_admin_configuration_chips_expose_default_accessible_state_and_hooks(self):
        bootstrap = copy.deepcopy(BOOTSTRAP)
        bootstrap["data"]["user"]["type"] = "admin"
        api = FakeApi(
            bootstrap=bootstrap,
            responses={
                "/api/v1/views/admin/configuration": (
                    200,
                    {
                        "success": True,
                        "data": {
                            "sections": [
                                {
                                    "id": "site",
                                    "title": "Site and interface",
                                    "settings": [
                                        {
                                            "key": "ctf_name",
                                            "label": "Event name",
                                            "type": "string",
                                            "effective": "CTFZone",
                                        }
                                    ],
                                },
                                {
                                    "id": "schedule",
                                    "title": "Schedule",
                                    "settings": [
                                        {
                                            "key": "paused",
                                            "label": "Paused",
                                            "type": "boolean",
                                            "effective": False,
                                        }
                                    ],
                                },
                                {
                                    "id": "registration",
                                    "title": "Registration access",
                                    "description": "Choose who may create an account.",
                                    "settings": [
                                        {
                                            "key": "registration_access_mode",
                                            "label": "Registration access",
                                            "help": "Choose one exclusive access policy.",
                                            "type": "select",
                                            "effective": "email_allowlist",
                                            "required": True,
                                            "options": [
                                                {"value": "open", "label": "Open"},
                                                {"value": "domain_rules", "label": "Domain rules"},
                                                {"value": "access_code", "label": "Access code"},
                                                {"value": "email_allowlist", "label": "Email allowlist"},
                                            ],
                                        },
                                        {
                                            "key": "registration_code",
                                            "label": "Registration code",
                                            "type": "secret",
                                            "sensitive": True,
                                            "configured": True,
                                            "depends_on": {
                                                "key": "registration_access_mode",
                                                "values": ["access_code"],
                                            },
                                        },
                                        {
                                            "key": "domain_whitelist",
                                            "label": "Allowed domains",
                                            "type": "text",
                                            "effective": "example.test",
                                            "depends_on": {
                                                "key": "registration_access_mode",
                                                "values": ["domain_rules"],
                                            },
                                        },
                                    ],
                                },
                                {
                                    "id": "accounts",
                                    "title": "Accounts",
                                    "description": "Participant account and competition policies.",
                                    "settings": [
                                        {
                                            "key": "user_mode",
                                            "label": "Competition mode",
                                            "type": "select",
                                            "effective": "users",
                                            "options": [
                                                {"value": "users", "label": "Individual users"},
                                                {"value": "teams", "label": "Teams"},
                                            ],
                                        },
                                        {
                                            "key": "password_min_length",
                                            "label": "Minimum password length",
                                            "type": "integer",
                                            "effective": 12,
                                        },
                                        {
                                            "key": "name_changes",
                                            "label": "Allow name changes",
                                            "type": "boolean",
                                            "effective": True,
                                        },
                                        {
                                            "key": "verify_emails",
                                            "label": "Require verified email",
                                            "type": "boolean",
                                            "effective": False,
                                        },
                                    ],
                                },
                            ],
                            "registration_emails": [
                                {"id": 7, "email": "invited@example.test", "registered": False}
                            ],
                        },
                    },
                )
            },
        )
        client = make_app(api).test_client()
        seed_browser_session(client)

        response = client.get("/admin/config")
        body = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn(
            '<nav class="config-index" aria-label="Configuration sections" '
            "data-config-tabs>",
            body,
        )
        self.assertRegex(
            body,
            r'<button type="button" data-config-tab="all" aria-pressed="false">'
            r'All sections</button>',
        )
        self.assertRegex(
            body,
            r'<button type="button" data-config-tab="site" '
            r'aria-controls="config-site" aria-pressed="true">Site and interface</button>',
        )
        self.assertRegex(
            body,
            r'<button type="button" data-config-tab="schedule" '
            r'aria-controls="config-schedule" aria-pressed="false">Schedule</button>',
        )
        self.assertNotIn('data-config-tab="allowlist"', body)
        self.assertIn(
            'id="config-site" data-config-panel="site">',
            body,
        )
        self.assertIn(
            'id="config-schedule" data-config-panel="schedule">',
            body,
        )
        self.assertIn(
            'class="config-panel-stack admin-panel registration-panel-stack" id="config-registration" data-config-panel="registration">',
            body,
        )
        self.assertIn(
            'id="config-accounts" data-config-panel="accounts">',
            body,
        )
        self.assertIn('data-config-section-id="registration"', body)
        self.assertIn('data-config-section-id="accounts"', body)
        self.assertIn('id="registration-allowlist"', body)
        self.assertIn("data-registration-allowlist", body)
        self.assertIn('data-depends-key="registration_access_mode"', body)
        self.assertIn('data-depends-values="[&quot;email_allowlist&quot;]"', body)
        self.assertIn("Switching policies keeps these invitations.", body)
        self.assertIn("data-conditional-fieldset", body)
        self.assertLess(
            body.index('id="config-registration"'),
            body.index('id="registration-allowlist"'),
        )
        registration_start = body.index('id="config-registration"')
        self.assertIn(
            '<form class="config-section" data-config-section data-config-section-id="registration">',
            body[registration_start:],
        )
        self.assertLess(
            body.index("</form>", registration_start),
            body.index('id="registration-allowlist"'),
        )
        self.assertLess(
            body.index('id="registration-allowlist"'),
            body.index('id="config-accounts"'),
        )
        registration_end = body.index("</form>", registration_start)
        accounts_start = body.index('id="config-accounts"')
        self.assertNotIn('data-config-key="password_min_length"', body[registration_start:registration_end])
        self.assertIn('data-config-key="password_min_length"', body[accounts_start:])
        self.assertIn('data-config-key="name_changes"', body[accounts_start:])
        for mode in ("open", "domain_rules", "access_code", "email_allowlist"):
            self.assertIn(f'data-registration-policy="{mode}"', body)
        self.assertIn(
            "Changing policy does not erase the saved code, domain rules, or email invitations.",
            body,
        )
        self.assertIn("All policy editors are shown because JavaScript is unavailable.", body)
        self.assertIn("invited@example.test", body)

        script = (
            Path(ctfzone_web.__file__).parent
            / "frontends"
            / "admin"
            / "static"
            / "js"
            / "admin.js"
        ).read_text(encoding="utf-8")
        self.assertIn(
            'button.setAttribute("aria-pressed", String(active))', script
        )
        self.assertIn(
            'button.setAttribute("aria-current", "true")', script
        )
        self.assertIn("panel.hidden = !selected || !matchesSearch", script)
        self.assertIn('document.querySelectorAll("[data-depends-key]")', script)
        self.assertIn('fieldset.disabled = !visible', script)
        self.assertIn('entry.classList.toggle("search-reveal"', script)
        self.assertIn("syncRegistrationPolicyGuide", script)
        self.assertIn("if (input.disabled || input.value", script)

        stylesheet = (
            Path(ctfzone_web.__file__).parent
            / "frontends"
            / "admin"
            / "static"
            / "css"
            / "admin.css"
        ).read_text(encoding="utf-8")
        self.assertIn(".config-panel-stack[hidden] { display: none; }", stylesheet)
        self.assertIn(
            ".config-panel-stack > .admin-panel { width: 100%; margin-bottom: 0; }",
            stylesheet,
        )
        self.assertIn(".registration-panel-stack { margin-bottom: 0; }", stylesheet)
        self.assertIn(
            ".registration-panel-stack > .allowlist-panel { border-top: 1px solid var(--border); }",
            stylesheet,
        )
        self.assertIn(".config-sections { display: grid; gap: 14px; }", stylesheet)
        self.assertIn(
            ".config-panel-stack { display: grid; width: 100%; gap: 0;",
            stylesheet,
        )
        self.assertIn(
            '.config-section[data-config-section-id="accounts"] .config-setting-list',
            stylesheet,
        )

    def test_accounts_and_registration_use_api_owned_groups_in_one_atomic_section(self):
        bootstrap = copy.deepcopy(BOOTSTRAP)
        bootstrap["data"]["user"]["type"] = "admin"
        groups = [
            {
                "id": "account_type",
                "title": "Account type",
                "description": "Choose the event participant model.",
            },
            {
                "id": "participant_accounts",
                "title": "Participant accounts",
                "description": "Policies shared by both account models.",
            },
            {
                "id": "team_accounts",
                "title": "Team accounts",
                "description": "Policies used only for team competition.",
            },
            {
                "id": "registration_access",
                "title": "Registration access",
                "description": "Choose how participant accounts are admitted.",
            },
        ]

        def setting(key, group, field_type="integer", effective=0, **extra):
            return {
                "key": key,
                "label": key.replace("_", " ").title(),
                "type": field_type,
                "effective": effective,
                "group": next(value for value in groups if value["id"] == group),
                **extra,
            }

        settings = [
            setting(
                "user_mode",
                "account_type",
                "select",
                "users",
                required=True,
                options=[
                    {"value": "users", "label": "Individual users"},
                    {"value": "teams", "label": "Teams"},
                ],
            ),
            setting("num_users", "participant_accounts"),
            setting("password_min_length", "participant_accounts", effective=12),
            setting("name_changes", "participant_accounts", "boolean", True),
            setting("verify_emails", "participant_accounts", "boolean", False),
            setting(
                "team_creation",
                "team_accounts",
                "boolean",
                True,
                depends_on={"key": "user_mode", "values": ["teams"]},
            ),
            setting(
                "team_size",
                "team_accounts",
                depends_on={"key": "user_mode", "values": ["teams"]},
            ),
            setting(
                "num_teams",
                "team_accounts",
                depends_on={"key": "user_mode", "values": ["teams"]},
            ),
            setting(
                "team_disbanding",
                "team_accounts",
                "select",
                "inactive_only",
                options=[{"value": "inactive_only", "label": "Inactive only"}],
                depends_on={"key": "user_mode", "values": ["teams"]},
            ),
            setting("registration_visibility", "registration_access", "select", "public"),
            setting(
                "registration_access_mode",
                "registration_access",
                "select",
                "email_allowlist",
                required=True,
                options=[
                    {"value": "open", "label": "Open"},
                    {"value": "email_allowlist", "label": "Email allowlist"},
                ],
            ),
            setting(
                "registration_code",
                "registration_access",
                "secret",
                None,
                sensitive=True,
                configured=True,
                depends_on={"key": "registration_access_mode", "values": ["access_code"]},
            ),
        ]
        api = FakeApi(
            bootstrap=bootstrap,
            responses={
                "/api/v1/views/admin/configuration": (
                    200,
                    {
                        "success": True,
                        "data": {
                            "sections": [
                                {
                                    "id": "accounts",
                                    "title": "Accounts & registration",
                                    "description": "Participant accounts and admission.",
                                    "groups": groups,
                                    "settings": settings,
                                }
                            ],
                            "registration_emails": [],
                        },
                    },
                )
            },
        )
        client = make_app(api).test_client()
        seed_browser_session(client)

        body = client.get("/admin/config").get_data(as_text=True)

        self.assertIn('data-config-tab="accounts"', body)
        self.assertNotIn('data-config-tab="registration"', body)
        self.assertEqual(body.count("data-config-section data-config-section-id="), 1)
        group_positions = [body.index(f'data-config-group="{group["id"]}"') for group in groups]
        self.assertEqual(group_positions, sorted(group_positions))
        self.assertLess(body.index('data-config-key="user_mode"'), body.index('data-config-key="num_users"'))
        self.assertLess(body.index('data-config-key="team_creation"'), body.index('data-config-key="registration_visibility"'))
        team_group = body[body.index('data-config-group="team_accounts"'):]
        self.assertIn('data-depends-key="user_mode"', team_group)
        self.assertIn('data-depends-values="[&#34;teams&#34;]"', team_group)
        form_start = body.index('<form class="config-section"')
        form_end = body.index("</form>", form_start)
        allowlist_start = body.index('id="registration-allowlist"')
        self.assertLess(form_end, allowlist_start)
        self.assertNotIn("<form", body[form_start + 1:form_end])
        self.assertLess(body.index('data-config-key="registration_access_mode"'), allowlist_start)

        script = (
            Path(ctfzone_web.__file__).parent
            / "frontends"
            / "admin"
            / "static"
            / "js"
            / "admin.js"
        ).read_text(encoding="utf-8")
        self.assertIn('["registration", "accounts"]', script)
        self.assertIn('document.querySelectorAll("[data-config-group]")', script)

    def test_admin_configuration_preserves_types_dependencies_and_secrets(self):
        bootstrap = copy.deepcopy(BOOTSTRAP)
        bootstrap["data"]["user"]["type"] = "admin"
        api = FakeApi(
            bootstrap=bootstrap,
            responses={
                "/api/v1/views/admin/configuration": (
                    200,
                    {
                        "success": True,
                        "data": {
                            "sections": [
                                {
                                    "id": "schedule",
                                    "title": "Schedule",
                                    "settings": [
                                        {"key": "start", "label": "Start", "type": "datetime", "effective": 1_800_000_000},
                                        {"key": "paused", "label": "Paused", "type": "boolean", "effective": True},
                                        {"key": "num_users", "label": "Maximum users", "type": "integer", "effective": 250},
                                    ],
                                },
                                {
                                    "id": "mail",
                                    "title": "Email",
                                    "settings": [
                                        {"key": "verify_emails", "label": "Require verified email", "type": "boolean", "effective": False},
                                        {"key": "mail_server", "label": "SMTP server", "type": "string", "effective": "smtp.example.test"},
                                        {
                                            "key": "mail_password",
                                            "label": "SMTP password",
                                            "type": "secret",
                                            "sensitive": True,
                                            "configured": True,
                                            "value": "must-never-render",
                                            "depends_on": {"key": "mail_server", "values": ["configured"]},
                                        },
                                    ],
                                },
                                {
                                    "id": "registration",
                                    "title": "Registration & accounts",
                                    "settings": [{
                                        "key": "registration_access_mode",
                                        "label": "Registration access",
                                        "type": "select",
                                        "effective": "email_allowlist",
                                        "required": True,
                                        "options": [
                                            {"value": "open", "label": "Open"},
                                            {"value": "domain_rules", "label": "Domain rules"},
                                            {"value": "access_code", "label": "Access code"},
                                            {"value": "email_allowlist", "label": "Email allowlist"},
                                        ],
                                    }],
                                },
                            ],
                            "registration_emails": [
                                {"id": 7, "email": "allowed@example.test", "registered": False}
                            ],
                        },
                    },
                )
            },
        )
        client = make_app(api).test_client()
        seed_browser_session(client)

        body = client.get("/admin/config").get_data(as_text=True)

        self.assertIn('type="datetime-local" value="2027-01-15T08:00"', body)
        self.assertIn('data-value-type="boolean"', body)
        self.assertIn('data-value-type="integer"', body)
        self.assertIn('data-secret-control data-config-key="mail_password"', body)
        self.assertIn('data-depends-values="[&#34;configured&#34;]"', body)
        self.assertIn('data-config-key="verify_emails"', body)
        self.assertIn(
            "Every signed-in account can request its verification link from Profile.",
            body,
        )
        self.assertNotIn("confirmation delivery flow is implemented", body)
        self.assertNotIn("must-never-render", body)
        self.assertIn("allowed@example.test", body)

        script = (
            Path(ctfzone_web.__file__).parent
            / "frontends"
            / "admin"
            / "static"
            / "js"
            / "admin.js"
        ).read_text(encoding="utf-8")
        self.assertIn('await apiRequest("/api/v1/configs", { method: "PATCH", body: payload })', script)
        self.assertIn('payload[secret.dataset.configKey] = null', script)
        self.assertIn('action.value === "keep"', script)
        self.assertIn('Math.floor(milliseconds / 1000)', script)
        self.assertIn("date.getFullYear()", script)
        self.assertIn("date.getHours()", script)
        self.assertIn('/api/v1/configs/registration-emails?${parameters}', script)
        self.assertNotIn('input.dataset.configKey === "verify_emails"', script)

    def test_stale_player_frontend_uses_installed_fallback_in_configuration(self):
        bootstrap = copy.deepcopy(BOOTSTRAP)
        bootstrap["data"]["user"]["type"] = "admin"
        api = FakeApi(
            bootstrap=bootstrap,
            responses={
                "/api/v1/views/admin/configuration": (
                    200,
                    {
                        "success": True,
                        "data": {
                            "sections": [{
                                "id": "site",
                                "title": "Site",
                                "settings": [{
                                    "key": "player_frontend",
                                    "label": "Player frontend",
                                    "type": "select",
                                    "effective": "removed-theme",
                                }],
                            }],
                            "registration_emails": [],
                        },
                    },
                )
            },
        )
        client = make_app(api).test_client()
        seed_browser_session(client)
        body = client.get("/admin/config").get_data(as_text=True)
        self.assertIn('data-force-dirty="true"', body)
        self.assertIn('value="terminal" selected', body)
        self.assertIn("not installed", body)
        script = (
            Path(ctfzone_web.__file__).parent
            / "frontends"
            / "admin"
            / "static"
            / "js"
            / "admin.js"
        ).read_text(encoding="utf-8")
        self.assertIn('input.dataset.forceDirty === "true"', script)
        self.assertIn("delete input.dataset.forceDirty", script)

    def test_configuration_caps_legacy_unbounded_allowlist_previews(self):
        bootstrap = copy.deepcopy(BOOTSTRAP)
        bootstrap["data"]["user"]["type"] = "admin"
        entries = [
            {"id": index, "email": f"user{index}@example.test", "registered": False}
            for index in range(1, 252)
        ]
        api = FakeApi(
            bootstrap=bootstrap,
            responses={
                "/api/v1/views/admin/configuration": (
                    200,
                    {
                        "success": True,
                        "data": {
                            "sections": [{
                                "id": "registration",
                                "title": "Registration & accounts",
                                "settings": [{
                                    "key": "registration_access_mode",
                                    "label": "Registration access",
                                    "type": "select",
                                    "effective": "email_allowlist",
                                    "required": True,
                                    "options": [
                                        {"value": "open", "label": "Open"},
                                        {"value": "email_allowlist", "label": "Email allowlist"},
                                    ],
                                }],
                            }],
                            "registration_emails": entries,
                        },
                    },
                )
            },
        )
        client = make_app(api).test_client()
        seed_browser_session(client)
        body = client.get("/admin/config").get_data(as_text=True)
        self.assertIn('data-allowlist-total="251"', body)
        self.assertEqual(body.count("data-allowlist-entry="), 200)
        self.assertIn("Search or paginate", body)

    def test_admin_challenge_form_uses_direct_storage_upload_helper(self):
        client = self.client_for_role("admin")
        body = client.get("/admin/challenges/new").get_data(as_text=True)
        self.assertIn('meta name="object-storage-origin"', body)
        self.assertIn('type="file" multiple data-challenge-files', body)
        self.assertIn("uploaded directly", body)

        source = (
            Path(ctfzone_web.__file__).parent
            / "frontends"
            / "shared"
            / "static"
            / "js"
            / "storage.js"
        ).read_text(encoding="utf-8")
        self.assertIn('credentials: "omit"', source)
        self.assertIn('redirect: "error"', source)
        self.assertIn("/api/v1/storage/uploads", source)
        self.assertIn('subtle.digest("SHA-256", await file.arrayBuffer())', source)
        self.assertIn("sha256: checksum.hex", source)
        self.assertIn('"x-amz-checksum-sha256"', source)
        self.assertIn("64 * 1024 * 1024", source)
        self.assertNotIn('startsWith("x-amz-")', source)
        self.assertNotIn("FormData", source)

    def test_unknown_legacy_admin_path_uses_placeholder_shell(self):
        response = self.client_for_role("admin").get("/admin/plugins/example")
        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Plugins / Example", body)
        self.assertIn('href="/admin"', body)

    def test_admin_modules_have_a_renderable_minimum_surface(self):
        client = self.client_for_role("admin")
        for path in (
            "/admin/challenges/new",
            "/admin/challenges/7",
            "/admin/config",
            "/admin/runtime",
            "/admin/users",
            "/admin/users/1",
            "/admin/teams",
            "/admin/submissions",
            "/admin/session-management",
        ):
            with self.subTest(path=path):
                response = client.get(path)
                body = response.get_data(as_text=True)
                self.assertEqual(response.status_code, 200)
                self.assertIn('<aside class="admin-sidebar" data-admin-sidebar>', body)
                self.assertIn('id="main-content"', body)
                self.assertIn('/assets/admin/css/admin.css', body)

    def test_admin_sessions_render_individual_account_and_global_revocation_controls(self):
        bootstrap = copy.deepcopy(BOOTSTRAP)
        bootstrap["data"]["user"]["type"] = "admin"
        session_payload = {
            "success": True,
            "data": {
                "user": {"id": 1, "name": "operator", "email": "operator@example.test"},
                "range": {
                    "start": "2026-08-12T10:00:00Z",
                    "end": "2026-08-12T11:00:00Z",
                },
                "sessions": [
                    {
                        "management_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                        "fingerprint": "00000000-000",
                        "last_seen": "2026-08-12T10:59:00Z",
                        "last_ip": "192.0.2.10",
                        "revoked_at": None,
                        "active": True,
                        "current": True,
                    },
                    {
                        "management_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                        "fingerprint": "11111111-111",
                        "last_seen": "2026-08-12T10:30:00Z",
                        "last_ip": "192.0.2.11",
                        "revoked_at": "2026-08-12T10:31:00Z",
                        "active": False,
                        "current": False,
                    },
                ],
                "activities": [
                    {
                        "method": "GET",
                        "endpoint": "/api/v1/challenges",
                        "status_code": 200,
                        "ip": "192.0.2.10",
                        "date": "2026-08-12T10:59:00Z",
                    }
                ],
            },
        }
        api = FakeApi(
            bootstrap=bootstrap,
            responses={
                "/api/v1/sessions/users?q=": (
                    200,
                    {"success": True, "data": [{"id": 1, "name": "operator"}]},
                ),
                "/api/v1/sessions?user_id=1": (200, session_payload),
            },
        )
        client = make_app(api).test_client()
        seed_browser_session(client)

        unselected_body = client.get("/admin/session-management").get_data(as_text=True)
        self.assertIn("data-revoke-all-sessions", unselected_body)

        body = client.get("/admin/session-management?user_id=1").get_data(as_text=True)

        self.assertIn("data-revoke-all-sessions", body)
        self.assertIn("Terminate all user sessions", body)
        self.assertIn('data-revoke-user-sessions="1"', body)
        self.assertIn("Terminate this user’s sessions", body)
        self.assertEqual(body.count('data-revoke-session="'), 1)
        self.assertIn(
            'data-revoke-session="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"', body
        )
        self.assertNotIn(
            'data-revoke-session="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"', body
        )
        self.assertIn("Recent Rust API activity", body)
        self.assertIn("/api/v1/challenges", body)

        source = (
            Path(ctfzone_web.__file__).parent
            / "frontends"
            / "admin"
            / "static"
            / "js"
            / "admin.js"
        ).read_text(encoding="utf-8")
        self.assertIn("/api/v1/sessions/${encodeURIComponent", source)
        self.assertIn("/api/v1/sessions/users/${encodeURIComponent", source)
        self.assertIn('apiRequest("/api/v1/sessions/revoke"', source)
        self.assertIn("This includes your current administration session", source)
        self.assertIn('window.location.assign("/login")', source)

        legacy = client.get("/admin/sessions")
        self.assertEqual(legacy.status_code, 302)
        self.assertEqual(
            urlsplit(legacy.headers["Location"]).path,
            "/admin/session-management",
        )

    def test_immutable_setup_marker_is_not_an_editable_config(self):
        bootstrap = copy.deepcopy(BOOTSTRAP)
        bootstrap["data"]["user"]["type"] = "admin"
        api = FakeApi(
            bootstrap=bootstrap,
            responses={
                "/api/v1/views/admin/configuration": (
                    200,
                    {
                        "success": True,
                        "data": {
                            "sections": [{
                                "id": "advanced",
                                "title": "Advanced",
                                "settings": [
                                    {"key": "ctf_name", "label": "Event name", "type": "string", "value": "CTFZone"}
                                ],
                            }],
                            "registration_emails": [],
                        },
                    },
                )
            },
        )
        client = make_app(api).test_client()
        seed_browser_session(client)
        body = client.get("/admin/config").get_data(as_text=True)
        self.assertNotIn('data-config-key="setup"', body)
        self.assertIn('data-config-key="ctf_name"', body)

    def test_private_profile_is_direct_and_uses_bootstrap_account_state(self):
        self.api.calls.clear()
        profile = self.client.get("/profile")
        body = profile.get_data(as_text=True)
        self.assertEqual(profile.status_code, 200)
        self.assertIn("operator@example.test", body)
        self.assertIn("Address verified", body)
        self.assertIn("150", body)
        self.assertNotIn("Send verification email", body)
        self.assertEqual(
            self.api.calls,
            [
                ("GET", "/api/v1/bootstrap", SESSION_ID),
                ("GET", "/api/v1/users/me", SESSION_ID),
            ],
        )

        team_bootstrap = copy.deepcopy(BOOTSTRAP)
        team_bootstrap["data"]["site"]["user_mode"] = "teams"
        team_bootstrap["data"]["user"]["team_id"] = 3
        team_api = FakeApi(bootstrap=team_bootstrap)
        team_client = make_app(team_api).test_client()
        seed_browser_session(team_client)
        team_profile = team_client.get("/profile")
        self.assertEqual(team_profile.status_code, 200)
        self.assertIn("operator@example.test", team_profile.get_data(as_text=True))
        self.assertNotIn("Blue Team", team_profile.get_data(as_text=True))

    def test_unverified_user_or_admin_requests_email_from_private_profile(self):
        for role in ("user", "admin"):
            with self.subTest(role=role):
                bootstrap = copy.deepcopy(BOOTSTRAP)
                bootstrap["data"]["user"]["type"] = role
                bootstrap["data"]["user"]["verified"] = False
                api = FakeApi(bootstrap=bootstrap)
                client = make_app(api).test_client()
                seed_browser_session(client)

                body = client.get("/profile").get_data(as_text=True)
                self.assertIn("Verify your address", body)
                self.assertIn("Send verification email", body)
                self.assertIn("/assets/player/terminal/js/profile.js", body)

                sent = client.post(
                    "/bff/api/v1/users/me/verification-email",
                    headers=unsafe_headers(),
                )
                self.assertEqual(sent.status_code, 200)
                self.assertEqual(api.browser_timeout, 20.0)
                self.assertEqual(
                    api.calls[-1],
                    ("POST", "/api/v1/users/me/verification-email", SESSION_ID),
                )

        source = (
            Path(ctfzone_web.__file__).parent
            / "frontends"
            / "player"
            / "terminal"
            / "static"
            / "js"
            / "profile.js"
        ).read_text(encoding="utf-8")
        self.assertIn('apiRequest("/api/v1/users/me/verification-email"', source)
        self.assertNotIn("/api/v1/users/${", source)

    def test_public_profiles_are_available_without_private_verification_controls(self):
        user = self.client.get("/users/1")
        team = self.client.get("/teams/3")
        self.assertEqual(user.status_code, 200)
        user_body = user.get_data(as_text=True)
        self.assertIn("operator", user_body)
        self.assertNotIn("operator@example.test", user_body)
        self.assertNotIn("Send verification email", user_body)
        self.assertEqual(team.status_code, 200)
        self.assertIn("Blue Team", team.get_data(as_text=True))
        self.assertIn('href="/users/1"', team.get_data(as_text=True))

    def test_team_navigation_and_onboarding_follow_the_public_team_policy(self):
        individual_body = self.client.get("/challenges").get_data(as_text=True)
        self.assertNotIn('href="/team">Team</a>', individual_body)

        bootstrap = copy.deepcopy(BOOTSTRAP)
        bootstrap["data"]["site"].update(user_mode="teams", team_creation=True)
        api = FakeApi(bootstrap=bootstrap)
        client = make_app(api).test_client()
        seed_browser_session(client)
        body = client.get("/team").get_data(as_text=True)

        self.assertIn('href="/team">Team</a>', body)
        self.assertIn("data-team-create", body)
        self.assertIn("data-team-join", body)
        self.assertIn("/assets/player/terminal/js/team.js", body)
        self.assertEqual([call[1] for call in api.calls], ["/api/v1/bootstrap"])

        bootstrap["data"]["site"]["team_creation"] = False
        api = FakeApi(bootstrap=bootstrap)
        client = make_app(api).test_client()
        seed_browser_session(client)
        body = client.get("/team").get_data(as_text=True)
        self.assertNotIn("data-team-create", body)
        self.assertIn("data-team-join", body)

    def test_bootstrap_team_policy_normalization_fails_closed(self):
        for raw_creation, raw_size, raw_count in (
            ("true", "4", "10"),
            (1, True, False),
            (None, -1, -2),
        ):
            with self.subTest(
                team_creation=raw_creation,
                team_size=raw_size,
                num_teams=raw_count,
            ):
                bootstrap = copy.deepcopy(BOOTSTRAP)
                bootstrap["data"]["site"].update(
                    user_mode="teams",
                    team_creation=raw_creation,
                    team_size=raw_size,
                    num_teams=raw_count,
                )
                api = FakeApi(bootstrap=bootstrap)
                client = make_app(api).test_client()
                seed_browser_session(client)
                body = client.get("/team").get_data(as_text=True)
                self.assertNotIn("data-team-create", body)
                self.assertNotIn("Teams may contain up to", body)
                self.assertNotIn("This event allows up to", body)

    def test_team_page_has_admin_error_and_captain_specific_states(self):
        bootstrap = copy.deepcopy(BOOTSTRAP)
        bootstrap["data"]["site"].update(user_mode="teams", team_creation=True)
        bootstrap["data"]["user"]["type"] = "admin"
        bootstrap["data"]["user"]["team_id"] = 3
        api = FakeApi(bootstrap=bootstrap)
        client = make_app(api).test_client()
        seed_browser_session(client)
        body = client.get("/team").get_data(as_text=True)
        self.assertIn("Administrator account", body)
        self.assertIn('href="/admin/teams"', body)
        self.assertNotIn("data-team-create", body)
        self.assertNotIn("data-team-join", body)
        self.assertNotIn("data-team-invite-form", body)
        self.assertEqual([call[1] for call in api.calls], ["/api/v1/bootstrap"])

        bootstrap["data"]["user"].update(type="user", team_id=3)
        api = FakeApi(
            bootstrap=bootstrap,
            responses={
                "/api/v1/teams/me": (
                    200,
                    {
                        "success": True,
                        "data": {
                            "id": 3,
                            "name": "Blue Team",
                            "captain_id": 1,
                            "members": [{"id": 1, "name": "operator"}],
                        },
                    },
                )
            },
        )
        client = make_app(api).test_client()
        seed_browser_session(client)
        body = client.get("/team").get_data(as_text=True)
        self.assertIn("Blue Team", body)
        self.assertIn("data-team-invite-form", body)
        self.assertIn("expires after 24 hours", body)

        api = FakeApi(
            bootstrap=bootstrap,
            responses={
                "/api/v1/teams/me": (
                    503,
                    {"success": False, "message": "database unavailable"},
                )
            },
        )
        client = make_app(api).test_client()
        seed_browser_session(client)
        body = client.get("/team").get_data(as_text=True)
        self.assertIn("Team details unavailable", body)
        self.assertIn("temporarily unavailable", body)
        self.assertNotIn("data-team-create", body)
        self.assertNotIn("data-team-join", body)

        source = (
            Path(ctfzone_web.__file__).parent
            / "frontends"
            / "player"
            / "terminal"
            / "static"
            / "js"
            / "team.js"
        ).read_text(encoding="utf-8")
        self.assertIn('submitTeamAction(form, "/api/v1/teams/me"', source)
        self.assertIn('submitTeamAction(form, "/api/v1/teams/me/join"', source)
        self.assertIn('apiRequest("/api/v1/teams/me/members"', source)

    def test_team_page_prioritizes_bootstrap_unavailability_over_mode_fallback(self):
        api = FakeApi(
            responses={
                "/api/v1/bootstrap": (
                    503,
                    {"success": False, "message": "temporarily unavailable"},
                )
            }
        )
        client = make_app(api).test_client()
        body = client.get("/team").get_data(as_text=True)

        self.assertIn("Team management unavailable", body)
        self.assertNotIn("Individual competition", body)
        self.assertNotIn("data-team-create", body)
        self.assertNotIn("data-team-join", body)

    def test_runtime_action_refreshes_are_statically_bounded(self):
        source = (
            Path(ctfzone_web.__file__).parent
            / "frontends"
            / "player"
            / "terminal"
            / "static"
            / "js"
            / "challenges.js"
        ).read_text(encoding="utf-8")
        match = re.search(r"transitionRefreshDelays\s*=\s*\[([^]]*)\]", source)
        self.assertIsNotNone(match)
        delays = [value for value in match.group(1).split(",") if value.strip()]
        self.assertLessEqual(len(delays), 2)

    def test_storage_origin_is_the_only_extra_connect_source(self):
        api = FakeApi()
        app = create_app(
            {
                **APP_CONFIG,
                "API_CLIENT": api,
                "OBJECT_STORAGE_PUBLIC_URL": "https://files.example.test",
            }
        )
        response = app.test_client().get("/healthz")
        policy = response.headers["Content-Security-Policy"]
        self.assertIn("connect-src 'self' https://files.example.test", policy)
        self.assertNotIn("test-backend-service-token", response.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
