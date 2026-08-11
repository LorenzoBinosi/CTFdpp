import copy
import json
import unittest
from urllib.parse import parse_qs, urlsplit

import httpx

from ctfzone_web import create_app


BOOTSTRAP = {
    "success": True,
    "data": {
        "setup_required": False,
        "authenticated": True,
        "csrf_token": "test-nonce",
        "user": {
            "id": 1,
            "name": "operator",
            "email": "operator@example.test",
            "type": "user",
            "team_id": None,
            "verified": True,
        },
        "site": {
            "name": "CTFZone",
            "user_mode": "users",
            "registration_visibility": "public",
        },
    },
}


class FakeApi:
    def __init__(self, bootstrap=None, responses=None):
        self.browser_request = None
        self.bootstrap = copy.deepcopy(BOOTSTRAP if bootstrap is None else bootstrap)
        self.responses = {
            "/api/v1/challenges?view=admin": (
                200,
                {
                    "success": True,
                    "data": [
                        {
                            "id": 7,
                            "name": "Cookie Jar",
                            "value": 150,
                            "category": "web",
                            "solves": 4,
                            "state": "visible",
                            "type": "standard",
                            "runtime_available": True,
                            "tags": [{"value": "easy"}, {"value": "instance"}],
                        }
                    ],
                },
            ),
            "/api/v1/users?view=admin&per_page=100": (
                200,
                {
                    "success": True,
                    "data": [
                        {
                            "id": 1,
                            "name": "operator",
                            "team_id": None,
                            "affiliation": "CTFZone",
                            "country": "IT",
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
            "/api/v1/admin/runtime/instances?per_page=20": (
                200,
                {
                    "success": True,
                    "data": {
                        "items": [
                            {
                                "id": 44,
                                "challenge_id": 7,
                                "user_id": 1,
                                "status": "running",
                                "endpoint": "challenge.example.test:31337",
                            }
                        ],
                        "pagination": {"total": 1},
                    },
                },
            ),
            "/api/v1/submissions?per_page=8": (
                200,
                {
                    "success": True,
                    "data": [
                        {
                            "id": 91,
                            "challenge_id": 7,
                            "user_id": 1,
                            "submission_type": "correct",
                            "date": "2026-08-11T10:30:00Z",
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
        }
        if responses:
            self.responses.update(copy.deepcopy(responses))

    def get_json(self, path, _incoming):
        responses = {
            "/api/v1/bootstrap": (200, self.bootstrap),
            "/api/v1/users/me": (
                200,
                {"success": True, "data": {"id": 1, "name": "operator", "score": 150, "place": "1st"}},
            ),
            "/api/v1/challenges": (
                200,
                {
                    "success": True,
                    "data": [
                        {
                            "id": 7,
                            "name": "Cookie Jar",
                            "value": 150,
                            "category": "web",
                            "solves": 4,
                            "solved_by_me": False,
                            "tags": [{"value": "easy"}, {"value": "instance"}],
                        }
                    ],
                },
            ),
            "/api/v1/challenges/7": (
                200,
                {
                    "success": True,
                    "data": {
                        "id": 7,
                        "name": "Cookie Jar",
                        "description": "Find **the flag** <script>bad()</script>",
                        "value": 150,
                        "category": "web",
                        "solves": 4,
                        "solved_by_me": False,
                        "tags": [{"value": "easy"}],
                        "hints": [],
                        "files": [],
                        "runtime": {"available": False},
                    },
                },
            ),
            "/api/v1/scoreboard": (200, {"success": True, "data": []}),
            "/api/v1/teams/me": (404, {"message": "No team"}),
            "/api/v1/pages/by-route/rules": (404, {"message": "Not found"}),
            "/api/v1/pages/route/rules": (404, {"message": "Not found"}),
        }
        responses.update(self.responses)
        return copy.deepcopy(responses.get(path, (404, {"message": "Not found"})))

    def request_from_browser(self, incoming, path):
        self.browser_request = (incoming.method, path, incoming.get_data())
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            content=json.dumps({"success": True, "data": {"status": "correct"}}),
            request=httpx.Request(incoming.method, f"http://api.test{path}"),
        )


class AppTests(unittest.TestCase):
    def setUp(self):
        self.api = FakeApi()
        self.app = create_app({"TESTING": True, "API_CLIENT": self.api})
        self.client = self.app.test_client()

    def client_for_role(self, role):
        bootstrap = copy.deepcopy(BOOTSTRAP)
        if role is None:
            bootstrap["data"]["authenticated"] = False
            bootstrap["data"]["user"] = None
        else:
            bootstrap["data"]["user"]["type"] = role
        api = FakeApi(bootstrap=bootstrap)
        app = create_app({"TESTING": True, "API_CLIENT": api})
        return app.test_client()

    def test_health_does_not_require_the_api(self):
        response = self.client.get("/healthz")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["mode"], "bff")

    def test_challenge_board_is_server_rendered_and_escaped(self):
        response = self.client.get("/challenges")
        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Cookie Jar", body)
        self.assertIn("<strong>the flag</strong>", body)
        self.assertNotIn("<script>bad()", body)
        self.assertIn("&lt;script&gt;bad()&lt;/script&gt;", body)
        self.assertIn('content="test-nonce"', body)

    def test_api_proxy_keeps_the_bff_as_browser_channel(self):
        response = self.client.post(
            "/bff/api/v1/challenges/attempt",
            data=b'{"challenge_id":7,"submission":"flag"}',
            content_type="application/json",
            headers={"csrf-token": "test-nonce"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.api.browser_request[0:2], ("POST", "/api/v1/challenges/attempt"))

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

    def test_first_boot_setup_requires_and_forwards_the_setup_token(self):
        bootstrap = copy.deepcopy(BOOTSTRAP)
        bootstrap["data"]["setup_required"] = True
        bootstrap["data"]["authenticated"] = False
        bootstrap["data"]["user"] = None
        api = FakeApi(bootstrap=bootstrap)
        app = create_app({"TESTING": True, "API_CLIENT": api})
        client = app.test_client()

        page = client.get("/setup")
        body = page.get_data(as_text=True)
        self.assertEqual(page.status_code, 200)
        self.assertIn("SETUP_TOKEN", body)
        self.assertIn('name="setup_token" type="password"', body)
        self.assertIn('id="setup-token" name="setup_token" type="password" autocomplete="off" required', body)

        response = client.post(
            "/setup",
            data={
                "setup_token": "bootstrap-secret",
                "name": "first-admin",
                "email": "admin@example.test",
                "password": "correct horse battery staple",
            },
        )
        self.assertEqual(response.status_code, 303)
        submitted = parse_qs(api.browser_request[2].decode())
        self.assertEqual(submitted["setup_token"], ["bootstrap-secret"])

    def test_admin_redirects_unauthenticated_users_to_login(self):
        response = self.client_for_role(None).get("/admin")

        self.assertEqual(response.status_code, 302)
        location = urlsplit(response.headers["Location"])
        self.assertEqual(location.path, "/login")
        self.assertEqual(parse_qs(location.query).get("next"), ["/admin"])

    def test_admin_rejects_authenticated_non_admin_users(self):
        response = self.client_for_role("user").get("/admin")
        body = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 403)
        self.assertIn("Administrator access is required", body)

    def test_admin_overview_and_challenge_list_render_for_admins(self):
        client = self.client_for_role("admin")

        overview = client.get("/admin")
        overview_body = overview.get_data(as_text=True)
        self.assertEqual(overview.status_code, 200)
        self.assertIn("Overview", overview_body)
        self.assertIn('href="/admin/challenges"', overview_body)

        challenges = client.get("/admin/challenges")
        challenges_body = challenges.get_data(as_text=True)
        self.assertEqual(challenges.status_code, 200)
        self.assertIn("Cookie Jar", challenges_body)
        self.assertIn('href="/admin/challenges/7"', challenges_body)

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
            "/admin/teams",
            "/admin/submissions",
            "/admin/sessions",
        ):
            with self.subTest(path=path):
                response = client.get(path)
                self.assertEqual(response.status_code, 200)
                self.assertIn("ADMINISTRATION", response.get_data(as_text=True))

    def test_immutable_setup_marker_is_not_an_editable_config(self):
        bootstrap = copy.deepcopy(BOOTSTRAP)
        bootstrap["data"]["user"]["type"] = "admin"
        api = FakeApi(
            bootstrap=bootstrap,
            responses={
                "/api/v1/configs": (
                    200,
                    {
                        "success": True,
                        "data": [
                            {"id": 1, "key": "setup", "value": "true"},
                            {"id": 2, "key": "ctf_name", "value": "CTFZone"},
                        ],
                    },
                )
            },
        )
        app = create_app({"TESTING": True, "API_CLIENT": api})

        body = app.test_client().get("/admin/config").get_data(as_text=True)
        self.assertNotIn('data-config-key="setup"', body)
        self.assertIn('data-config-key="ctf_name"', body)

    def test_public_profiles_and_profile_alias_are_available(self):
        alias = self.client.get("/profile")
        self.assertEqual(alias.status_code, 302)
        self.assertEqual(urlsplit(alias.headers["Location"]).path, "/users/1")

        user = self.client.get("/users/1")
        team = self.client.get("/teams/3")
        self.assertEqual(user.status_code, 200)
        self.assertIn("operator", user.get_data(as_text=True))
        self.assertEqual(team.status_code, 200)
        self.assertIn("Blue Team", team.get_data(as_text=True))
        self.assertIn('href="/users/1"', team.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
