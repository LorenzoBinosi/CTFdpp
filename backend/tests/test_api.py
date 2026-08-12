import unittest

import httpx
from flask import Flask, request

from ctfzone_web.api import ApiClient


class ApiClientTests(unittest.TestCase):
    def test_replaces_browser_credentials_with_trusted_backend_headers(self):
        captured = []

        def upstream(incoming):
            captured.append(dict(incoming.headers))
            return httpx.Response(200, json={"success": True})

        client = ApiClient("http://api.test", "private-service-token")
        client._client.close()
        client._client = httpx.Client(
            base_url="http://api.test",
            transport=httpx.MockTransport(upstream),
        )
        app = Flask(__name__)

        with app.test_request_context(
            "/bff/api/v1/challenges/attempt",
            method="POST",
            headers={
                "Authorization": "Bearer browser-token",
                "Cookie": "session=browser-cookie",
                "Csrf-Token": "browser-csrf",
                "Origin": "https://evil.example",
                "Referer": "https://evil.example/form",
                "Sec-Fetch-Site": "cross-site",
                "Idempotency-Key": "safe-operation-key",
                "X-CTFZone-Browser-Request-Id": "browser-controlled-marker",
            },
        ):
            response = client.request_from_browser(
                request,
                "/api/v1/challenges/attempt",
                session_id="opaque-rust-session",
            )

        self.assertEqual(response.status_code, 200)
        headers = captured[0]
        self.assertEqual(headers["x-ctfzone-backend-token"], "private-service-token")
        self.assertEqual(headers["x-ctfzone-session"], "opaque-rust-session")
        self.assertEqual(headers["idempotency-key"], "safe-operation-key")
        for forbidden in (
            "authorization",
            "cookie",
            "csrf-token",
            "origin",
            "referer",
            "sec-fetch-site",
            "x-ctfzone-browser-request-id",
        ):
            self.assertNotIn(forbidden, headers)
        client._client.close()

    def test_every_call_has_service_token_without_python_request_marker(self):
        captured = []

        def upstream(incoming):
            captured.append(dict(incoming.headers))
            return httpx.Response(200, json={"success": True, "data": {}})

        client = ApiClient("http://api.test", "private-service-token")
        client._client.close()
        client._client = httpx.Client(
            base_url="http://api.test",
            transport=httpx.MockTransport(upstream),
        )
        app = Flask(__name__)
        with app.test_request_context("/scoreboard"):
            client.get_json("/api/v1/bootstrap", request)
            client.get_json("/api/v1/scoreboard", request)

        self.assertEqual(len(captured), 2)
        self.assertTrue(
            all(
                headers["x-ctfzone-backend-token"] == "private-service-token"
                for headers in captured
            )
        )
        self.assertTrue(
            all("x-ctfzone-browser-request-id" not in headers for headers in captured)
        )
        self.assertTrue(all("x-ctfzone-session" not in headers for headers in captured))
        client._client.close()


if __name__ == "__main__":
    unittest.main()
