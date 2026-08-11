import unittest

import httpx
from flask import Flask, request

from ctfzone_web.api import ApiClient


class ApiClientTests(unittest.TestCase):
    def test_forwards_fetch_metadata_across_the_bff_hop(self):
        captured = {}

        def upstream(incoming):
            captured.update(incoming.headers)
            return httpx.Response(200, json={"success": True})

        client = ApiClient("http://api.test")
        client._client.close()
        client._client = httpx.Client(
            base_url="http://api.test",
            transport=httpx.MockTransport(upstream),
        )
        app = Flask(__name__)

        with app.test_request_context(
            "/logout",
            method="POST",
            headers={
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "same-origin",
                "Sec-Fetch-User": "?1",
            },
        ):
            response = client.request_from_browser(request, "/logout")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(captured["sec-fetch-site"], "same-origin")
        self.assertEqual(captured["sec-fetch-mode"], "navigate")
        self.assertEqual(captured["sec-fetch-dest"], "document")
        self.assertEqual(captured["sec-fetch-user"], "?1")
        client._client.close()


if __name__ == "__main__":
    unittest.main()
