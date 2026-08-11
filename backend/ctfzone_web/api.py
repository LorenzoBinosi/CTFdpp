"""Small, explicit HTTP boundary between the Python BFF and Rust API."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit

import httpx
from flask import Request


class ApiUnavailable(RuntimeError):
    """Raised when the Rust API cannot be reached within the BFF timeout."""


class ApiClient:
    _FORWARDED_REQUEST_HEADERS = (
        "accept",
        "authorization",
        "content-type",
        "cookie",
        "csrf-token",
        "idempotency-key",
        "if-none-match",
        "origin",
        "referer",
        # Rust uses Fetch Metadata to reject cross-site logout and other
        # browser-originated state changes. Preserve the browser signal across
        # the trusted BFF hop instead of making every request look server-side.
        "sec-fetch-dest",
        "sec-fetch-mode",
        "sec-fetch-site",
        "sec-fetch-user",
        "user-agent",
    )

    def __init__(self, base_url: str, timeout_seconds: float = 5.0) -> None:
        parsed = urlsplit(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("API_BASE_URL must be an absolute HTTP(S) URL")
        self._client = httpx.Client(
            base_url=base_url.rstrip("/"),
            timeout=httpx.Timeout(timeout_seconds),
            follow_redirects=False,
            trust_env=False,
        )

    def request(
        self,
        method: str,
        path: str,
        *,
        incoming: Request | None = None,
        content: bytes | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> httpx.Response:
        self._validate_path(path)
        request_headers: dict[str, str] = {}
        if incoming is not None:
            for name in self._FORWARDED_REQUEST_HEADERS:
                value = incoming.headers.get(name)
                if value and "\r" not in value and "\n" not in value:
                    request_headers[name] = value

            forwarded_for = incoming.headers.get("X-Forwarded-For")
            if not forwarded_for:
                forwarded_for = incoming.remote_addr
            if forwarded_for:
                request_headers["x-forwarded-for"] = forwarded_for
            request_headers["x-forwarded-proto"] = incoming.headers.get(
                "X-Forwarded-Proto", incoming.scheme
            )
            request_headers["x-forwarded-host"] = incoming.headers.get(
                "X-Forwarded-Host", incoming.host
            )
        if headers:
            request_headers.update(headers)

        try:
            return self._client.request(
                method.upper(), path, headers=request_headers, content=content
            )
        except httpx.HTTPError as error:
            raise ApiUnavailable("The CTFZone API is temporarily unavailable") from error

    def request_from_browser(self, incoming: Request, path: str) -> httpx.Response:
        query = incoming.query_string.decode("ascii", errors="ignore")
        target = f"{path}?{query}" if query else path
        return self.request(
            incoming.method,
            target,
            incoming=incoming,
            content=incoming.get_data(cache=False),
        )

    def get_json(self, path: str, incoming: Request) -> tuple[int, Any]:
        response = self.request("GET", path, incoming=incoming)
        try:
            payload = response.json()
        except ValueError:
            payload = None
        return response.status_code, payload

    def open_download(self, path: str, incoming: Request) -> httpx.Response:
        """Open a streamed GET response. The caller must close the response."""
        self._validate_path(path)
        request_headers: dict[str, str] = {}
        for name in self._FORWARDED_REQUEST_HEADERS:
            value = incoming.headers.get(name)
            if value and "\r" not in value and "\n" not in value:
                request_headers[name] = value
        request_headers["x-forwarded-for"] = (
            incoming.headers.get("X-Forwarded-For")
            or incoming.remote_addr
            or "unknown"
        )
        request_headers["x-forwarded-proto"] = incoming.headers.get(
            "X-Forwarded-Proto", incoming.scheme
        )
        request_headers["x-forwarded-host"] = incoming.headers.get(
            "X-Forwarded-Host", incoming.host
        )
        try:
            prepared = self._client.build_request("GET", path, headers=request_headers)
            return self._client.send(prepared, stream=True)
        except httpx.HTTPError as error:
            raise ApiUnavailable("The CTFZone API is temporarily unavailable") from error

    @staticmethod
    def unwrap(payload: Any, default: Any = None) -> Any:
        if not isinstance(payload, dict):
            return default
        if payload.get("success") is False:
            return default
        return payload.get("data", payload)

    @staticmethod
    def _validate_path(path: str) -> None:
        parsed = urlsplit(path)
        if parsed.scheme or parsed.netloc or not parsed.path.startswith("/"):
            raise ValueError("API request path must be local")
        if any(part == ".." for part in parsed.path.split("/")):
            raise ValueError("API request path must not traverse directories")
