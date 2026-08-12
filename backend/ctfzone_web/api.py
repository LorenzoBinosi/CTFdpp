"""Trusted HTTP boundary between the Python BFF and the private Rust API."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit

import httpx
from flask import Request


class ApiUnavailable(RuntimeError):
    """Raised when the Rust API cannot be reached within the BFF timeout."""


class ApiClient:
    """Call Rust as the backend service, never as the user's browser.

    Browser credentials and browser security headers deliberately stop at Python.
    Rust receives the BFF service credential and, when present, the opaque Rust
    session identifier recovered from Python's signed browser session.
    """

    _SAFE_BROWSER_HEADERS = (
        "accept",
        "content-type",
        "idempotency-key",
        "if-none-match",
        "range",
        "user-agent",
    )
    _RESERVED_HEADERS = {
        "authorization",
        "cookie",
        "csrf-token",
        "origin",
        "referer",
        "sec-fetch-dest",
        "sec-fetch-mode",
        "sec-fetch-site",
        "sec-fetch-user",
        "x-ctfzone-backend-token",
        "x-ctfzone-browser-request-id",
        "x-ctfzone-session",
    }

    def __init__(
        self,
        base_url: str,
        service_token: str,
        timeout_seconds: float = 5.0,
    ) -> None:
        parsed = urlsplit(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("API_BASE_URL must be an absolute HTTP(S) URL")
        if not service_token or "\r" in service_token or "\n" in service_token:
            raise ValueError("BACKEND_SERVICE_TOKEN must be a non-empty HTTP header value")
        self._service_token = service_token
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
        session_id: str | None = None,
        content: bytes | None = None,
        headers: Mapping[str, str] | None = None,
        timeout_seconds: float | None = None,
    ) -> httpx.Response:
        self._validate_path(path)
        request_headers = self._request_headers(incoming, session_id, headers)
        try:
            if timeout_seconds is None:
                return self._client.request(
                    method.upper(), path, headers=request_headers, content=content
                )
            return self._client.request(
                method.upper(), path, headers=request_headers, content=content,
                timeout=timeout_seconds,
            )
        except httpx.HTTPError as error:
            raise ApiUnavailable("The CTFZone API is temporarily unavailable") from error

    def request_from_browser(
        self,
        incoming: Request,
        path: str,
        *,
        session_id: str | None = None,
        timeout_seconds: float | None = None,
    ) -> httpx.Response:
        query = incoming.query_string.decode("ascii", errors="ignore")
        target = f"{path}?{query}" if query else path
        return self.request(
            incoming.method,
            target,
            incoming=incoming,
            session_id=session_id,
            content=incoming.get_data(cache=False),
            timeout_seconds=timeout_seconds,
        )

    def get_json(
        self,
        path: str,
        incoming: Request,
        *,
        session_id: str | None = None,
    ) -> tuple[int, Any]:
        response = self.request(
            "GET", path, incoming=incoming, session_id=session_id
        )
        try:
            payload = response.json()
        except ValueError:
            payload = None
        return response.status_code, payload

    def _request_headers(
        self,
        incoming: Request | None,
        session_id: str | None,
        headers: Mapping[str, str] | None,
    ) -> dict[str, str]:
        request_headers: dict[str, str] = {}
        if incoming is not None:
            for name in self._SAFE_BROWSER_HEADERS:
                value = incoming.headers.get(name)
                if self._safe_header_value(value):
                    request_headers[name] = value

            forwarded_for = incoming.headers.get("X-Forwarded-For")
            if not forwarded_for:
                forwarded_for = incoming.remote_addr
            if self._safe_header_value(forwarded_for):
                request_headers["x-forwarded-for"] = forwarded_for
            forwarded_proto = incoming.headers.get("X-Forwarded-Proto", incoming.scheme)
            if self._safe_header_value(forwarded_proto):
                request_headers["x-forwarded-proto"] = forwarded_proto
            forwarded_host = incoming.headers.get("X-Forwarded-Host", incoming.host)
            if self._safe_header_value(forwarded_host):
                request_headers["x-forwarded-host"] = forwarded_host
        if headers:
            for name, value in headers.items():
                if name.casefold() in self._RESERVED_HEADERS:
                    continue
                if self._safe_header_value(value):
                    request_headers[name] = value

        request_headers["x-ctfzone-backend-token"] = self._service_token
        if session_id:
            if not self._safe_header_value(session_id) or len(session_id) > 512:
                raise ValueError("Rust session identifier is not a valid HTTP header value")
            request_headers["x-ctfzone-session"] = session_id
        return request_headers

    @staticmethod
    def _safe_header_value(value: str | None) -> bool:
        return bool(value) and "\r" not in value and "\n" not in value

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
