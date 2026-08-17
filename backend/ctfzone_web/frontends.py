"""Installed web frontend discovery and isolated asset delivery.

Player frontends are trusted, read-only application code bundled in the backend
image.  PostgreSQL stores only their opaque identifier; this registry is the
only component allowed to turn that identifier into a filesystem location.
"""

from __future__ import annotations

import json
import hashlib
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any, Mapping

from flask import Blueprint, abort, current_app, send_file
from jinja2 import FileSystemLoader, PrefixLoader

DEFAULT_PLAYER_FRONTEND = "terminal"

_IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}\Z")
_MAX_MANIFEST_BYTES = 64 * 1024
_REQUIRED_PLAYER_TEMPLATES = (
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
_REQUIRED_ADMIN_TEMPLATES = (
    "base.html",
    "setup.html",
    "forbidden.html",
    "overview.html",
    "challenges.html",
    "challenge_form.html",
    "users.html",
    "user_form.html",
    "config.html",
    "machines.html",
    "records.html",
    "sessions.html",
)
_REQUIRED_ADMIN_ASSETS = (
    "css/admin.css",
    "js/admin.js",
    "vendor/xterm/xterm.css",
    "vendor/xterm/xterm.js",
    "vendor/xterm/addon-fit.js",
    "vendor/xterm/LICENSE",
    "vendor/xterm/LICENSE.addon-fit",
    "vendor/xterm/VERSIONS",
)
_REQUIRED_SHARED_ASSETS = ("js/api.js", "js/storage.js", "js/ui.js")


class FrontendConfigurationError(RuntimeError):
    """Raised when bundled frontend files do not form a safe installation."""


@dataclass(frozen=True, slots=True)
class PlayerFrontend:
    identifier: str
    name: str
    description: str
    version: str
    assets: tuple[str, ...]
    template_directory: Path
    static_directory: Path

    def public_manifest(self) -> dict[str, str]:
        """Return display metadata without leaking application filesystem paths."""

        return {
            "id": self.identifier,
            "name": self.name,
            "description": self.description,
            "version": self.version,
        }


class FrontendRegistry:
    """Immutable mapping of installed player frontends and fixed UI roots."""

    def __init__(
        self,
        *,
        root: Path,
        admin_templates: Path,
        admin_static: Path,
        shared_static: Path,
        players: Mapping[str, PlayerFrontend],
    ) -> None:
        if DEFAULT_PLAYER_FRONTEND not in players:
            raise FrontendConfigurationError(
                f"The required {DEFAULT_PLAYER_FRONTEND!r} player frontend is not installed"
            )
        self.root = root
        self.admin_template_directory = admin_templates
        self.admin_static_directory = admin_static
        self.shared_static_directory = shared_static
        self._players = MappingProxyType(dict(players))
        self.asset_version = _asset_bundle_version(
            admin_static=admin_static,
            shared_static=shared_static,
            players=self._players,
        )

    @classmethod
    def discover(cls, root: str | Path) -> FrontendRegistry:
        root_path = _required_directory(Path(root), "frontend root")
        admin_root = _required_directory(root_path / "admin", "admin frontend")
        admin_templates = _required_directory(
            admin_root / "templates", "admin template directory"
        )
        admin_static = _required_directory(
            admin_root / "static", "admin static directory"
        )
        shared_static = _required_directory(
            root_path / "shared" / "static", "shared static directory"
        )
        for relative in _REQUIRED_ADMIN_TEMPLATES:
            _required_child_file(
                admin_templates, relative, f"administration template {relative!r}"
            )
        for relative in _REQUIRED_ADMIN_ASSETS:
            _required_child_file(
                admin_static, relative, f"administration asset {relative!r}"
            )
        for relative in _REQUIRED_SHARED_ASSETS:
            _required_child_file(shared_static, relative, f"shared asset {relative!r}")
        player_root = _required_directory(
            root_path / "player", "player frontend directory"
        )

        players: dict[str, PlayerFrontend] = {}
        for directory in sorted(player_root.iterdir(), key=lambda value: value.name):
            if not directory.is_dir():
                continue
            identifier = directory.name
            if not _valid_identifier(identifier):
                raise FrontendConfigurationError(
                    f"Player frontend directory {identifier!r} is not a safe identifier"
                )
            frontend = _load_player_frontend(directory, identifier)
            if frontend.identifier in players:
                raise FrontendConfigurationError(
                    f"Duplicate player frontend identifier {frontend.identifier!r}"
                )
            players[frontend.identifier] = frontend

        return cls(
            root=root_path,
            admin_templates=admin_templates,
            admin_static=admin_static,
            shared_static=shared_static,
            players=players,
        )

    @property
    def default(self) -> PlayerFrontend:
        return self._players[DEFAULT_PLAYER_FRONTEND]

    def installed(self) -> tuple[PlayerFrontend, ...]:
        return tuple(
            sorted(
                self._players.values(),
                key=lambda frontend: (frontend.name.casefold(), frontend.identifier),
            )
        )

    def public_manifests(self) -> list[dict[str, str]]:
        return [frontend.public_manifest() for frontend in self.installed()]

    def get(self, identifier: Any) -> PlayerFrontend | None:
        if not isinstance(identifier, str) or not _valid_identifier(identifier):
            return None
        return self._players.get(identifier)

    def resolve(self, identifier: Any) -> PlayerFrontend:
        """Resolve a DB value through the map, never by constructing a path."""

        return self.get(identifier) or self.default

    def template_name(self, frontend: PlayerFrontend, name: str) -> str:
        relative = _safe_relative_name(name, "template")
        registered = self._players.get(frontend.identifier)
        if registered is not frontend:
            raise FrontendConfigurationError("Player frontend is not registered")
        return f"player/{frontend.identifier}/{relative}"

    def template_loader(self) -> PrefixLoader:
        player_loaders = {
            identifier: FileSystemLoader(str(frontend.template_directory))
            for identifier, frontend in self._players.items()
        }
        return PrefixLoader(
            {
                "admin": FileSystemLoader(str(self.admin_template_directory)),
                "player": PrefixLoader(player_loaders),
            }
        )


def _valid_identifier(value: str) -> bool:
    return _IDENTIFIER.fullmatch(value) is not None


def _safe_relative_name(value: str, label: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise FrontendConfigurationError(f"Invalid {label} name")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise FrontendConfigurationError(f"Invalid {label} name")
    return path.as_posix()


def _required_directory(path: Path, label: str) -> Path:
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise FrontendConfigurationError(f"Missing {label}: {path}") from error
    if not resolved.is_dir():
        raise FrontendConfigurationError(f"Missing {label}: {path}")
    return resolved


def _required_file(path: Path, label: str) -> Path:
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise FrontendConfigurationError(f"Missing {label}: {path}") from error
    if not resolved.is_file():
        raise FrontendConfigurationError(f"Missing {label}: {path}")
    return resolved


def _required_child_file(root: Path, relative: str, label: str) -> Path:
    """Require a regular file whose resolved target remains below ``root``."""

    resolved = _required_file(root / relative, label)
    try:
        resolved.relative_to(root)
    except ValueError as error:
        raise FrontendConfigurationError(
            f"{label.capitalize()} resolves outside its registered frontend root"
        ) from error
    return resolved


def _asset_bundle_version(
    *,
    admin_static: Path,
    shared_static: Path,
    players: Mapping[str, PlayerFrontend],
) -> str:
    """Return a deterministic cache key for every browser asset in the bundle."""

    digest = hashlib.sha256()
    entries = [
        *(('admin/' + relative, admin_static / relative) for relative in _REQUIRED_ADMIN_ASSETS),
        *(('shared/' + relative, shared_static / relative) for relative in _REQUIRED_SHARED_ASSETS),
        *(
            (f'player/{identifier}/{relative}', frontend.static_directory / relative)
            for identifier, frontend in sorted(players.items())
            for relative in frontend.assets
        ),
    ]
    for public_name, path in entries:
        digest.update(public_name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()[:16]


def _asset_response(root: Path, filename: str):
    try:
        relative = _safe_relative_name(filename, "asset")
        candidate = (root / relative).resolve(strict=True)
        candidate.relative_to(root)
    except (FrontendConfigurationError, OSError, ValueError):
        abort(404)
    if not candidate.is_file():
        abort(404)
    return send_file(candidate, conditional=True)


def _manifest_string(
    manifest: dict[str, Any], key: str, *, required: bool, maximum: int
) -> str:
    value = manifest.get(key)
    if value is None and not required:
        return ""
    if not isinstance(value, str) or len(value) > maximum:
        raise FrontendConfigurationError(
            f"Player frontend manifest field {key!r} must be a string of at most {maximum} characters"
        )
    normalized = value.strip()
    if required and not normalized:
        qualifier = "non-empty " if required else ""
        raise FrontendConfigurationError(
            f"Player frontend manifest field {key!r} must be a {qualifier}string of at most {maximum} characters"
        )
    return normalized


def _manifest_assets(manifest: dict[str, Any]) -> tuple[str, ...]:
    value = manifest.get("assets")
    if not isinstance(value, list) or not value or len(value) > 128:
        raise FrontendConfigurationError(
            "Player frontend manifest field 'assets' must be a non-empty list"
        )
    assets: list[str] = []
    for entry in value:
        if not isinstance(entry, str) or len(entry) > 256:
            raise FrontendConfigurationError(
                "Player frontend manifest assets must be paths of at most 256 characters"
            )
        relative = _safe_relative_name(entry, "asset")
        if relative in assets:
            raise FrontendConfigurationError(
                f"Player frontend manifest contains duplicate asset {relative!r}"
            )
        assets.append(relative)
    return tuple(assets)


def _load_player_frontend(directory: Path, directory_identifier: str) -> PlayerFrontend:
    manifest_path = _required_file(
        directory / "manifest.json", f"manifest for {directory_identifier!r}"
    )
    if manifest_path.stat().st_size > _MAX_MANIFEST_BYTES:
        raise FrontendConfigurationError(
            f"Player frontend manifest {manifest_path} is too large"
        )
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise FrontendConfigurationError(
            f"Player frontend manifest {manifest_path} is invalid"
        ) from error
    if not isinstance(manifest, dict):
        raise FrontendConfigurationError(
            f"Player frontend manifest {manifest_path} must be a JSON object"
        )

    identifier = _manifest_string(manifest, "id", required=True, maximum=64)
    if not _valid_identifier(identifier) or identifier != directory_identifier:
        raise FrontendConfigurationError(
            f"Player frontend manifest id must match directory {directory_identifier!r}"
        )
    name = _manifest_string(manifest, "name", required=True, maximum=128)
    description = _manifest_string(
        manifest, "description", required=False, maximum=512
    )
    version = _manifest_string(manifest, "version", required=False, maximum=64)
    assets = _manifest_assets(manifest)
    template_directory = _required_directory(
        directory / "templates", f"template directory for {identifier!r}"
    )
    static_directory = _required_directory(
        directory / "static", f"static directory for {identifier!r}"
    )
    for relative in _REQUIRED_PLAYER_TEMPLATES:
        _required_child_file(
            template_directory,
            relative,
            f"player template {relative!r} for {identifier!r}",
        )
    for relative in assets:
        _required_child_file(
            static_directory,
            relative,
            f"player asset {relative!r} for {identifier!r}",
        )

    return PlayerFrontend(
        identifier=identifier,
        name=name,
        description=description,
        version=version,
        assets=assets,
        template_directory=template_directory,
        static_directory=static_directory,
    )


assets = Blueprint("frontend_assets", __name__)


def _registry() -> FrontendRegistry:
    return current_app.extensions["ctfzone_frontends"]


@assets.get("/assets/admin/<path:filename>")
def admin_asset(filename: str):
    return _asset_response(_registry().admin_static_directory, filename)


@assets.get("/assets/shared/<path:filename>")
def shared_asset(filename: str):
    return _asset_response(_registry().shared_static_directory, filename)


@assets.get("/assets/player/<frontend_id>/<path:filename>")
def player_asset(frontend_id: str, filename: str):
    frontend = _registry().get(frontend_id)
    if frontend is None:
        abort(404)
    return _asset_response(frontend.static_directory, filename)


__all__ = [
    "DEFAULT_PLAYER_FRONTEND",
    "FrontendConfigurationError",
    "FrontendRegistry",
    "PlayerFrontend",
    "assets",
]
