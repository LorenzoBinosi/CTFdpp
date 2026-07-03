from collections import namedtuple

from flask import url_for

from CTFd.utils.config.pages import get_pages
from CTFd.utils.helpers import markup

Menu = namedtuple("Menu", ["title", "route", "link_target"])


class _PluginWrapper:
    """Backwards-compatible accessor used by the themes to inject extra
    scripts/styles and to build the user-facing page menu. The plugin system
    has been removed, so scripts/styles are always empty and the menu is built
    purely from the configured Pages."""

    @property
    def scripts(self):
        return markup("")

    @property
    def styles(self):
        return markup("")

    @property
    def user_menu_pages(self):
        pages = []
        for p in get_pages():
            if p.route.startswith("http"):
                route = p.route
            else:
                route = url_for("views.static_html", route=p.route)
            pages.append(Menu(title=p.title, route=route, link_target=p.link_target))
        return pages


Plugins = _PluginWrapper()
