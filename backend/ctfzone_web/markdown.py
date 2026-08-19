"""A small Markdown renderer with an escape-first, allowlisted HTML policy.

Challenge authors get headings, lists, emphasis, links, code, and a deliberately
limited set of structural HTML tags. Attributes and URL schemes are rebuilt
from an allowlist; scripts, styles, media, event handlers, and unknown tags are
rendered as text instead of becoming active player-page content.
"""

from __future__ import annotations

import re
from html import escape
from html.parser import HTMLParser
from urllib.parse import urlsplit

from markupsafe import Markup

_FENCE = re.compile(r"^```(?:[A-Za-z0-9_+.-]+)?\s*$")
_LINK = re.compile(r"\[([^\]\n]+)]\(([^)\s]+)\)")
_CODE = re.compile(r"`([^`\n]+)`")
_BOLD = re.compile(r"\*\*([^*\n]+)\*\*")
_ITALIC = re.compile(r"(?<!\*)\*([^*\n]+)\*(?!\*)")
_ALLOWED_HTML_TAGS = frozenset(
    {
        "a",
        "b",
        "blockquote",
        "br",
        "code",
        "details",
        "div",
        "em",
        "h1",
        "h2",
        "h3",
        "h4",
        "hr",
        "i",
        "kbd",
        "li",
        "ol",
        "p",
        "pre",
        "s",
        "span",
        "strong",
        "sub",
        "summary",
        "sup",
        "table",
        "tbody",
        "td",
        "th",
        "thead",
        "tr",
        "ul",
    }
)
_VOID_HTML_TAGS = frozenset({"br", "hr"})
_ALLOWED_PAGE_LAYOUT_CLASSES = frozenset(
    {
        "align-items-center",
        "align-items-end",
        "align-items-start",
        "col",
        "display-1",
        "lead",
        "page-actions",
        "page-section",
        "row",
        "text-center",
        "text-end",
        "text-start",
    }
)
_ALLOWED_PAGE_GRID_CLASS = re.compile(r"^(?:col-md-(?:[1-9]|1[0-2])|offset-md-(?:[0-9]|1[01]))$")
_BLOCK_HTML = re.compile(
    r"^</?(?:blockquote|details|div|h[1-4]|hr|ol|p|pre|summary|table|tbody|td|th|thead|tr|ul)(?:\s|/?>)",
    re.IGNORECASE,
)


def _safe_href(value: str) -> str | None:
    parsed = urlsplit(value)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return value
    if not parsed.scheme and not parsed.netloc and value.startswith(("/", "#")):
        return value
    return None


class _HtmlTokenParser(HTMLParser):
    def __init__(self, tokens: dict[str, str], *, allow_page_layout: bool = False) -> None:
        super().__init__(convert_charrefs=True)
        self.tokens = tokens
        self.output: list[str] = []
        self.allow_page_layout = allow_page_layout

    def _token(self, html: str) -> None:
        token = f"\x00HTML{len(self.tokens)}\x00"
        self.tokens[token] = html
        self.output.append(token)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.casefold()
        if tag not in _ALLOWED_HTML_TAGS:
            self.output.append(escape(self.get_starttag_text() or f"<{tag}>", quote=True))
            return
        values = {name.casefold(): value for name, value in attrs if value is not None}
        attributes = ""
        if self.allow_page_layout:
            safe_classes = [
                value
                for value in values.get("class", "").split()
                if value in _ALLOWED_PAGE_LAYOUT_CLASSES
                or _ALLOWED_PAGE_GRID_CLASS.fullmatch(value)
            ]
            if safe_classes:
                attributes += f' class="{escape(" ".join(safe_classes), quote=True)}"'
        if tag == "a":
            href = _safe_href(values.get("href", ""))
            title = values.get("title")
            if href is not None:
                attributes += f' href="{escape(href, quote=True)}"'
                parsed_href = urlsplit(href)
                if parsed_href.scheme in {"http", "https"} and parsed_href.netloc:
                    attributes += ' target="_blank" rel="noopener noreferrer"'
            if title:
                attributes += f' title="{escape(title, quote=True)}"'
            self._token(f"<a{attributes}>")
            return
        self._token(f"<{tag}{attributes}>")

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        if tag.casefold() in _ALLOWED_HTML_TAGS and tag.casefold() not in _VOID_HTML_TAGS:
            self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.casefold()
        if tag in _ALLOWED_HTML_TAGS and tag not in _VOID_HTML_TAGS:
            self._token(f"</{tag}>")
        elif tag not in _VOID_HTML_TAGS:
            self.output.append(escape(f"</{tag}>", quote=True))

    def handle_data(self, data: str) -> None:
        self.output.append(escape(data, quote=True))

    def handle_comment(self, data: str) -> None:
        self.output.append(escape(f"<!--{data}-->", quote=True))

    def handle_decl(self, decl: str) -> None:
        self.output.append(escape(f"<!{decl}>", quote=True))

    def handle_pi(self, data: str) -> None:
        self.output.append(escape(f"<?{data}>", quote=True))


def _escape_with_safe_html(
    raw: str, tokens: dict[str, str], *, allow_page_layout: bool = False
) -> str:
    parser = _HtmlTokenParser(tokens, allow_page_layout=allow_page_layout)
    parser.feed(raw)
    parser.close()
    return "".join(parser.output)


def _inline(raw: str) -> str:
    tokens: dict[str, str] = {}
    value = _escape_with_safe_html(raw, tokens)

    def code(match: re.Match[str]) -> str:
        token = f"\x00CODE{len(tokens)}\x00"
        tokens[token] = f"<code>{match.group(1)}</code>"
        return token

    value = _CODE.sub(code, value)

    def link(match: re.Match[str]) -> str:
        href = _safe_href(match.group(2))
        if href is None:
            return match.group(0)
        return (
            f'<a href="{escape(href, quote=True)}" target="_blank" '
            f'rel="noopener noreferrer">{match.group(1)}</a>'
        )

    value = _LINK.sub(link, value)
    value = _BOLD.sub(r"<strong>\1</strong>", value)
    value = _ITALIC.sub(r"<em>\1</em>", value)
    for token, html in tokens.items():
        value = value.replace(token, html)
    return value


def render_html(raw: object) -> Markup:
    """Render the deliberately small, script-free custom-page HTML subset."""

    text = "" if raw is None else str(raw).replace("\r\n", "\n").replace("\r", "\n")
    tokens: dict[str, str] = {}
    value = _escape_with_safe_html(text, tokens, allow_page_layout=True)
    for token, html in tokens.items():
        value = value.replace(token, html)
    return Markup(value)


def render_markdown(raw: object) -> Markup:
    text = "" if raw is None else str(raw).replace("\r\n", "\n").replace("\r", "\n")
    lines = text.split("\n")
    output: list[str] = []
    paragraph: list[str] = []
    list_items: list[str] = []
    code_lines: list[str] = []
    in_code = False

    def flush_paragraph() -> None:
        if paragraph:
            output.append(f"<p>{'<br>'.join(_inline(line) for line in paragraph)}</p>")
            paragraph.clear()

    def flush_list() -> None:
        if list_items:
            output.append("<ul>" + "".join(f"<li>{item}</li>" for item in list_items) + "</ul>")
            list_items.clear()

    for line in lines:
        if _FENCE.match(line):
            if in_code:
                output.append("<pre><code>" + escape("\n".join(code_lines)) + "</code></pre>")
                code_lines.clear()
                in_code = False
            else:
                flush_paragraph()
                flush_list()
                in_code = True
            continue
        if in_code:
            code_lines.append(line)
            continue

        stripped = line.strip()
        if not stripped:
            flush_paragraph()
            flush_list()
            continue
        heading = re.match(r"^(#{1,4})\s+(.+)$", stripped)
        if heading:
            flush_paragraph()
            flush_list()
            level = len(heading.group(1))
            output.append(f"<h{level}>{_inline(heading.group(2))}</h{level}>")
            continue
        item = re.match(r"^[-*]\s+(.+)$", stripped)
        if item:
            flush_paragraph()
            list_items.append(_inline(item.group(1)))
            continue
        if _BLOCK_HTML.match(stripped):
            flush_paragraph()
            flush_list()
            output.append(_inline(stripped))
            continue
        flush_list()
        paragraph.append(line)

    if in_code:
        output.append("<pre><code>" + escape("\n".join(code_lines)) + "</code></pre>")
    flush_paragraph()
    flush_list()
    return Markup("\n".join(output))
