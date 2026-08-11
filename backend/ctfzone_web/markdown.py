"""A deliberately small Markdown renderer with an escape-first policy.

Challenge authors get headings, lists, emphasis, links, and code. Raw HTML is
shown as text rather than accepted, keeping the BFF safe without a large parser
or sanitizer dependency.
"""

from __future__ import annotations

import re
from html import escape
from urllib.parse import urlsplit

from markupsafe import Markup

_FENCE = re.compile(r"^```(?:[A-Za-z0-9_+.-]+)?\s*$")
_LINK = re.compile(r"\[([^\]\n]+)]\(([^)\s]+)\)")
_CODE = re.compile(r"`([^`\n]+)`")
_BOLD = re.compile(r"\*\*([^*\n]+)\*\*")
_ITALIC = re.compile(r"(?<!\*)\*([^*\n]+)\*(?!\*)")


def _safe_href(value: str) -> str | None:
    parsed = urlsplit(value)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return value
    if not parsed.scheme and not parsed.netloc and value.startswith(("/", "#")):
        return value
    return None


def _inline(raw: str) -> str:
    value = escape(raw, quote=True)
    tokens: dict[str, str] = {}

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
        flush_list()
        paragraph.append(line)

    if in_code:
        output.append("<pre><code>" + escape("\n".join(code_lines)) + "</code></pre>")
    flush_paragraph()
    flush_list()
    return Markup("\n".join(output))
