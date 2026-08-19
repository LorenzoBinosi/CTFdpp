import unittest

from ctfzone_web.markdown import render_html, render_markdown


class MarkdownTests(unittest.TestCase):
    def test_allows_safe_html_and_escapes_active_content(self):
        rendered = str(
            render_markdown(
                '<strong data-unsafe="x">Safe</strong> '
                '<a href="https://example.org/path" onclick="steal()">visit</a> '
                '<a href="javascript:alert(1)">bad</a> '
                '<script>alert("x")</script> '
                '<img src=x onerror="steal()">'
            )
        )
        self.assertIn("<strong>Safe</strong>", rendered)
        self.assertIn('href="https://example.org/path"', rendered)
        self.assertIn('rel="noopener noreferrer"', rendered)
        self.assertNotIn("onclick", rendered)
        self.assertNotIn('href="javascript:', rendered)
        self.assertNotIn("<script>", rendered)
        self.assertIn("&lt;script&gt;", rendered)
        self.assertNotIn("<img", rendered)
        self.assertIn("&lt;img", rendered)

    def test_renders_safe_block_html_without_paragraph_wrapping(self):
        rendered = str(render_markdown("<div><h2>Connect</h2><p>Use <code>nc host 1</code></p></div>"))
        self.assertEqual(
            rendered,
            "<div><h2>Connect</h2><p>Use <code>nc host 1</code></p></div>",
        )

    def test_renders_basic_structure(self):
        rendered = str(render_markdown("# Goal\n\n- Find **flag**\n- Run `id`"))
        self.assertIn("<h1>Goal</h1>", rendered)
        self.assertIn("<ul>", rendered)
        self.assertIn("<strong>flag</strong>", rendered)
        self.assertIn("<code>id</code>", rendered)

    def test_page_html_preserves_only_the_safe_layout_vocabulary(self):
        rendered = str(
            render_html(
                '<div class="row topbar unknown">'
                '<div class="col-md-6 offset-md-3">'
                '<h1 class="text-center" style="position:fixed">CTFZone</h1>'
                "</div></div>"
            )
        )
        self.assertEqual(
            rendered,
            '<div class="row"><div class="col-md-6 offset-md-3">'
            '<h1 class="text-center">CTFZone</h1></div></div>',
        )
        self.assertNotIn("topbar", rendered)
        self.assertNotIn("style=", rendered)


if __name__ == "__main__":
    unittest.main()
