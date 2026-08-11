import unittest

from ctfzone_web.markdown import render_markdown


class MarkdownTests(unittest.TestCase):
    def test_escapes_raw_html_and_unsafe_links(self):
        rendered = str(
            render_markdown(
                '<script>alert("x")</script> [bad](javascript:alert(1)) '
                "[good](https://example.org/path)"
            )
        )
        self.assertNotIn("<script>", rendered)
        self.assertIn("&lt;script&gt;", rendered)
        self.assertNotIn('href="javascript:', rendered)
        self.assertIn('href="https://example.org/path"', rendered)

    def test_renders_basic_structure(self):
        rendered = str(render_markdown("# Goal\n\n- Find **flag**\n- Run `id`"))
        self.assertIn("<h1>Goal</h1>", rendered)
        self.assertIn("<ul>", rendered)
        self.assertIn("<strong>flag</strong>", rendered)
        self.assertIn("<code>id</code>", rendered)


if __name__ == "__main__":
    unittest.main()
