import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[0]
sys.path.insert(0, str(ROOT))
import build  # noqa: E402

FIX = Path(__file__).resolve().parent
NOW = datetime(2026, 10, 19, 12, 0, tzinfo=timezone.utc)


def make_content(root: Path) -> Path:
    c = root / "content"
    (c / "briefings").mkdir(parents=True)
    (c / "patch-tuesday").mkdir(parents=True)
    (c / "briefings" / "_template.md").write_text("---\ntitle: T\ndate: 2026-01-01\ndraft: false\n---\nx\n", encoding="utf-8")
    (c / "briefings" / "2026-10-19-week.md").write_text(
        "---\ntitle: Week 42 briefing\ndate: 2026-10-19\nsummary: What changed.\ndraft: false\n---\n"
        "## What happened\n\nEntra <script>alert(1)</script> changed.\n\n- first point\n- second **bold**\n\n"
        "[Good link](https://learn.microsoft.com/) and [bad](javascript:alert(1))\n", encoding="utf-8")
    (c / "patch-tuesday" / "2026-10.md").write_text(
        "---\ntitle: October notes\ndate: 2026-10-13\n---\nDraft by default, not published.\n", encoding="utf-8")
    return c


class ParseTests(unittest.TestCase):
    def test_front_matter(self):
        meta, body = build.parse_front_matter("---\ntitle: \"Hi\"\ndraft: false\n---\nBody line")
        self.assertEqual(meta["title"], "Hi")
        self.assertEqual(meta["draft"], "false")
        self.assertEqual(body, "Body line")

    def test_markdown_escapes_html_and_blocks_unsafe_links(self):
        out = build.md_to_html("Text <b>x</b> [ok](https://a.example/) [no](javascript:alert(1))\n\n- one\n- two")
        self.assertNotIn("<b>x</b>", out)
        self.assertIn("&lt;b&gt;x&lt;/b&gt;", out)
        self.assertIn('href="https://a.example/"', out)
        self.assertNotIn("javascript:", out)
        self.assertIn("<li>two</li>", out)

    def test_html_comments_hidden(self):
        self.assertNotIn("Publishing", build.md_to_html("Text\n\n<!-- Publishing: secret note -->"))

    def test_headings_shift_down(self):
        self.assertIn("<h2>Title</h2>", build.md_to_html("# Title"))
        self.assertIn("<h3>Sub</h3>", build.md_to_html("## Sub"))


class PublishingTests(unittest.TestCase):
    def test_drafts_and_templates_are_skipped(self):
        with tempfile.TemporaryDirectory() as t:
            c = make_content(Path(t))
            warnings: list[str] = []
            arts = build.load_articles(c, warnings)
            slugs = [a["slug"] for a in arts]
            self.assertEqual(slugs, ["2026-10-19-week"])  # patch-tuesday draft and _template excluded
            self.assertEqual(warnings, [])

    def test_full_build_with_content_and_newsletter(self):
        cfg = json.loads((ROOT / "feeds.json").read_text(encoding="utf-8"))
        cfg["site_url"] = "https://test.example.org/brief"
        site_cfg = {
            "publisher": {"name": "Leon Test", "address": "Musterstr. 1\n12345 Berlin", "email": "a@example.org"},
            "newsletter_form_action": "https://newsletter.example.com/subscribe",
        }
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            c = make_content(t)
            status = build.run(cfg, t / "site", t / "d" / "stories.json", FIX, NOW, site_cfg, c)
            site = t / "site"
            article = (site / "briefings" / "2026-10-19-week.html").read_text(encoding="utf-8")
            self.assertIn("Week 42 briefing", article)
            self.assertIn("&lt;script&gt;", article)
            self.assertNotIn("<script>alert", article)
            self.assertNotIn("javascript:", article)
            self.assertFalse((site / "patch-tuesday" / "2026-10.html").exists())
            self.assertTrue((site / "patch-tuesday" / "index.html").exists())
            self.assertIn("Leon Test", (site / "impressum.html").read_text(encoding="utf-8"))
            self.assertIn("newsletter.example.com", (site / "index.html").read_text(encoding="utf-8"))
            self.assertIn("Get the analysis by email", (site / "briefings" / "index.html").read_text(encoding="utf-8"))
            self.assertIn("briefings/2026-10-19-week.html", (site / "sitemap.xml").read_text(encoding="utf-8"))
            self.assertIn("Week 42 briefing", (site / "feed.xml").read_text(encoding="utf-8"))
            self.assertEqual(status["analysis_articles"], 1)
            self.assertFalse(any("publisher" in w for w in status["warnings"]))

    def test_no_form_and_placeholder_impressum_when_unconfigured(self):
        cfg = json.loads((ROOT / "feeds.json").read_text(encoding="utf-8"))
        cfg["site_url"] = "https://test.example.org/brief"
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            c = make_content(t)
            status = build.run(cfg, t / "site", t / "d" / "stories.json", FIX, NOW, {}, c)
            site = t / "site"
            self.assertNotIn("subscribe-form", (site / "index.html").read_text(encoding="utf-8"))
            self.assertIn("Angaben werden ergänzt", (site / "impressum.html").read_text(encoding="utf-8"))
            self.assertTrue(any("publisher details incomplete" in w for w in status["warnings"]))

    def test_changing_article_triggers_rebuild(self):
        cfg = json.loads((ROOT / "feeds.json").read_text(encoding="utf-8"))
        cfg["site_url"] = "https://test.example.org/brief"
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            c = make_content(t)
            build.run(cfg, t / "site", t / "d" / "stories.json", FIX, NOW, {}, c)
            again = build.run(cfg, t / "site", t / "d" / "stories.json", FIX, NOW, {}, c)
            self.assertFalse(again["changed"])
            f = c / "briefings" / "2026-10-19-week.md"
            f.write_text(f.read_text(encoding="utf-8") + "\nNew paragraph.\n", encoding="utf-8")
            third = build.run(cfg, t / "site", t / "d" / "stories.json", FIX, NOW, {}, c)
            self.assertTrue(third["changed"])


if __name__ == "__main__":
    unittest.main()
