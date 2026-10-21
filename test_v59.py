import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import build  # noqa: E402

FIX = Path(__file__).resolve().parent / "fixtures"
SRC = {"id": "msblog", "name": "Microsoft Security Blog", "url": "https://www.microsoft.com/en-us/security/blog/feed/",
       "site": "https://www.microsoft.com/en-us/security/blog/", "official": False}


class MicrosoftBlogFeed(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.items = build.parse_feed((FIX / "msblog.xml").read_bytes(), SRC)

    def test_two_items_parsed(self):
        self.assertEqual(len(self.items), 2)

    def test_table_of_contents_is_not_the_summary(self):
        first = self.items[0]
        self.assertNotIn("In this article", first["summary"])
        self.assertNotIn("table-of-contents", first["summary"])
        self.assertIn("mission of the FORGE Lab", first["summary"])

    def test_table_of_contents_does_not_add_cves(self):
        # The aside mentions CVE-2026-99999 only inside the table of contents.
        self.assertEqual(self.items[0]["cves"], [])

    def test_image_comes_from_article_not_toc(self):
        self.assertIn("forge.webp", self.items[0]["image"] or "")

    def test_cve_in_body_is_found(self):
        self.assertEqual(self.items[1]["cves"], ["CVE-2026-12345"])

    def test_blog_is_not_official(self):
        self.assertFalse(self.items[0]["official"])

    def test_render_version_bumped(self):
        self.assertRegex((FIX.parent.parent / "build.py").read_text(encoding="utf-8"), r'"render": "5\.\d+"')


class CveTableSources(unittest.TestCase):
    def _story(self, source_name, cves=("CVE-2026-1",)):
        return {"title": "t", "cves": list(cves), "kev": [], "score": 3,
                "sources": [{"name": source_name, "title": "t", "url": "https://example.test/a", "published": None}]}

    def test_msrc_is_included(self):
        rows = build.msrc_cve_rows([self._story("Microsoft Security Response Center")])
        self.assertEqual(len(rows), 1)

    def test_microsoft_security_blog_is_excluded(self):
        rows = build.msrc_cve_rows([self._story("Microsoft Security Blog")])
        self.assertEqual(rows, [])


if __name__ == "__main__":
    unittest.main()
