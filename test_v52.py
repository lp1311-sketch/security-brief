import io
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock
from urllib.parse import unquote

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import build  # noqa: E402

NOW = datetime(2026, 10, 19, 12, 0, tzinfo=timezone.utc)


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def story(title, tags=(), prio="Standard", vendors=(), image=None):
    return {"id": title[:8].lower().replace(" ", ""), "title": title, "summary": "Short summary.",
            "published": "2026-10-19T08:00:00+00:00", "category": "threats", "tags": list(tags),
            "priority": prio, "score": 3, "reasons": [], "cves": [], "vendors": list(vendors),
            "kev": [], "kev_checked": True, "image": image, "image_source": "X" if image else None,
            "sources": [{"name": "BleepingComputer", "title": title, "url": "https://example.test/a",
                         "published": "2026-10-19T08:00:00+00:00"}]}


class PreviewImages(unittest.TestCase):
    def test_og_image_is_read_from_article_page(self):
        page = (b'<html><head><meta property="og:image" content="/img/cover.jpg">'
                b'<meta name="twitter:card" content="summary"></head></html>')
        with mock.patch("urllib.request.urlopen", return_value=FakeResponse(page)):
            img = build.fetch_preview_image("https://news.example.test/story/1")
        self.assertEqual(img, "https://news.example.test/img/cover.jpg")

    def test_http_only_or_missing_image_returns_none(self):
        page = b'<meta property="og:image" content="http://insecure.test/a.jpg">'
        with mock.patch("urllib.request.urlopen", return_value=FakeResponse(page)):
            self.assertIsNone(build.fetch_preview_image("https://news.example.test/x"))
        with mock.patch("urllib.request.urlopen", side_effect=OSError("offline")):
            self.assertIsNone(build.fetch_preview_image("https://news.example.test/x"))

    def test_enrich_checks_each_item_once_and_respects_budget(self):
        items = [
            {"link": "https://a.test/1", "published": "2026-10-19T09:00:00+00:00", "image": None},
            {"link": "https://a.test/2", "published": "2026-10-19T08:00:00+00:00", "image": "https://feed.test/x.jpg"},
            {"link": "https://a.test/3", "published": "2026-10-19T07:00:00+00:00", "image": None},
        ]
        with mock.patch.object(build, "fetch_preview_image", return_value="https://a.test/og.jpg") as f:
            build.enrich_images(items, budget=1)
            self.assertEqual(f.call_count, 1)
            build.enrich_images(items, budget=5)
            self.assertEqual(f.call_count, 2)  # item 3 only; item 1 done, item 2 has a feed image
        self.assertEqual(items[0]["image"], "https://a.test/og.jpg")
        self.assertTrue(items[2]["image_checked"])


class Design(unittest.TestCase):
    def test_fallback_cover_names_vendor_and_is_svg(self):
        uri = build.fallback_cover(story("x", prio="Critical", vendors=["ConnectWise"]))
        self.assertTrue(uri.startswith("data:image/svg+xml"))
        self.assertIn("ConnectWise", unquote(uri))

    def test_filter_counts_match_tags(self):
        stories = [story("a", tags=["critical", "exploited"]), story("b", tags=["ai"]), story("c", tags=["exploited"])]
        bar = build.filter_bar(stories)
        self.assertIn('data-filter="all" aria-pressed="true">All <span class="count">3</span>', bar)
        self.assertIn('data-filter="exploited" aria-pressed="false">Actively exploited <span class="count">2</span>', bar)
        self.assertIn('data-filter="critical" aria-pressed="false">Critical <span class="count">1</span>', bar)

    def test_index_has_summary_and_keeps_two_scripts(self):
        stories = [story("Top story here", tags=["critical"], prio="Critical"), story("Second story here")]
        status = {"sources_ok": 6, "sources_total": 7}
        page = build.index_page(stories, {"site_name": "Security Brief", "site_url": "https://example.test"},
                                NOW, status, [], {})
        self.assertIn('class="stats"', page)
        self.assertNotIn("sources reachable", page)  # source counter removed from homepage
        self.assertIn('class="hero"', page)
        self.assertEqual(page.count("<script"), 2)
        self.assertNotIn("Generated category cover", page)

    def test_story_page_without_image_uses_branded_cover(self):
        s = story("Breach story title", prio="High", vendors=["Fortinet"])
        page = build.story_page(s, {"site_name": "Security Brief", "site_url": "https://example.test"})
        self.assertIn("data:image/svg+xml", page)
        self.assertIn("Illustration", page)


if __name__ == "__main__":
    unittest.main()
