import json
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import build  # noqa: E402

NOW = datetime(2026, 10, 19, 12, 0, tzinfo=timezone.utc)
CFG = {"site_name": "Security Brief", "site_url": "https://example.test"}


def st(title, tags=(), prio="Standard"):
    return {"id": title.lower().replace(" ", "")[:10], "title": title, "summary": "Short summary text.",
            "published": "2026-10-19T08:00:00+00:00", "category": "threats", "tags": list(tags),
            "priority": prio, "score": 3, "reasons": [], "cves": [], "vendors": ["Fortinet"], "kev": [],
            "kev_checked": True, "image": None, "image_source": None,
            "sources": [{"name": "BleepingComputer", "title": title, "url": "https://example.test/a",
                         "published": "2026-10-19T08:00:00+00:00"}]}


def scripts(page):
    return page.count("<script")


class Search(unittest.TestCase):
    def test_index_has_search_box_and_searchable_cards(self):
        page = build.index_page([st("Fortinet flaw", ["critical"], "Critical"), st("Other news")],
                                CFG, NOW, {"sources_ok": 1, "sources_total": 1}, [], {})
        self.assertIn('id="story-search"', page)
        self.assertIn('data-search="', page)
        self.assertIn("fortinet", page)  # vendor is searchable
        self.assertEqual(scripts(page), 2)  # theme toggle + one combined page script


class Saving(unittest.TestCase):
    def test_cards_have_save_buttons(self):
        page = build.index_page([st("A story")], CFG, NOW, {"sources_ok": 1, "sources_total": 1}, [], {})
        self.assertIn('data-save="', page)
        self.assertIn('<span>Save</span>', page)

    def test_saved_page_reads_index_and_uses_local_storage_only(self):
        page = build.saved_page(CFG)
        self.assertIn("localStorage", page)
        self.assertIn("../stories.json", page)
        self.assertNotIn("fetch('https://", page)
        self.assertEqual(scripts(page), 2)
        self.assertIn("Saved in this browser only", page)

    def test_stories_index_is_plain_data(self):
        data = json.loads(build.stories_index([st("A story", ["critical"], "Critical")]))
        row = data["stories"][0]
        self.assertEqual(row["url"], "story/astory.html")
        self.assertEqual(row["priority"], "Critical")
        self.assertNotIn("<", json.dumps(row))


class Navigation(unittest.TestCase):
    def test_nav_has_today_and_saved(self):
        page = build.index_page([st("A story")], CFG, NOW, {"sources_ok": 1, "sources_total": 1}, [], {})
        self.assertIn('href="saved/index.html">Saved</a>', page)
        self.assertIn('href="today/index.html">Today</a>', page)

    def test_privacy_notice_mentions_local_list(self):
        pages = build.legal_pages({"publisher": {}}, CFG)
        self.assertIn("Merkliste", pages["datenschutz.html"])


if __name__ == "__main__":
    unittest.main()
