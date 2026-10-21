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
SRC_BC = {"id": "bleepingcomputer", "name": "BleepingComputer", "official": False}
SRC_THN = {"id": "thehackernews", "name": "The Hacker News", "official": False}
SRC_CISA = {"id": "cisa", "name": "CISA", "official": True}


class ParseTests(unittest.TestCase):
    def test_rss_items_images_and_cleaning(self):
        items = build.parse_feed((FIX / "bleepingcomputer.xml").read_bytes(), SRC_BC)
        titles = [i["title"] for i in items]
        self.assertNotIn("Broken item without link", titles)
        win = next(i for i in items if "Windows" in i["title"])
        self.assertEqual(win["image"], "https://img.example-news.test/win.jpg")
        self.assertNotIn("utm_source", win["link"])
        self.assertEqual(win["cves"], ["CVE-2026-1111"])
        hosp = next(i for i in items if "hospital" in i["title"])
        self.assertEqual(hosp["image"], "https://img.example-news.test/hosp.png")
        self.assertNotIn("<p>", hosp["summary"])

    def test_enclosure_image_and_atom_alternate_link(self):
        thn = build.parse_feed((FIX / "thehackernews.xml").read_bytes(), SRC_THN)
        self.assertEqual(thn[0]["image"], "https://img.example.test/thn-win.jpg")
        cisa = build.parse_feed((FIX / "cisa.xml").read_bytes(), SRC_CISA)
        self.assertEqual(cisa[0]["link"], "https://www.cisa.example.test/news/kev-windows")
        self.assertIsNone(cisa[0]["image"])

    def test_non_https_image_rejected(self):
        self.assertIsNone(build.https_image("http://insecure.test/a.jpg"))
        self.assertIsNone(build.https_image("javascript:alert(1)"))


class RankTests(unittest.TestCase):
    def _items(self):
        files = [("bleepingcomputer", SRC_BC), ("thehackernews", SRC_THN), ("cisa", SRC_CISA)]
        items = []
        for fname, src in files:
            items += build.parse_feed((FIX / f"{fname}.xml").read_bytes(), src)
        return items

    def test_same_cve_clusters_together_and_critical_with_kev(self):
        items = self._items()
        kev = {"CVE-2026-1111"}
        groups = build.cluster(items)
        win = [g for g in groups if any("CVE-2026-1111" in i["cves"] for i in g)]
        self.assertEqual(len(win), 1)
        self.assertEqual(len(win[0]), 3)
        story = build.build_story(win[0], kev, True, NOW)
        self.assertEqual(story["priority"], "Critical")
        self.assertEqual(story["kev"], ["CVE-2026-1111"])
        self.assertEqual(story["category"], "vulnerabilities")
        self.assertTrue(story["image"])

    def test_no_kev_means_no_critical_from_kev_alone(self):
        items = [i for i in self._items() if i["source"] == "bleepingcomputer"][:1]
        story = build.build_story([items[0]], set(), False, NOW)
        self.assertNotEqual(story["priority"], "Critical")

    def test_exploited_by_official_source_is_critical(self):
        items = build.parse_feed((FIX / "cisa.xml").read_bytes(), SRC_CISA)
        items[0]["summary"] = "Exploited in the wild."
        story = build.build_story(items, set(), False, NOW)
        self.assertEqual(story["priority"], "Critical")

    def test_categories(self):
        self.assertEqual(build.categorize("Ransomware gang breaches hospital"), "threats")
        self.assertEqual(build.categorize("Entra ID sign-in anomalies"), "microsoft")
        self.assertEqual(build.categorize("Copilot prompt injection flaw"), "ai")
        self.assertEqual(build.categorize("Weather in Berlin"), "general")


class MergeTests(unittest.TestCase):
    def test_old_items_dropped_and_duplicates_merged(self):
        old = build.parse_feed((FIX / "bleepingcomputer.xml").read_bytes(), SRC_BC)
        stored = [dict(i) for i in old]
        fresh = [dict(old[0], summary="updated")]
        merged = build.merge(stored, fresh, NOW, retention_days=7)
        links = [m["link"] for m in merged]
        self.assertEqual(len(links), len(set(links)))
        self.assertFalse(any("insecure.example-news" in l for l in links))  # 2024 item expired
        self.assertEqual(next(m for m in merged if m["id"] == old[0]["id"])["summary"], "updated")


class EndToEndTests(unittest.TestCase):
    def test_offline_build_writes_site(self):
        cfg = json.loads((ROOT / "feeds.json").read_text(encoding="utf-8"))
        cfg["site_url"] = "https://test.example.org/brief"
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            status = build.run(cfg, tmp / "site", tmp / "stories.json", FIX, NOW)
            self.assertEqual(status["sources_ok"], 4)  # fixtures: bleepingcomputer, thehackernews, cisa, msblog
            index = (tmp / "site" / "index.html").read_text(encoding="utf-8")
            self.assertIn('class="hero"', index)
            self.assertIn("Microsoft Windows zero-day", index)
            story_files = list((tmp / "site" / "story").glob("*.html"))
            self.assertGreaterEqual(len(story_files), 3)
            feed = (tmp / "site" / "feed.xml").read_text(encoding="utf-8")
            self.assertIn("<rss", feed)
            self.assertIn("https://test.example.org/brief/story/", feed)
            self.assertIn("sitemap", (tmp / "site" / "robots.txt").read_text(encoding="utf-8"))
            # second run is idempotent w.r.t. stored data
            status2 = build.run(cfg, tmp / "site", tmp / "stories.json", FIX, NOW)
            self.assertEqual(status["stories"], status2["stories"])
            self.assertIn("Critical", (tmp / "site" / "index.html").read_text(encoding="utf-8"))
            # XSS: no raw script tag from feed text
            # only our own scripts may appear; feed text must not add scripts
            self.assertEqual(index.count("<script"), 2)  # theme toggle + topic filters


if __name__ == "__main__":
    unittest.main()
