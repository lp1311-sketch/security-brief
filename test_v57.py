import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import build  # noqa: E402

CFG = {"site_name": "Security Brief", "site_url": "https://example.test"}
MON_0700 = datetime(2026, 10, 19, 7, 0, tzinfo=timezone.utc)   # Monday
MON_0500 = datetime(2026, 10, 19, 5, 0, tzinfo=timezone.utc)
TUE_0700 = datetime(2026, 10, 20, 7, 0, tzinfo=timezone.utc)


def st(title, tags=(), cves=(), vendors=(), prio="Standard", score=3, kev=()):
    return {"id": title.lower().replace(" ", "")[:10], "title": title, "summary": "x",
            "published": "2026-10-19T08:00:00+00:00", "category": "microsoft", "tags": list(tags),
            "priority": prio, "score": score, "reasons": [], "cves": list(cves), "vendors": list(vendors),
            "kev": list(kev), "kev_checked": True, "image": None, "image_source": None,
            "sources": [{"name": "BleepingComputer", "title": title, "url": "https://news.example.test/a",
                         "published": "2026-10-19T08:00:00+00:00"}]}


class Timing(unittest.TestCase):
    def test_due_once_on_monday_after_six_utc(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d)
            self.assertTrue(build.digest_due(out, MON_0700))
            self.assertFalse(build.digest_due(out, MON_0500))
            self.assertFalse(build.digest_due(out, TUE_0700))
            (out / "digest").mkdir()
            (out / "digest" / "2026-10-19.html").write_text("x", encoding="utf-8")
            self.assertFalse(build.digest_due(out, MON_0700))


class Content(unittest.TestCase):
    def test_snapshot_has_stats_top_list_and_external_links_only(self):
        stories = [st("Exchange flaw", tags=["critical", "exploited", "patch-now"], cves=["CVE-2026-1"],
                      vendors=["Fortinet"], prio="Critical", score=9, kev=["CVE-2026-1"]),
                   st("Other news", score=2)]
        page = build.digest_snapshot(stories, CFG, MON_0700)
        self.assertIn("Weekly digest: week ending 19 Oct 2026", page)
        self.assertIn("CVE-2026-1", page)
        self.assertIn("Fortinet (1)", page)
        self.assertIn("Patch now", page)
        self.assertIn("https://news.example.test/a", page)
        self.assertNotIn('href="../story/', page)  # snapshots must not depend on pages that expire

    def test_empty_window(self):
        self.assertIn("No stories in this window", build.digest_snapshot([], CFG, MON_0700))


class WriteSite(unittest.TestCase):
    def test_monday_build_writes_snapshot_and_archive_index(self):
        status = {"sources_ok": 1, "sources_total": 1, "warnings": []}
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "docs"
            build.write_site(out, [st("A story")], CFG, MON_0700, status, [], {})
            self.assertTrue((out / "digest" / "2026-10-19.html").exists())
            index = (out / "digest" / "index.html").read_text(encoding="utf-8")
            self.assertIn('href="2026-10-19.html"', index)
            self.assertIn("Week ending 19 Oct 2026", index)
            home = (out / "index.html").read_text(encoding="utf-8")
            self.assertIn('href="digest/index.html">Digest</a>', home)

    def test_editions_are_kept_newest_first(self):
        status = {"sources_ok": 1, "sources_total": 1, "warnings": []}
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "docs"
            build.write_site(out, [st("A story")], CFG, MON_0700, status, [], {})
            nxt = datetime(2026, 10, 26, 7, 0, tzinfo=timezone.utc)
            build.write_site(out, [st("A story")], CFG, nxt, status, [], {})
            index = (out / "digest" / "index.html").read_text(encoding="utf-8")
            self.assertLess(index.index("2026-10-26.html"), index.index("2026-10-19.html"))


if __name__ == "__main__":
    unittest.main()
