import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import build  # noqa: E402

NOW = datetime(2026, 10, 20, 8, 0, tzinfo=timezone.utc)


def it(src, official, title, summary, source_type="news"):
    return {"source": src, "official": official, "source_type": source_type, "title": title,
            "summary": summary, "cves": [], "published": "2026-10-19T10:00:00+00:00", "link": "x"}


class PriorityRules(unittest.TestCase):
    def test_news_zero_day_wording_is_not_critical(self):
        self.assertNotEqual(build.score_story([it("Krebs", False, "Patches 1,400 flaws", "one zero-day")], set(), False, NOW)[1], "Critical")

    def test_clustered_official_item_without_exploit_claim_is_not_critical(self):
        items = [it("Krebs", False, "Patches 1,400 flaws", "updates"),
                 it("MSRC", True, "Security Update Guide release", "Summary of release", "advisory")]
        self.assertNotEqual(build.score_story(items, set(), False, NOW)[1], "Critical")

    def test_official_advisory_with_exploit_claim_is_critical(self):
        items = [it("CISA", True, "Flaw", "Vulnerability is actively exploited in attacks", "advisory")]
        self.assertEqual(build.score_story(items, set(), False, NOW)[1], "Critical")

    def test_vendor_blog_flagged_official_cannot_be_critical(self):
        items = [it("Google", True, "Chrome research", "Actively exploited in the wild", "vendor_blog")]
        self.assertNotEqual(build.score_story(items, set(), False, NOW)[1], "Critical")

    def test_kev_still_critical(self):
        items = [dict(it("Krebs", False, "Flaw CVE-2026-1", "details"), cves=["CVE-2026-1"])]
        self.assertEqual(build.score_story(items, {"CVE-2026-1"}, True, NOW)[1], "Critical")


if __name__ == "__main__":
    unittest.main()
