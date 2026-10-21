import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import build  # noqa: E402

NOW = datetime(2026, 10, 19, 12, 0, tzinfo=timezone.utc)
CFG = {"site_name": "Security Brief", "site_url": "https://example.test"}


def st(title, tags=(), vendors=(), kev=(), prio="Standard", score=3, category="threats"):
    return {"id": title.lower().replace(" ", "")[:10], "title": title, "summary": "x", "published": None,
            "category": category, "tags": list(tags), "priority": prio, "score": score, "reasons": [],
            "cves": [], "vendors": list(vendors), "kev": list(kev), "kev_checked": True, "image": None,
            "image_source": None, "sources": [{"name": "BleepingComputer", "title": title,
                                               "url": "https://example.test/a", "published": None}]}


class ActionRules(unittest.TestCase):
    def test_kev_is_patch_now(self):
        a = build.suggest_action(st("Flaw", kev=["CVE-2026-1"], tags=["critical", "patch-now"], vendors=["Fortinet"]))
        self.assertEqual(a["kind"], "patch")
        self.assertIn("Known Exploited Vulnerabilities", a["text"])
        self.assertFalse(a["text"].startswith("Patch"))
        self.assertEqual(a["product"], "Fortinet")

    def test_exploited_without_cve_is_investigate(self):
        a = build.suggest_action(st("Attack", tags=["exploited"]))
        self.assertEqual(a["kind"], "investigate")

    def test_microsoft_tag_is_review_and_names_product(self):
        a = build.suggest_action(st("Entra sign-in change", tags=["entra"], category="cloud"))
        self.assertEqual(a["kind"], "review")
        self.assertEqual(a["product"], "Entra ID")

    def test_no_signal_says_no_action_identified(self):
        a = build.suggest_action(st("General news"))
        self.assertEqual(a["kind"], "monitor")
        self.assertIn("No immediate action identified", a["text"])


class TodayPage(unittest.TestCase):
    def test_top_five_sorted_by_action_then_score(self):
        stories = [st(f"Story {i}", score=i) for i in range(8)]
        stories.append(st("Patch me", kev=["CVE-1"], tags=["patch-now"], score=1))
        page = build.today_page(stories, CFG, NOW)
        self.assertEqual(page.count('<article class="todo'), 5)
        self.assertTrue(page.index("Patch me") < page.index("Story 7"))

    def test_page_is_labelled_as_suggestion_and_links_source(self):
        page = build.today_page([st("Attack", tags=["exploited"])], CFG, NOW)
        self.assertIn("not from a person", page)
        self.assertIn("https://example.test/a", page)
        self.assertEqual(page.count("<script"), 1)  # theme toggle only

    def test_index_links_to_today_and_nav_has_it(self):
        page = build.index_page([st("A story")], CFG, NOW, {"sources_ok": 1, "sources_total": 1}, [], {})
        self.assertIn('href="today/index.html"', page)
        self.assertEqual(page.count("<script"), 2)


class LinkPreviews(unittest.TestCase):
    def test_og_tags_present_and_image_only_when_https(self):
        with_img = build._og_tags(CFG, "T", "D", "https://img.test/a.jpg")
        self.assertIn('property="og:image" content="https://img.test/a.jpg"', with_img)
        self.assertIn("summary_large_image", with_img)
        no_img = build._og_tags(CFG, "T", "D", "data:image/svg+xml,xx")
        self.assertNotIn("og:image", no_img)
        self.assertIn('name="twitter:card" content="summary"', no_img)


if __name__ == "__main__":
    unittest.main()
