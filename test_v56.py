import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import build  # noqa: E402

NOW = datetime(2026, 10, 19, 12, 0, tzinfo=timezone.utc)
CFG = {"site_name": "Security Brief", "site_url": "https://example.test"}


def st(title, cves=(), tags=(), kev=(), source="BleepingComputer", score=3, category="microsoft"):
    return {"id": title.lower().replace(" ", "")[:10], "title": title, "summary": "x", "published": "2026-10-19T08:00:00+00:00",
            "category": category, "tags": list(tags), "priority": "Standard", "score": score, "reasons": [],
            "cves": list(cves), "vendors": [], "kev": list(kev), "kev_checked": True, "image": None,
            "image_source": None,
            "sources": [{"name": source, "title": title, "url": "https://example.test/a", "published": "2026-10-19T08:00:00+00:00"}]}


class Categories(unittest.TestCase):
    def test_cloud_category_is_gone(self):
        self.assertNotIn("cloud", build.CATEGORIES)
        self.assertNotIn("cloud", build.CATEGORY_ORDER)
        self.assertEqual(build.CATEGORIES["microsoft"][0], "Microsoft")

    def test_identity_and_entra_stories_go_to_microsoft(self):
        for title in ["Entra ID sign-in anomalies", "Conditional Access bypass found",
                      "MFA fatigue attacks rise", "Azure AD tenant takeover technique"]:
            self.assertEqual(build.categorize(title), "microsoft", title)

    def test_nav_has_no_cloud_entry(self):
        page = build.index_page([st("A story")], CFG, NOW, {"sources_ok": 1, "sources_total": 1}, [], {})
        self.assertNotIn("Cloud &amp; Identity", page)
        self.assertNotIn("index.html#cloud", page)
        self.assertIn('href="category/microsoft/index.html"', page)


class CveTable(unittest.TestCase):
    def test_only_msrc_stories_with_cves_are_listed_kev_first(self):
        stories = [
            st("Windows flaw one", cves=["CVE-2026-1"], source="Microsoft Security Response Center", score=5),
            st("Exchange flaw KEV", cves=["CVE-2026-2"], kev=["CVE-2026-2"],
               source="Microsoft Security Response Center", score=1),
            st("MSRC note without CVE", source="Microsoft Security Response Center"),
            st("Third party CVE", cves=["CVE-2026-3"], source="BleepingComputer"),
        ]
        rows = build.msrc_cve_rows(stories)
        self.assertEqual([r["title"] for r in rows], ["Exchange flaw KEV", "Windows flaw one"])

    def test_table_shows_kev_and_disclaimer(self):
        html_out = build.cve_table(build.msrc_cve_rows([
            st("Exchange flaw KEV", cves=["CVE-2026-2"], kev=["CVE-2026-2"], source="Microsoft Security Response Center")]))
        self.assertIn("CVE-2026-2", html_out)
        self.assertIn(">KEV<", html_out)
        self.assertIn("not the complete Patch Tuesday list", html_out)

    def test_empty_state(self):
        self.assertIn("No Microsoft CVE entries", build.cve_table([]))

    def test_section_page_only_gets_table_for_patch_tuesday(self):
        page = build.section_page("patch-tuesday", [], CFG, {}, cve_rows=[])
        self.assertIn('id="cve-table"', page)
        page2 = build.section_page("briefings", [], CFG, {})
        self.assertNotIn('id="cve-table"', page2)


class Design(unittest.TestCase):
    def test_save_button_has_icon_and_label_span(self):
        page = build.index_page([st("A story")], CFG, NOW, {"sources_ok": 1, "sources_total": 1}, [], {})
        self.assertIn('<span>Save</span>', page)
        self.assertIn('<path d="M6 3h12v18l-6-4-6 4z"', page)

    def test_search_has_icon_and_pill_input(self):
        page = build.index_page([st("A story")], CFG, NOW, {"sources_ok": 1, "sources_total": 1}, [], {})
        self.assertIn('class="search" type="search"', page)
        self.assertIn('<svg width="18" height="18"', page)


if __name__ == "__main__":
    unittest.main()
