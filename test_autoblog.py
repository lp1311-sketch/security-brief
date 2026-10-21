"""Single test file for Security Brief. Runs offline with the sample feeds in this folder.

Run from the repository root:
    python3 -m unittest test_autoblog -v
"""
import json
import shutil
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import build  # noqa: E402

NOW = datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc)


def item(title, summary="", **kw):
    base = {"title": title, "summary": summary, "tags": [], "cves": [], "kev": False, "category": "threats"}
    base.update(kw)
    return base


class Categories(unittest.TestCase):
    def test_named_categories_exist(self):
        for cid in ("threats", "vulnerabilities", "ai", "microsoft", "general"):
            self.assertIn(cid, build.CATEGORIES)

    def test_ransomware_is_attacks(self):
        self.assertEqual(build.categorize("Ransomware gang breaches hospital network"), "threats")

    def test_patch_news_is_vulnerabilities(self):
        self.assertEqual(build.categorize("Vendor ships patch for CVE-2026-1234"), "vulnerabilities")

    def test_unrelated_text_falls_back_to_general(self):
        self.assertEqual(build.categorize("Weather in Berlin"), "general")


class WhyItMatters(unittest.TestCase):
    def test_personal_data_breach_names_gdpr(self):
        text = build.why_it_matters(item("Nikkei breach", "1.83 million personal information records exposed"))
        self.assertIn("Personal data", text)
        self.assertIn("Art. 33", text)

    def test_kev_cve_is_confirmed_and_named(self):
        text = build.why_it_matters(item("Windows flaw", "patch released", cves=["CVE-2026-1111"], kev=True))
        self.assertIn("Known Exploited Vulnerabilities", text)
        self.assertIn("CVE-2026-1111", text)

    def test_no_signal_uses_category_text(self):
        self.assertEqual(build.why_it_matters(item("Weather", "sunny", category="general")), build.WHY["general"])

    def test_at_most_three_sentences_kept(self):
        text = build.why_it_matters(item(
            "Ransomware web shell backdoor npm package",
            "ransomware gang stole customer records, OAuth consent abused, API keys exposed",
            cves=["CVE-2026-2222"], kev=True))
        self.assertIn("Known Exploited", text)
        self.assertNotIn("Ransomware intrusions", text)


class BroadVendorFeeds(unittest.TestCase):
    def test_security_post_is_kept(self):
        self.assertTrue(build.is_security_item(item("Phishing campaign targets Entra users")))

    def test_feature_post_is_dropped(self):
        self.assertFalse(build.is_security_item(item("New Word feature for dark mode")))


class Articles(unittest.TestCase):
    def test_flat_root_files_are_loaded_and_drafts_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "good-analysis.md").write_text(
                "---\ntitle: Good analysis\ndate: 2026-10-20\ndraft: false\n---\nBody text.\n", encoding="utf-8")
            (tmp / "draft-piece.md").write_text(
                "---\ntitle: Draft\ndate: 2026-10-20\ndraft: true\n---\nNot ready.\n", encoding="utf-8")
            (tmp / "_template.md").write_text("---\ntitle: T\ndate: 2026-10-20\ndraft: false\n---\n", encoding="utf-8")
            warnings = []
            arts = build.load_articles(tmp / "content", warnings)
            slugs = [a["slug"] for a in arts]
            self.assertIn("good-analysis", slugs)
            self.assertNotIn("draft-piece", slugs)
            self.assertNotIn("_template", slugs)

    def test_patch_tuesday_name_selects_section(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "patch-tuesday-notes-2026-10-20.md").write_text(
                "---\ntitle: PT\ndate: 2026-10-20\ndraft: false\n---\nx\n", encoding="utf-8")
            arts = build.load_articles(tmp / "content", [])
            self.assertEqual(arts[0]["section"], "patch-tuesday")


class Legal(unittest.TestCase):
    def setUp(self):
        self.cfg = json.loads((ROOT / "feeds.json").read_text(encoding="utf-8"))

    def test_impressum_shows_publisher_when_complete(self):
        site = {"publisher": {"name": "Leon Pavesic", "address": "Kellerstr. 8\n83022 Rosenheim",
                              "email": "leon.pavesic@gmx.de"}}
        imp = build.legal_pages(site, self.cfg)["impressum.html"]
        self.assertIn("Kellerstr. 8", imp)
        self.assertIn("Urheberrecht", imp)

    def test_impressum_placeholder_when_incomplete(self):
        imp = build.legal_pages({"publisher": {}}, self.cfg)["impressum.html"]
        self.assertIn("Angaben werden ergänzt", imp)

    def test_corrections_list_is_rendered(self):
        site = {"corrections": [{"date": "20 Oct 2026", "note": "Fixed a rating"}]}
        page = build.legal_pages(site, self.cfg)["corrections.html"]
        self.assertIn("Fixed a rating", page)


class OfflineBuild(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cfg = json.loads((ROOT / "feeds.json").read_text(encoding="utf-8"))
        cfg["site_url"] = "https://test.example.org/brief"
        cls.status = build.run(cfg, cls.tmp / "site", cls.tmp / "stories.json", ROOT, NOW)
        cls.site = cls.tmp / "site"

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def read(self, rel):
        return (self.site / rel).read_text(encoding="utf-8")

    def test_core_pages_exist(self):
        for rel in ("index.html", "feed.xml", "sitemap.xml", "status.json", "style.css",
                    "impressum.html", "datenschutz.html", "corrections.html", "favicon.svg",
                    "stories/index.html", "patch-tuesday/index.html", "briefings/index.html"):
            self.assertTrue((self.site / rel).exists(), rel)

    def test_category_pages_exist(self):
        for cid in ("threats", "vulnerabilities", "ai", "microsoft", "general"):
            self.assertTrue((self.site / "category" / cid / "index.html").exists(), cid)

    def test_logo_in_header(self):
        self.assertIn("logo-img", self.read("index.html"))

    def test_nav_links_to_category_pages_not_anchors(self):
        page = self.read("index.html")
        self.assertIn('href="category/microsoft/index.html"', page)
        self.assertNotIn("index.html#microsoft", page)

    def test_no_source_health_notice_or_run_status_link_for_visitors(self):
        page = self.read("index.html")
        self.assertNotIn("did not update in the last run", page)
        self.assertNotIn("Run status", page)

    def test_sources_monitored_counter_without_split(self):
        page = self.read("index.html")
        self.assertIn("sources monitored", page)
        self.assertNotIn("sources reachable", page)

    def test_footer_copyright_and_contact(self):
        page = self.read("index.html")
        self.assertIn("Leon Pavesic", page)
        self.assertIn("mailto:leon.pavesic@gmx.de", page)

    def test_no_donation_section_without_configured_links(self):
        self.assertNotIn("Support this site", self.read("index.html"))

    def test_feed_and_sitemap_use_site_url(self):
        self.assertIn("https://test.example.org/brief/", self.read("feed.xml"))
        self.assertIn("https://test.example.org/brief/stories/index.html", self.read("sitemap.xml"))

    def test_status_file_reports_changed_on_first_run(self):
        self.assertTrue(self.status["changed"])

    def test_render_version_is_set(self):
        self.assertRegex((ROOT / "build.py").read_text(encoding="utf-8"), r'"render": "5\.\d+"')


if __name__ == "__main__":
    unittest.main()
