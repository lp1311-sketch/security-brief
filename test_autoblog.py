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
FIXTURES = ROOT / "tests" / "fixtures"


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
        cls.status = build.run(cfg, cls.tmp / "site", cls.tmp / "stories.json", FIXTURES, NOW)
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

    def test_free_download_is_copied_linked_and_sitemap_listed(self):
        filename = "m365-identity-incident-triage-checklist.pdf"
        self.assertTrue((self.site / filename).is_file(), filename)
        self.assertIn("Free field guide", self.read("index.html"))
        self.assertIn(f'href="{filename}" download', self.read("index.html"))
        self.assertIn(f"https://test.example.org/brief/{filename}", self.read("sitemap.xml"))

    def test_google_search_console_verification_file_is_copied_to_site_root(self):
        filename = "google06dce61680795c6c.html"
        expected = "google-site-verification: google06dce61680795c6c.html"
        self.assertTrue((self.site / filename).is_file(), filename)
        self.assertEqual((self.site / filename).read_text(encoding="utf-8").strip(), expected)

    def test_homepage_separates_content_publication_from_feed_check(self):
        page = self.read("index.html")
        self.assertIn("Last content publication:", page)
        self.assertIn('id="feed-freshness"', page)
        self.assertIn("status.json?fresh=", page)
        self.assertIn("Browse and filter all", page)
        self.assertNotIn('id="story-search"', page)

    def test_homepage_analysis_and_free_guide_follow_news_before_footer(self):
        page = self.read("index.html")
        news = page.index("Browse and filter all")
        guide = page.index('id="free-downloads"')
        analysis = page.index('id="analysis"')
        footer = page.index('<footer')
        self.assertLess(news, guide)
        self.assertLess(guide, analysis)
        self.assertLess(analysis, footer)

    def test_full_story_list_has_date_sort_and_important_filters(self):
        page = self.read("stories/index.html")
        self.assertIn('id="date-filter"', page)
        self.assertIn('value="24"', page)
        self.assertIn('value="72"', page)
        self.assertIn('value="168"', page)
        self.assertIn('id="sort-filter"', page)
        self.assertIn('id="important-only"', page)
        self.assertIn('data-published=', page)
        self.assertIn('data-priority-rank=', page)

    def test_priority_explanation_separates_editorial_score_from_cvss(self):
        data = json.loads(self.read("stories.json"))
        self.assertIn("priority_basis", data["stories"][0])
        first_story = self.site / data["stories"][0]["url"]
        page = first_story.read_text(encoding="utf-8")
        self.assertIn("Editorial triage priority", page)
        self.assertIn("not a CVSS severity score", page)
        self.assertIn("Scoring signals", page)

    def test_status_refreshes_without_content_change(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            cfg = json.loads((ROOT / "feeds.json").read_text(encoding="utf-8"))
            cfg["site_url"] = "https://test.example.org/brief"
            out, data_file = tmp / "site", tmp / "data" / "stories.json"
            first_time = NOW
            first = build.run(cfg, out, data_file, FIXTURES, first_time)
            first_status = json.loads((out / "status.json").read_text(encoding="utf-8"))
            stale = dict(first_status)
            stale["last_check_at"] = "2000-01-01T00:00:00+00:00"
            (out / "status.json").write_text(json.dumps(stale), encoding="utf-8")
            second = build.run(cfg, out, data_file, FIXTURES, first_time)
            second_status = json.loads((out / "status.json").read_text(encoding="utf-8"))
            self.assertFalse(second["changed"])
            self.assertEqual(second_status["last_check_at"], first_status["last_check_at"])
            self.assertEqual(first_status["content_published_at"], second_status["content_published_at"])
            successful = next(x for x in second_status["sources"] if x["ok"])
            self.assertEqual(successful["last_success_at"], second_status["last_check_at"])
            self.assertGreater(second_status["sources_ok"], 0)
            self.assertLessEqual(second_status["sources_ok"], second_status["sources_total"])
            self.assertTrue(first["changed"])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_failed_feed_retains_last_success_timestamp(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            fixture_copy = tmp / "fixtures"
            shutil.copytree(FIXTURES, fixture_copy)
            cfg = json.loads((ROOT / "feeds.json").read_text(encoding="utf-8"))
            cfg["site_url"] = "https://test.example.org/brief"
            out, data_file = tmp / "site", tmp / "data" / "stories.json"
            build.run(cfg, out, data_file, fixture_copy, NOW)
            before = json.loads((out / "status.json").read_text(encoding="utf-8"))
            source_before = next(x for x in before["sources"] if x["id"] == "bleepingcomputer")
            (fixture_copy / "bleepingcomputer.xml").unlink()
            build.run(cfg, out, data_file, fixture_copy, NOW)
            after = json.loads((out / "status.json").read_text(encoding="utf-8"))
            source_after = next(x for x in after["sources"] if x["id"] == "bleepingcomputer")
            self.assertTrue(source_before["ok"])
            self.assertFalse(source_after["ok"])
            self.assertEqual(source_after["last_success_at"], source_before["last_success_at"])
            self.assertIn("last_attempt_at", source_after)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

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

    def test_single_buy_me_a_coffee_block_retains_qr_and_sits_before_editorial_sections(self):
        cfg = {"site_name": "Security Brief", "site_url": "https://example.org", "description": "d"}
        status = {"sources_total": 1, "content_published_at": NOW.isoformat()}
        article = {"section": "briefings", "slug": "sample", "title": "Sample analysis",
                   "summary": "A sample analysis.", "date": "2026-10-20"}
        site_cfg = {"donations": [{"provider": "buymeacoffee", "label": "Buy me a coffee",
                                   "url": "https://buymeacoffee.com/leonpavesic"}],
                    "donation_text": "If Security Brief saves you time, you can buy me a coffee.",
                    "donation_qr": "buymeacoffee-qr.png"}
        page = build.index_page([], cfg, NOW, status, [article], site_cfg)
        self.assertEqual(page.count('class="support"'), 1)
        self.assertEqual(page.count(">Buy me a coffee &rarr;</a>"), 1)  # one visible button label
        self.assertEqual(page.count("QR code linking to the Buy me a coffee page"), 1)
        self.assertLess(page.index('class="support"'), page.index('id="analysis"'))

    def test_feed_and_sitemap_use_site_url(self):
        self.assertIn("https://test.example.org/brief/", self.read("feed.xml"))
        self.assertIn("https://test.example.org/brief/stories/index.html", self.read("sitemap.xml"))

    def test_status_file_reports_changed_on_first_run(self):
        self.assertTrue(self.status["changed"])

    def test_render_version_is_set(self):
        self.assertRegex((ROOT / "build.py").read_text(encoding="utf-8"), r'"render": "5\.\d+"')


class Design(unittest.TestCase):
    def test_article_cover_is_branded_svg(self):
        a = {"title": "Weekly M365 and Entra briefing with a long title that wraps across lines", "section": "briefings", "summary": "", "slug": "x", "date": "2026-10-20"}
        cover = build.article_cover(a)
        self.assertTrue(cover.startswith("data:image/svg+xml"))
        self.assertIn("ANALYSIS", cover.upper())

    def test_donations_only_show_configured_https_links(self):
        self.assertEqual(build.donation_links({"donations": []}), [])
        self.assertEqual(build.donation_links({"donations": [{"label": "X", "url": "http://insecure.example"}]}), [])
        self.assertEqual(build.donation_links({"donations": [{"provider": "kofi", "url": "https://ko-fi.com/example"}]}),
                         [("Ko-fi", "https://ko-fi.com/example")])
        self.assertEqual(build._donate({"donations": []}), "")

    def test_motion_layer_respects_reduced_motion(self):
        self.assertIn("prefers-reduced-motion", build.DESIGN_CSS)
        cfg = {"site_name": "Security Brief", "site_url": "https://example.com/sb", "description": "d"}
        html = build._layout(cfg, "Test", "Desc", "<p>body</p>", "")
        self.assertIn('class="fx"', html)
        self.assertIn('class="led g"', html)
        self.assertIn('class="led r"', html)
        self.assertIn('id="banner-text"', html)
        self.assertIn("Every story links", build.BANNER_JS)


class FeedEndpoints(unittest.TestCase):
    def test_confirmed_publisher_rss_links_are_configured(self):
        cfg = json.loads((ROOT / "feeds.json").read_text(encoding="utf-8"))
        sources = {source["id"]: source for source in cfg["sources"]}
        self.assertEqual(sources["google-threat-intel"]["url"],
                         "https://feeds.feedburner.com/threatintelligence/pvexyqv7v0v")
        self.assertEqual(sources["sophos"]["url"],
                         "https://news.sophos.com/en-us/blog/feed?id=blt6f15f4f7deaf4242")
        self.assertEqual(sources["cisa"]["url"],
                         "https://www.cisa.gov/cybersecurity-advisories/all.xml")


class EditorialPresentation(unittest.TestCase):
    def test_ordered_markdown_becomes_action_cards(self):
        rendered = build.md_to_html("1. **Check exposure.** Restrict public management access.\n2. Review logs.")
        self.assertIn('<ol class="action-list">', rendered)
        self.assertIn("<li><strong>Check exposure.</strong> Restrict public management access.</li>", rendered)
        self.assertIn("<li>Review logs.</li>", rendered)
        self.assertEqual(rendered.count("<li>"), 2)

    def test_article_headings_get_navigation_anchors(self):
        rendered = build.md_to_html("## Short answer\n\nBrief.\n\n## What to check\n\nSteps.")
        toc = build.article_toc(rendered)
        self.assertIn('id="section-1-short-answer"', rendered)
        self.assertIn('href="#section-2-what-to-check"', toc)
        self.assertIn("On this page", toc)

    def test_filter_panel_is_visible_and_has_reset(self):
        page = build.filter_bar([item("Important CVE", tags=["critical"])])
        self.assertIn('class="filter-panel"', page)
        self.assertIn('id="reset-filters"', page)
        self.assertIn('id="date-filter"', page)
        self.assertIn('id="sort-filter"', page)
        self.assertIn('id="important-only"', page)
        self.assertNotIn("<details", page)

    def test_mailchimp_signup_cta_uses_only_public_https_link(self):
        cfg = {"newsletter_signup_url": "https://example.us1.list-manage.com/subscribe?u=public"}
        html_out = build._newsletter(cfg, "")
        self.assertIn("THE WEEKLY SIGNAL", html_out)
        self.assertIn("Get the weekly briefing", html_out)
        self.assertIn('href="https://example.us1.list-manage.com/subscribe?u=public"', html_out)
        self.assertNotIn("api_key", html_out.lower())
        self.assertEqual(build._newsletter({"newsletter_signup_url": "http://example.com"}, ""), "")

    def test_analysis_page_uses_new_layout_and_reading_controls(self):
        arts = build.load_articles(ROOT / "content", [])
        self.assertTrue(arts)
        cfg = {"site_name": "Security Brief", "site_url": "https://test.example.org/brief", "description": "test"}
        page = build.article_page(arts[0], cfg, {"donations": []})
        self.assertIn('class="analysis-hero"', page)
        self.assertIn('class="article-toc"', page)
        self.assertIn("min read", page)
        self.assertIn('<ol class="action-list">', page)
        self.assertNotIn("Original link to add after review", page)
        self.assertIn("china-linked-hackers-exploited.html", page)
        self.assertIn("ahsaycbs-flaws-exploited-to-deploy-web.html", page)


if __name__ == "__main__":
    unittest.main()
