import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import build  # noqa: E402

ARTICLE = """<html><head><script>var x = "You must update now. Apply the fix immediately ok";</script>
<style>p{}</style></head><body>
<nav><p>Home news should be read here. Subscribe to our newsletter for updates today.</p></nav>
<aside class="table-of-contents-block"><p>In this article: Microsoft recommends you should apply KB5127648 on all hosts.</p></aside>
<article>
<p>Microsoft recommends that administrators install update KB5127648 on all affected Windows Server hosts.</p>
<p>Customers should verify the version after installing and restart the Exchange services.</p>
<p>The company published the timeline of events in the attack on Monday morning for its customers.</p>
<li>Organisations must disable the legacy protocol until the patch is applied across the estate.</li>
<p>Subscribe to our newsletter and follow us on social media for the latest updates every day.</p>
<p>Users should be aware of phishing emails that claim to come from the vendor support desk.</p>
<p>Microsoft recommends that administrators install update KB5127648 on all affected Windows Server hosts.</p>
</article></body></html>"""

STORY = {"id": "s1", "title": "Patch KB5127648", "summary": "", "published": "2026-10-19T08:00:00+00:00",
         "category": "vulnerabilities", "tags": [], "priority": "Standard", "score": 3, "reasons": [],
         "cves": [], "vendors": [], "kev": [], "kev_checked": True, "image": None, "image_source": None,
         "instructions": [], "sources": [{"name": "BleepingComputer", "title": "Patch KB5127648",
                                          "url": "https://news.example.test/a", "published": None}]}
CFG = {"site_name": "Security Brief", "site_url": "https://example.test"}


class ExtractInstructions(unittest.TestCase):
    def setUp(self):
        self.out = build.extract_instructions(ARTICLE)

    def test_recommendations_are_kept(self):
        joined = " ".join(self.out)
        self.assertIn("Microsoft recommends that administrators install update KB5127648", joined)
        self.assertIn("Customers should verify the version", joined)
        self.assertIn("Organisations must disable the legacy protocol", joined)

    def test_navigation_ads_scripts_and_toc_are_ignored(self):
        joined = " ".join(self.out)
        self.assertNotIn("newsletter", joined.lower())
        self.assertNotIn("In this article", joined)
        self.assertNotIn("You must update now", joined)
        self.assertNotIn("Home news", joined)

    def test_news_sentence_without_action_is_ignored(self):
        self.assertFalse(any("timeline of events" in s for s in self.out))

    def test_no_duplicates_and_limit(self):
        self.assertEqual(len(self.out), len(set(x.lower() for x in self.out)))
        self.assertLessEqual(len(self.out), 4)

    def test_strongest_sentence_first(self):
        self.assertIn("recommends", self.out[0])

    def test_empty_page_gives_nothing(self):
        self.assertEqual(build.extract_instructions(""), [])


class EnrichInstructions(unittest.TestCase):
    def test_each_item_read_once_and_budget_respected(self):
        items = [{"link": f"https://a.test/{i}", "published": f"2026-10-19T0{9 - i}:00:00+00:00"} for i in range(3)]
        with mock.patch.object(build, "fetch_page", return_value=ARTICLE) as f:
            build.enrich_instructions(items, budget=2)
            self.assertEqual(f.call_count, 2)
            build.enrich_instructions(items, budget=5)
            self.assertEqual(f.call_count, 3)
        self.assertTrue(all(i["instructions_checked"] for i in items))
        self.assertTrue(items[0]["instructions"])


class StoryPage(unittest.TestCase):
    def test_real_instructions_are_shown_with_source_link(self):
        s = dict(STORY, instructions=[{"text": "Install KB5127648 on all hosts.", "source": "BleepingComputer",
                                       "url": "https://news.example.test/a"}])
        page = build.story_page(s, CFG)
        self.assertIn("Instructions from the source", page)
        self.assertIn("Install KB5127648 on all hosts.", page)
        self.assertIn("https://news.example.test/a", page)

    def test_no_instructions_says_so_honestly(self):
        page = build.story_page(STORY, CFG)
        self.assertIn("We found no specific instructions", page)

    def test_generic_checks_are_gone(self):
        page = build.story_page(STORY, CFG)
        self.assertNotIn("Generic checks", page)
        self.assertNotIn("general checks for this category", page)

    def test_msrc_cve_links_to_security_update_guide(self):
        s = dict(STORY, cves=["CVE-2026-40001"],
                 sources=[{"name": build.MSRC_NAME, "title": "x", "url": "https://msrc.example/a", "published": None}])
        page = build.story_page(s, CFG)
        self.assertIn("https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-40001", page)

    def test_no_sug_link_for_third_party_cve(self):
        s = dict(STORY, cves=["CVE-2026-50001"])
        self.assertNotIn("update-guide", build.story_page(s, CFG))

    def test_old_stories_without_field_still_render(self):
        s = dict(STORY)
        s.pop("instructions")
        self.assertIn("We found no specific instructions", build.story_page(s, CFG))


if __name__ == "__main__":
    unittest.main()
