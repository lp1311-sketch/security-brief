import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import build  # noqa: E402

MSRC = "Microsoft Security Response Center"


def st(title, cves=(), kev=(), tags=(), source=MSRC):
    return {"id": title[:8], "title": title, "summary": "x", "published": "2026-10-13T08:00:00+00:00",
            "category": "vulnerabilities", "tags": list(tags), "priority": "Standard", "score": 3, "reasons": [],
            "cves": list(cves), "vendors": [], "kev": list(kev), "kev_checked": True, "image": None,
            "image_source": None, "sources": [{"name": source, "title": title, "url": "https://x.test/a", "published": None}]}


class PatchNormal(unittest.TestCase):
    def test_msrc_cve_without_exploitation_is_patch_normal(self):
        a = build.suggest_action(st("Windows Kerberos Elevation of Privilege Vulnerability", cves=["CVE-2026-1"]))
        self.assertEqual(a["kind"], "patch-normal")
        self.assertEqual(a["label"], "Patch in normal cycle")
        self.assertNotIn("No immediate action", a["text"])

    def test_kev_still_patch_now(self):
        a = build.suggest_action(st("Flaw", cves=["CVE-2026-2"], kev=["CVE-2026-2"]))
        self.assertEqual(a["kind"], "patch")

    def test_exploited_msrc_cve_is_investigate_not_normal(self):
        a = build.suggest_action(st("Flaw", cves=["CVE-2026-3"], tags=["exploited"]))
        self.assertEqual(a["kind"], "investigate")

    def test_non_msrc_news_without_cve_is_still_monitor(self):
        a = build.suggest_action(st("General news", source="BleepingComputer"))
        self.assertEqual(a["kind"], "monitor")

    def test_blog_with_cve_is_not_patch_normal(self):
        a = build.suggest_action(st("Blog post mentioning CVE-2026-4", cves=["CVE-2026-4"], source="Microsoft Security Blog"))
        self.assertNotEqual(a["kind"], "patch-normal")

    def test_patch_normal_sorts_after_patch_before_review(self):
        self.assertLess(build.ACTION_RANK["patch"], build.ACTION_RANK["patch-normal"])
        self.assertLess(build.ACTION_RANK["patch-normal"], build.ACTION_RANK["review"])
        self.assertLess(build.ACTION_RANK["review"], build.ACTION_RANK["monitor"])


class MobileCveTable(unittest.TestCase):
    def test_date_and_details_hidden_under_640px(self):
        css = (Path(__file__).resolve().parent.parent / "build.py").read_text(encoding="utf-8")
        self.assertIn(".cve-table th:nth-child(5),.cve-table td:nth-child(5)", css)
        self.assertIn(".cve-table th:nth-child(6),.cve-table td:nth-child(6)", css)
        self.assertRegex(css, r'"render": "5\.\d+"')


if __name__ == "__main__":
    unittest.main()
