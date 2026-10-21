import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import build  # noqa: E402

MSRC = "Microsoft Security Response Center"


def st(title, cves=(), summary="A real description of the flaw.", published="2026-10-16T14:00:00+00:00",
       kev=(), tags=(), score=3, sid=None):
    return {"id": sid or title[:8].replace(" ", "x"), "title": title, "summary": summary, "published": published,
            "category": "vulnerabilities", "tags": list(tags), "priority": "Standard", "score": score, "reasons": [],
            "cves": list(cves), "vendors": [], "kev": list(kev), "kev_checked": True, "image": None,
            "image_source": None, "sources": [{"name": MSRC, "title": title, "url": "https://x.test/a", "published": published}]}


CHROMIUM = st("Chromium CVE-2026-106258: Uninitialized resource",
              cves=["CVE-2026-106258", "CVE-2026-106263", "CVE-2026-106264"],
              summary="This CVE was assigned by Chrome. See [Google Chrome Releases](https://chromereleases.googleblog.com/2026).",
              sid="chromium")


class CveRowsFromTitle(unittest.TestCase):
    def test_body_cves_do_not_become_rows(self):
        out = build.cve_table(build.msrc_cve_rows([CHROMIUM]))
        self.assertEqual(out.count('class="cve-id"'), 1)
        self.assertIn("Also named in this entry", out)
        self.assertIn("CVE-2026-106263", out)

    def test_each_row_keeps_its_own_entry_date(self):
        a = st("Flaw A CVE-2026-1001", cves=["CVE-2026-1001"], published="2026-10-16T14:00:00+00:00", sid="a")
        b = st("Flaw B CVE-2026-2001", cves=["CVE-2026-2001"], published="2026-10-13T08:00:00+00:00", sid="b")
        out = build.cve_table(build.msrc_cve_rows([a, b]))
        self.assertIn("16 Oct 2026, 14:00 UTC", out)
        self.assertIn("13 Oct 2026, 08:00 UTC", out)

    def test_markdown_link_text_is_clean(self):
        out = build.cve_table(build.msrc_cve_rows([CHROMIUM]))
        self.assertIn("Google Chrome Releases", out)
        self.assertNotIn("](", out)

    def test_counts_line_and_legend_explain_date_and_also(self):
        out = build.cve_table(build.msrc_cve_rows([CHROMIUM]))
        self.assertIn("1 new CVE", out)
        self.assertIn("Feed date", out)
        self.assertIn("Also named", out)


class Revisions(unittest.TestCase):
    REV = st("Windows Update Delivery Optimization Elevation of Privilege Vulnerability CVE-2026-108465",
             cves=["CVE-2026-108465"], summary="Updated an acknowledgement. This is an informational change only.", sid="rev")

    def test_revision_detected(self):
        self.assertTrue(build.is_revision(self.REV))
        self.assertFalse(build.is_revision(CHROMIUM))

    def test_revision_is_not_patch_normal(self):
        a = build.suggest_action(self.REV)
        self.assertEqual(a["kind"], "monitor")
        self.assertIn("revised this entry", a["text"])

    def test_revision_shown_as_revision_and_listed_last(self):
        rows = build.msrc_cve_rows([self.REV, CHROMIUM])
        out = build.cve_table(rows)
        self.assertIn('class="badge None">Revision<', out)
        self.assertLess(out.index("CVE-2026-106258"), out.index("CVE-2026-108465"))
        self.assertIn("1 revision (no new fix)", out)

    def test_visual_studio_style_revision(self):
        vs = st("CVE-2026-103572 Visual Studio Tools for Applications and SQL Server Management Studio Remote Code Execution Vulnerability",
                cves=["CVE-2026-103572"],
                summary="Updated the Security Updates table to add download and KB article links for Microsoft Visual Studio. This is an informational change only; the fixed builds are unchanged.",
                sid="vs")
        self.assertTrue(build.is_revision(vs))


if __name__ == "__main__":
    unittest.main()
