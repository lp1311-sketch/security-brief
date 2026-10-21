import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import build  # noqa: E402

NOW = datetime(2026, 10, 19, 12, 0, tzinfo=timezone.utc)


def st(title, cves=(), kev=(), tags=(), priority="Standard", summary="", score=3, sid="abc123"):
    return {"id": sid, "title": title, "summary": summary, "published": "2026-10-13T08:00:00+00:00",
            "category": "vulnerabilities", "tags": list(tags), "priority": priority, "score": score, "reasons": [],
            "cves": list(cves), "vendors": [], "kev": list(kev), "kev_checked": True, "image": None,
            "image_source": None,
            "sources": [{"name": "Microsoft Security Response Center", "title": title,
                         "url": "https://msrc.example/a", "published": None}]}


class CveTableV510(unittest.TestCase):
    def test_one_row_per_cve_with_guide_link(self):
        rows = build.msrc_cve_rows([st("Flaw CVE-2026-1001 and CVE-2026-2001 in one update", cves=["CVE-2026-1001", "CVE-2026-2001"])])
        out = build.cve_table(rows)
        self.assertEqual(out.count('class="cve-id"'), 2)
        self.assertIn("https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-1001", out)
        self.assertIn("https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-2001", out)

    def test_duplicate_cve_appears_once(self):
        rows = build.msrc_cve_rows([st("First", cves=["CVE-2026-1001"], sid="a"),
                                    st("Second", cves=["CVE-2026-1001"], sid="b")])
        self.assertEqual(build.cve_table(rows).count('class="cve-id"'), 1)

    def test_kev_status_and_order(self):
        rows = build.msrc_cve_rows([st("Exploited flaw", cves=["CVE-2026-9001"], kev=["CVE-2026-9001"],
                                       priority="Critical", summary="Attackers use this flaw.")])
        out = build.cve_table(rows)
        self.assertIn(">KEV<", out)
        self.assertIn("1 · Patch first", out)
        self.assertIn("Attackers use this flaw.", out)

    def test_exploited_and_not_reported_labels(self):
        rows = build.msrc_cve_rows([st("A", cves=["CVE-2026-3001"], tags=["exploited"]),
                                    st("B", cves=["CVE-2026-4001"])])
        out = build.cve_table(rows)
        self.assertIn(">Exploited<", out)
        self.assertIn(">Not reported<", out)
        self.assertIn("3 · Normal cycle", out)

    def test_missing_description_has_honest_fallback(self):
        rows = build.msrc_cve_rows([st("Patch note only", cves=["CVE-2026-5001"], summary="")])
        self.assertIn("The feed gives no description", build.cve_table(rows))

    def test_title_as_summary_is_treated_as_missing(self):
        rows = build.msrc_cve_rows([st("Same text", cves=["CVE-2026-6001"], summary="Same text.")])
        self.assertIn("The feed gives no description", build.cve_table(rows))

    def test_legend_explains_columns_and_limits(self):
        out = build.cve_table(build.msrc_cve_rows([st("X", cves=["CVE-2026-7001"])]))
        self.assertIn("How to read this table", out)
        self.assertIn("does not include CVSS", out)
        self.assertIn("not the complete Patch Tuesday", out)
        self.assertIn("1 new CVE", out)  # counts line

    def test_empty_state_keeps_legend(self):
        out = build.cve_table([])
        self.assertIn("How to read this table", out)
        self.assertIn("No Microsoft CVE entries", out)

    def test_escaping(self):
        rows = build.msrc_cve_rows([st("<script>x</script>", cves=["CVE-2026-8001"], summary="<b>bad</b>")])
        out = build.cve_table(rows)
        self.assertNotIn("<script>x</script>", out)
        self.assertNotIn("<b>bad</b>", out)

    def test_render_version(self):
        self.assertRegex((Path(__file__).resolve().parent.parent / "build.py").read_text(encoding="utf-8"), r'"render": "5\.\d+"')


if __name__ == "__main__":
    unittest.main()
