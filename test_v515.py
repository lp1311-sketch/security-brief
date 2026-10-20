import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import build  # noqa: E402


def item(title, summary="", **kw):
    base = {"title": title, "summary": summary, "tags": [], "cves": [], "kev": False, "category": "threats"}
    base.update(kw)
    return base


class WhyItMatters(unittest.TestCase):
    def test_breach_with_personal_records_is_specific(self):
        text = build.why_it_matters(item("Nikkei discloses breach", "1.83 million personal information records exposed"))
        self.assertIn("Personal data", text)
        self.assertIn("Art. 33", text)
        self.assertNotIn("Even an unconfirmed report", text)

    def test_kev_cve_is_named_and_confirmed(self):
        text = build.why_it_matters(item("Windows flaw", "patch released", cves=["CVE-2026-1111"], kev=True))
        self.assertIn("Known Exploited Vulnerabilities", text)
        self.assertIn("CVE-2026-1111", text)

    def test_no_signal_falls_back_to_category_text(self):
        text = build.why_it_matters(item("Weather in Berlin", "sunny", category="general"))
        self.assertEqual(text, build.WHY["general"])

    def test_at_most_three_sentences(self):
        text = build.why_it_matters(item(
            "Ransomware web shell backdoor npm package",
            "ransomware gang stole customer records, OAuth consent abused, API keys exposed",
            cves=["CVE-2026-2222"], kev=True))
        self.assertIn("Known Exploited", text)
        self.assertIn("Personal data", text)
        self.assertNotIn("Ransomware intrusions", text)  # capped at three sentences
        self.assertNotIn("Token and consent", text)


if __name__ == "__main__":
    unittest.main()
