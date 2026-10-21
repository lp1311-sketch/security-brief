import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import build  # noqa: E402


def item(title, summary="", cves=(), published="2026-10-19T08:00:00+00:00", link=None):
    return {"title": title, "summary": summary, "cves": list(cves), "published": published,
            "link": link or f"https://example.test/{abs(hash(title))}", "id": title[:12]}


class VendorGrouping(unittest.TestCase):
    def test_vendor_detection(self):
        self.assertIn("BeyondTrust", build.vendors_in("BeyondTrust Remote Support flaw"))
        self.assertIn("Fortinet", build.vendors_in("FortiOS auth bypass"))
        self.assertIn("Google Chrome", build.vendors_in("Chrome zero-day patched"))
        self.assertEqual(build.vendors_in("Microsoft patches Exchange flaw"), set())

    def test_same_vendor_different_headlines_group(self):
        a = item("BeyondTrust warns of critical flaw in Remote Support and PRA")
        b = item("Hackers exploit BeyondTrust Remote Support bug in attacks")
        groups = build.cluster([a, b])
        self.assertEqual(len(groups), 1)
        self.assertEqual(len(groups[0]), 2)

    def test_unrelated_same_vendor_stays_apart(self):
        a = item("Fortinet patches FortiOS authentication bypass")
        b = item("Fortinet warns of FortiWeb zero-day exploited in attacks")
        self.assertEqual(len(build.cluster([a, b])), 2)

    def test_shared_cve_groups_even_with_different_titles(self):
        a = item("Vendor X ships update", cves=["CVE-2026-1111"])
        b = item("Totally different wording here", cves=["CVE-2026-1111"])
        self.assertEqual(len(build.cluster([a, b])), 1)

    def test_different_vendors_never_group_on_vendor_alone(self):
        a = item("Cisco warns of critical flaw in remote access VPN")
        b = item("Ivanti warns of critical flaw in remote access VPN")
        self.assertEqual(len(build.cluster([a, b])), 2)


if __name__ == "__main__":
    unittest.main()
