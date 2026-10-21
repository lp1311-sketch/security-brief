import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import build  # noqa: E402

# Real headlines from the live page; expected categories were checked by hand.
CASES = [
    ("OpenAI models hacked a crypto wallet and breached more websites", "", "ai"),
    ("Candiru spyware delivered through targeted online ads", "", "threats"),
    ("Hackers hijack D-Link, Ubiquiti devices to resell your stolen bandwidth", "", "threats"),
    ("Attackers Tampered with AOMEI Backupper's Update Servers to Deliver a Backdoor", "", "threats"),
    ("Microsoft: October Windows Server updates break Exchange sign-in, mail flow", "", "microsoft"),
    ("Hackers breach Microsoft 365 tenants via ConnectWise supply-chain attack", "", "threats"),
    ("Microsoft Patches More Than 1,400 Security Flaws", "", "vulnerabilities"),
    ("Entra ID sign-in anomalies rise as attackers abuse OAuth consent", "", "microsoft"),
    ("Android gets AI defenses against messaging scams, fake calls", "", "ai"),
    ("Burger King Japan data breach exposes 11 million customer records", "", "threats"),
    ("India Mandates Registered Caller Name Display on 4G Networks", "", "general"),
    ("Drupal patches critical RCE flaws, warns exploits may emerge soon", "", "vulnerabilities"),
]


class CategoryTests(unittest.TestCase):
    def test_real_headlines(self):
        for title, summary, expected in CASES:
            with self.subTest(title=title):
                self.assertEqual(build.categorize(title, summary), expected)

    def test_cve_pushes_to_vulnerabilities(self):
        self.assertEqual(build.categorize("Vendor ships update for appliance", "", ("CVE-2026-1",)), "vulnerabilities")


class TextTests(unittest.TestCase):
    def test_excerpt_cleanup(self):
        self.assertEqual(build.clean_excerpt("Cryptomus ,  a platform \\[...\\]"), "Cryptomus, a platform")
        self.assertEqual(build.clean_excerpt("Text [...] more"), "Text more")


class TagTests(unittest.TestCase):
    def test_patch_now_needs_kev_or_exploitation_with_cve(self):
        self.assertIn("patch-now", build.story_tags("x", "Critical", "vulnerabilities", True, True, True))
        self.assertNotIn("patch-now", build.story_tags("x", "High", "vulnerabilities", False, False, True))
        self.assertIn("exploited", build.story_tags("zero-day seen", "High", "vulnerabilities", False, True, False))
        self.assertNotIn("patch-now", build.story_tags("zero-day seen", "High", "vulnerabilities", False, True, False))

    def test_topic_tags(self):
        tags = build.story_tags("Microsoft 365 sign-in alerts; Defender XDR update", "Standard", "microsoft", False, False, False)
        self.assertIn("m365", tags)
        self.assertIn("entra", tags)
        self.assertIn("defender", tags)


if __name__ == "__main__":
    unittest.main()
