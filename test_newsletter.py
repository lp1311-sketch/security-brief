"""Newsletter controls, signup URL and no-change fallback; run: python3 -m unittest test_newsletter -v"""
import unittest
from datetime import datetime, timezone
import build

URL="https://eepurl.com/wnapSxhkuE"
CFG={"site_name":"Security Brief","site_url":"https://lp1311-sketch.github.io/security-brief"}

class Newsletter(unittest.TestCase):
    def test_home_has_two_ctas_without_repeating_donation(self):
        site={"newsletter_signup_url":URL,"donations":[{"provider":"buymeacoffee","url":"https://buymeacoffee.com/leonpavesic"}]}
        page=build.index_page([],CFG,datetime(2026,10,23,tzinfo=timezone.utc),{},[],site)
        self.assertEqual(page.count('href="'+URL+'"'),2)
        self.assertEqual(page.count('class="subscribe"'),1)
        self.assertEqual(page.count('class="signal-teaser"'),1)
        self.assertEqual(page.count('class="donate-btn"'),1)
        self.assertLess(page.index('class="donate-btn"'),page.index('class="signal-teaser"'))
        self.assertLess(page.index('class="signal-teaser"'),page.index('id="free-downloads"'))
        self.assertLess(page.index('class="subscribe"'),page.index('id="analysis"') if 'id="analysis"' in page else len(page))
    def test_invalid_signup_does_not_show_cta(self):
        for value in ('','http://example.com','javascript:alert(1)'):
            with self.subTest(value=value):
                self.assertFalse(build._newsletter_teaser({"newsletter_signup_url":value}))
                self.assertFalse(build._newsletter({"newsletter_signup_url":value},""))
    def test_relative_privacy_link_on_nested_article(self):
        self.assertIn('href="../datenschutz.html"',build._newsletter({"newsletter_signup_url":URL},"../"))

if __name__=="__main__":unittest.main()
