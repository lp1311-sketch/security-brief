"""My Radar offline smoke tests; run: python3 -m unittest test_radar -v"""
import json,unittest
from datetime import datetime,timezone
from pathlib import Path
import build

CFG={"site_name":"Security Brief","site_url":"https://lp1311-sketch.github.io/security-brief"}

class Radar(unittest.TestCase):
    def test_nav_and_page(self):
        page=build.radar_page(CFG)
        self.assertIn('href="../radar/index.html"',page)
        self.assertIn("fetch('../stories.json'",page)
        self.assertIn('radar-choices',page)
        self.assertIn('sb-radar-v1',page)
        self.assertIn('keyword',page.lower())
        self.assertIn('href="../m365-identity-incident-triage-checklist.pdf"',page)
    def test_homelink_does_not_remove_existing_blocks(self):
        cfg=json.loads((Path(__file__).parent/'site.json').read_text())
        page=build.index_page([],CFG,datetime(2026,10,23,tzinfo=timezone.utc),{},[],cfg)
        self.assertIn('href="radar/index.html"',page)
        self.assertIn('href="https://eepurl.com/wnapSxhkuE"',page)
        self.assertIn('buymeacoffee-qr.png',page)
    def test_story_index_exposes_iso_time_and_local_link(self):
        story={'id':'0123456789ab','title':'Example','summary':'Summary','priority':'High','score':7,
               'category':'microsoft','published':'2026-10-22T14:30:00+00:00','tags':[],
               'kev':[],'priority_basis':[],'sources':[{'name':'Vendor'}]}
        item=json.loads(build.stories_index([story]))['stories'][0]
        self.assertEqual(item['url'],'story/0123456789ab.html')
        self.assertEqual(item['published'],story['published'])
        self.assertIn('radar/index.html',build.sitemap_xml([],CFG))
    def test_evidence_is_cautious(self):
        self.assertIn('CISA KEV',build.evidence_label({'kev':['CVE-2026-1001']}))
        self.assertIn('not confirmed exposure',build.evidence_label({}))
if __name__=='__main__':unittest.main()
