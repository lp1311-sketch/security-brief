"""Generated-site link regression: python3 -m unittest test_internal_links -v"""
from pathlib import Path
from html.parser import HTMLParser
from urllib.parse import urlsplit, unquote
import unittest
import build

ROOT=Path(__file__).resolve().parent
class Links(HTMLParser):
    def __init__(self):
        super().__init__();self.refs=[];self.ids=set()
    def handle_starttag(self,tag,attrs):
        attrs=dict(attrs)
        if attrs.get('id'):self.ids.add(attrs['id'])
        key='href' if tag in ('a','link','area') else 'src' if tag in ('img','script','iframe') else None
        if key and attrs.get(key):self.refs.append(attrs[key])

class InternalLinks(unittest.TestCase):
    def test_generated_pages_local_targets(self):
        docs=ROOT/'docs';pages={}
        for page in docs.rglob('*.html'):
            parsed=Links();parsed.feed(page.read_text(encoding='utf-8'))
            pages[page.resolve()]=parsed
        broken=[]
        for page,parsed in pages.items():
            for href in parsed.refs:
                u=urlsplit(href)
                if u.scheme or u.netloc or href.startswith(('//','mailto:','tel:','data:','javascript:')):continue
                target=(docs / unquote(u.path).lstrip('/')).resolve() if u.path.startswith('/') else (page.parent / unquote(u.path)).resolve() if u.path else page
                if target.is_dir():target=target/'index.html'
                if not target.is_relative_to(docs.resolve()) or not target.is_file():
                    broken.append((str(page.relative_to(docs)),href))
                elif u.fragment and target in pages and unquote(u.fragment) not in pages[target].ids:
                    broken.append((str(page.relative_to(docs)),href+' (fragment missing)'))
        self.assertFalse(broken,f'{len(broken)} broken local targets; first: {broken[:10]}')

    def test_card_links_are_relative_to_page_depth(self):
        story={'id':'abc','title':'Example','summary':'Sample','priority':'Standard','category':'general',
               'published':None,'image':None,'sources':[],'tags':[],'score':0,'reasons':[]}
        for base in ('','../','../../'):
            self.assertEqual(build._card(story,base).count('href="'+base+'story/abc.html"'),2)

    def test_analysis_page_assets_use_one_parent(self):
        article={'section':'briefings','slug':'example','title':'Example','summary':'Sample',
                 'date':'2026-10-20','body':'<h2>Sample</h2><p>Body</p>'}
        cfg={'site_name':'Security Brief','site_url':'https://example.org/security-brief'}
        page=build.article_page(article,cfg,{})
        self.assertIn('href="../style.css"',page)
        self.assertIn('href="../index.html">Back to home',page)
        self.assertNotIn('href="../../style.css"',page)
if __name__=='__main__': unittest.main()
