import re, sys, os
from pathlib import Path
from html.parser import HTMLParser
root = Path(sys.argv[1]).resolve()
class P(HTMLParser):
    def __init__(s): super().__init__(); s.refs=[]; s.scripts=[]; s.inscript=False; s.buf=[]
    def handle_starttag(s, tag, attrs):
        a=dict(attrs)
        for k in ("href","src"):
            if a.get(k): s.refs.append((k,a[k]))
        if tag=="script" and not a.get("src"): s.inscript=True; s.buf=[]
    def handle_endtag(s, tag):
        if tag=="script" and s.inscript: s.scripts.append("".join(s.buf)); s.inscript=False
    def handle_data(s, d):
        if s.inscript: s.buf.append(d)
bad=[]; ext=set(); scripts=0; pages=0
for f in root.rglob("*.html"):
    pages+=1
    p=P(); p.feed(f.read_text(encoding="utf-8", errors="replace"))
    for i,js in enumerate(p.scripts):
        if js.strip():
            scripts+=1; Path("/tmp/s.js").write_text(js, encoding="utf-8")
            r=os.system("node --check /tmp/s.js >/tmp/s.err 2>&1")
            if r!=0: bad.append(("JS-SYNTAX", str(f.relative_to(root)), open('/tmp/s.err').read()[:200]))
    for k,ref in p.refs:
        if ref.startswith(("http://","https://","mailto:","tel:")): ext.add(ref); continue
        if ref.startswith("#") or ref.startswith("data:") or ref.startswith("javascript:"): continue
        target=ref.split("#")[0].split("?")[0]
        if not target: continue
        t=(f.parent/target) if not target.startswith("/") else (root/target.lstrip("/"))
        if not t.exists(): bad.append(("MISSING", str(f.relative_to(root)), ref))
print("pages",pages,"inline scripts",scripts,"external refs",len(ext))
for b in bad[:60]: print(b)
print("broken total:", len(bad))
print("EXTERNAL SAMPLE:"); [print(" ",e) for e in sorted(ext)[:60]]
