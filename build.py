#!/usr/bin/env python3
"""Security Brief autoblog: public RSS/Atom feeds -> dedupe -> rank -> static site in docs/.

Stdlib only. No paid APIs, no server, no database.
  python3 build.py                  # live run (needs internet)
  python3 build.py --fixtures DIR   # offline run using DIR/<source-id>.xml (+ optional kev.json)
"""
from __future__ import annotations

import argparse
import hashlib
import html
import json
import re
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime, parsedate_to_datetime
from pathlib import Path
from urllib.parse import parse_qsl, quote, urlencode, urlparse, urlunparse

ROOT = Path(__file__).resolve().parent
CONFIG = ROOT / "feeds.json"
DATA = ROOT / "data" / "stories.json"
DEFAULT_OUT = ROOT / "docs"
UA = "SecurityBriefBot/1.0 (personal RSS reader; low frequency)"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
TAG_RE = re.compile(r"<[^>]+>")
IMG_RE = re.compile(r"""<img[^>]+src=["']([^"']+)["']""", re.I)
EXPLOITED_RE = re.compile(r"actively exploited|exploited in the wild|in the wild|zero-day|0-day", re.I)

# Category id -> (label, first-match regex). Checked in CATEGORY_ORDER.
CATEGORIES = {
    "threats": ("Ransomware, Malware & Breaches", r"ransomware|malware|breach|phishing|stealer|botnet|extortion|data leak"),
    "vulnerabilities": ("Vulnerabilities & Exploited CVEs", r"vulnerab|\bcve-|patch|exploit"),
    "ai": ("AI Security & Emerging Threats", r"\bai\b|llm|copilot|deepfake|generative"),
    "microsoft": ("Microsoft & Enterprise", r"microsoft|windows|entra|azure|m365|office 365|exchange|sharepoint|teams"),
    "cloud": ("Cloud & Identity", r"cloud|identity|\bmfa\b|okta|\bsso\b|aws|oauth|sign-in"),
    "general": ("Security News", r"$^"),  # fallback, never matches
}
CATEGORY_ORDER = ["threats", "vulnerabilities", "ai", "cloud", "microsoft", "general"]  # cloud before microsoft: Entra = identity

# Score signals: (regex, points, label). Documented in README.md.
SIGNALS = [
    (re.compile(r"ransomware", re.I), 2, "ransomware"),
    (re.compile(r"breach|data leak|stolen data", re.I), 2, "breach or data theft"),
    (re.compile(r"\bcritical\b", re.I), 2, "'critical' wording"),
    (re.compile(r"microsoft|windows|entra|azure|m365|exchange", re.I), 2, "Microsoft/enterprise relevance"),
    (re.compile(r"cloud|identity|\bmfa\b|okta|\bsso\b", re.I), 1, "cloud/identity relevance"),
    (re.compile(r"\bai\b|llm|copilot", re.I), 1, "AI relevance"),
]

WHY = {
    "threats": "Ransomware, malware and breach reports often hit identity, email and file-sharing systems first. Even an unconfirmed report is a reason to check your detections.",
    "vulnerabilities": "Exploitable vulnerabilities become urgent once attackers use them. Your exposure and patch status matter more than the headline.",
    "ai": "AI tools are becoming part of normal business workflows, so weaknesses in them can expose data or access quickly.",
    "microsoft": "Microsoft products are widely used in enterprises, so an issue here can affect many tenants and devices at once.",
    "cloud": "Identity and cloud weaknesses often lead to account takeover, so they matter even when no endpoint is affected.",
    "general": "General security development. Whether it matters depends on the products and processes in your own environment.",
}
CHECKS = {
    "threats": [
        "Check EDR/Defender alerts and mail flow for indicators mentioned in the original report.",
        "Confirm backups are current and that a restore has been tested recently.",
        "Review MFA and privileged-access coverage for the affected user groups.",
    ],
    "vulnerabilities": [
        "Check whether the affected products or versions exist in your environment.",
        "Compare with the vendor advisory and current patch status.",
        "If a CVE is listed in the CISA KEV catalog, treat it as a priority under your change process.",
    ],
    "ai": [
        "Confirm which AI tools are approved and how their access is logged.",
        "Review the vendor guidance for the affected feature.",
        "Check whether sensitive data can reach the tool through connectors or plugins.",
    ],
    "microsoft": [
        "Check the Microsoft Security Update Guide or Message Center for the affected products.",
        "Confirm patch deployment status for affected devices and servers.",
        "Review related sign-in and audit logs if the issue involves identity or mail.",
    ],
    "cloud": [
        "Review sign-in logs and risky-user signals for anomalies.",
        "Verify MFA and Conditional Access coverage for the affected apps.",
        "Check app consents, service principals and admin roles if OAuth or tokens are involved.",
    ],
    "general": [
        "Read the original report and decide whether your environment is affected.",
        "Involve the relevant team only if the affected products are in use.",
    ],
}


# ---------- helpers ----------

def esc(s) -> str:
    return html.escape(str(s or ""), quote=True)


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].lower()


def _clean(raw: str) -> str:
    return re.sub(r"\s+", " ", html.unescape(TAG_RE.sub(" ", raw or ""))).strip()


def _short(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    cut = text[:limit].rsplit(" ", 1)[0].rstrip(".,;:")
    return cut + "…"


def _date(s: str | None) -> datetime | None:
    if not s:
        return None
    s = s.strip()
    try:
        d = parsedate_to_datetime(s)
    except (TypeError, ValueError):
        try:
            d = datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError:
            return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d.astimezone(timezone.utc)


def fmt_date(iso: str | None) -> str:
    d = _date(iso)
    return d.strftime("%d %b %Y, %H:%M UTC") if d else "date not provided"


def clean_link(u: str) -> str | None:
    p = urlparse((u or "").strip())
    if p.scheme not in ("http", "https") or not p.netloc:
        return None
    query = [(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True) if not k.lower().startswith("utm_")]
    return urlunparse(p._replace(query=urlencode(query), fragment=""))


def https_image(u: str | None) -> str | None:
    p = urlparse((u or "").strip())
    return p.geturl() if p.scheme == "https" and p.netloc else None


def cover_svg(label: str) -> str:
    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" width="640" height="360" viewBox="0 0 640 360">'
        '<rect width="640" height="360" fill="#0b1a33"/>'
        '<rect x="40" y="40" width="560" height="280" fill="none" stroke="#3b82f6" stroke-width="2"/>'
        f'<text x="64" y="186" fill="#ffffff" font-family="Arial, sans-serif" font-size="30" font-weight="700">{esc(label)}</text>'
        "</svg>"
    )
    return "data:image/svg+xml;charset=utf-8," + quote(svg)


# ---------- fetching & parsing ----------

def fetch(url: str, timeout: int = 15, tries: int = 2) -> bytes:
    last: Exception | None = None
    for _ in range(tries):
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": UA,
                "Accept": "application/rss+xml, application/atom+xml, application/xml;q=0.9, */*;q=0.5",
            })
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read(5_000_000)
        except Exception as e:  # noqa: BLE001 - we record and continue
            last = e
    raise RuntimeError(str(last))


def load_kev(fixtures: Path | None) -> tuple[set[str], str | None]:
    try:
        if fixtures:
            p = fixtures / "kev.json"
            raw = p.read_bytes() if p.exists() else None
            if raw is None:
                return set(), "KEV not loaded (no kev.json in fixtures)"
        else:
            raw = fetch(KEV_URL)
        data = json.loads(raw)
        return {v["cveID"].upper() for v in data.get("vulnerabilities", [])}, None
    except Exception as e:  # noqa: BLE001
        return set(), f"KEV unavailable: {e}"


def parse_feed(data: bytes, src: dict) -> list[dict]:
    root = ET.fromstring(data)
    out: list[dict] = []
    for entry in root.iter():
        if _local(entry.tag) not in ("item", "entry"):
            continue

        def raw(name: str) -> str:
            el = next((c for c in entry if _local(c.tag) == name), None)
            return (el.text or "") if el is not None else ""

        title = _clean(raw("title"))
        link = ""
        for c in entry:
            if _local(c.tag) == "link" and c.get("rel", "alternate") == "alternate":
                link = c.get("href") or (c.text or "")
                if link:
                    break
        link = clean_link(link)
        if not title or not link:
            continue

        body_raw = next((r for r in (raw("encoded"), raw("description"), raw("summary"), raw("content")) if r.strip()), "")

        image = None
        for c in entry:
            name = _local(c.tag)
            typ = c.get("type") or ""
            if name in ("content", "thumbnail") and c.get("url"):
                if name == "thumbnail" or c.get("medium") == "image" or typ.startswith("image"):
                    image = https_image(c.get("url"))
            elif name == "enclosure" and typ.startswith("image"):
                image = https_image(c.get("url"))
            if image:
                break
        if not image:
            m = IMG_RE.search(body_raw)
            if m:
                image = https_image(m.group(1))

        date = _date(raw("pubdate") or raw("published") or raw("updated") or raw("date"))
        summary = _short(_clean(body_raw), 320)
        cves = sorted({c.upper() for c in CVE_RE.findall(f"{title} {body_raw}")})

        out.append({
            "id": hashlib.sha1(link.encode()).hexdigest()[:12],
            "source": src["id"],
            "source_name": src["name"],
            "official": bool(src.get("official")),
            "title": title,
            "link": link,
            "published": date.isoformat() if date else None,
            "summary": summary,
            "image": image,
            "cves": cves,
        })
    return out


# ---------- merge, cluster, rank ----------

def merge(stored: list[dict], fresh: list[dict], now: datetime, retention_days: int) -> list[dict]:
    by_link = {i["link"]: i for i in stored}
    for i in fresh:
        old = by_link.get(i["link"])
        if old:
            old.update({k: v for k, v in i.items() if v not in (None, "", [])})
        else:
            i["first_seen"] = now.isoformat()
            by_link[i["link"]] = i
    cutoff = now - timedelta(days=retention_days)
    keep = []
    for i in by_link.values():
        ref = _date(i.get("published")) or _date(i.get("first_seen"))
        if ref and ref >= cutoff:
            keep.append(i)
    return keep


STOP = {"the", "a", "an", "of", "to", "in", "on", "for", "and", "or", "with", "by", "from", "as", "at",
        "is", "are", "be", "after", "new", "how", "why", "what", "its", "it", "this", "that", "via", "over", "into"}


def _tokens(title: str) -> set[str]:
    return {w for w in re.findall(r"[a-z0-9]+", title.lower()) if w not in STOP and len(w) > 2}


def _jaccard(a: set[str], b: set[str]) -> float:
    return len(a & b) / len(a | b) if a and b else 0.0


def cluster(items: list[dict]) -> list[list[dict]]:
    """Group items about the same event: shared CVE, or title similarity >= 0.5. Newest first."""
    groups: list[dict] = []
    for it in sorted(items, key=lambda i: i.get("published") or "", reverse=True):
        toks = _tokens(it["title"])
        home = next((g for g in groups if (set(it["cves"]) & g["cves"]) or _jaccard(toks, g["tokens"]) >= 0.5), None)
        if home is None:
            home = {"items": [], "cves": set(), "tokens": toks}
            groups.append(home)
        home["items"].append(it)
        home["cves"] |= set(it["cves"])
    return [g["items"] for g in groups]


def categorize(text: str) -> str:
    t = text.lower()
    for key in CATEGORY_ORDER:
        if key == "general":
            return key
        if re.search(CATEGORIES[key][1], t):
            return key
    return "general"


def score_story(items: list[dict], kev: set[str], kev_checked: bool, now: datetime) -> tuple[int, str, list[str]]:
    text = " ".join(f"{i['title']} {i['summary']}" for i in items)
    cves = {c for i in items for c in i["cves"]}
    kev_hit = sorted(cves & kev) if kev_checked else []
    exploited = bool(EXPLOITED_RE.search(text))
    official = any(i["official"] for i in items)
    score, reasons = 0, []
    if kev_hit:
        score += 5
        reasons.append(f"CVE listed in CISA KEV: {', '.join(kev_hit)} (+5)")
    if exploited:
        score += 4
        reasons.append("exploitation reported (+4)")
    for rx, pts, label in SIGNALS:
        if rx.search(text):
            score += pts
            reasons.append(f"{label} (+{pts})")
    n_sources = len({i["source"] for i in items})
    if n_sources > 1:
        p = min(n_sources - 1, 3)
        score += p
        reasons.append(f"reported by {n_sources} sources (+{p})")
    newest = _date(items[0].get("published"))
    if newest:
        age = now - newest
        if age <= timedelta(hours=24):
            score += 2
            reasons.append("published in the last 24 h (+2)")
        elif age <= timedelta(hours=48):
            score += 1
            reasons.append("published in the last 48 h (+1)")
    if official:
        score += 1
        reasons.append("official source (+1)")
    # Documented Critical criteria: KEV-listed CVE, or exploitation reported by an official source.
    if kev_hit or (exploited and official):
        prio = "Critical"
    elif score >= 6:
        prio = "High"
    else:
        prio = "Standard"
    return score, prio, reasons


def build_story(items: list[dict], kev: set[str], kev_checked: bool, now: datetime) -> dict:
    head = items[0]
    text = f"{head['title']} {head['summary']} {' '.join(c for i in items for c in i['cves'])}"
    score, prio, reasons = score_story(items, kev, kev_checked, now)
    with_img = next((i for i in items if i["image"]), None)
    cves = sorted({c for i in items for c in i["cves"]})
    return {
        "id": head["id"],
        "title": head["title"],
        "summary": head["summary"],
        "published": head["published"],
        "category": categorize(text),
        "priority": prio,
        "score": score,
        "reasons": reasons,
        "cves": cves,
        "kev": sorted(set(cves) & kev) if kev_checked else [],
        "kev_checked": kev_checked,
        "image": with_img["image"] if with_img else None,
        "image_source": with_img["source_name"] if with_img else None,
        "sources": [
            {"name": i["source_name"], "title": i["title"], "url": i["link"], "published": i["published"]}
            for i in items
        ],
    }


def quality_warnings(stories: list[dict]) -> list[str]:
    warnings = []
    for s in stories:
        if not s["sources"] or not all(x["url"].startswith("https://") or x["url"].startswith("http://") for x in s["sources"]):
            warnings.append(f"story {s['id']}: missing source link")
        if len(s["title"]) < 10:
            warnings.append(f"story {s['id']}: suspicious short title")
        if not s["summary"]:
            warnings.append(f"story {s['id']}: empty summary (page shows link only)")
    return warnings


# ---------- rendering ----------

CSS = """
:root{--navy:#0b1a33;--ink:#14213d;--muted:#4b5563;--line:#e5e7eb;--blue:#1d4ed8;--bg:#f7f8fb;--crit:#b91c1c}
*{box-sizing:border-box}
body{margin:0;font-family:system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif;color:var(--ink);background:var(--bg);line-height:1.55}
a{color:var(--blue)}
header{background:var(--navy);color:#fff;padding:18px 20px}
header .wrap{max-width:1100px;margin:0 auto;display:flex;flex-wrap:wrap;gap:12px 24px;align-items:center;justify-content:space-between}
header a{color:#fff;text-decoration:none}
.brand{font-weight:800;font-size:1.3rem;letter-spacing:.02em}
nav a{margin-right:14px;font-size:.92rem;opacity:.92}
nav a:hover,nav a:focus{opacity:1;text-decoration:underline}
main{max-width:1100px;margin:0 auto;padding:28px 20px 60px}
h1{font-size:1.9rem;line-height:1.2;margin:.3em 0 .4em}
h2{font-size:1.25rem;margin:2rem 0 .8rem;border-bottom:2px solid var(--line);padding-bottom:.3rem}
.grid{display:grid;gap:18px;grid-template-columns:repeat(auto-fill,minmax(260px,1fr))}
.card{background:#fff;border:1px solid var(--line);border-radius:10px;overflow:hidden;display:flex;flex-direction:column}
.card img{width:100%;height:auto;aspect-ratio:16/9;object-fit:cover;display:block;background:var(--navy)}
.card .body{padding:14px 16px 16px;display:flex;flex-direction:column;gap:6px;flex:1}
.card h3{font-size:1.05rem;margin:0;line-height:1.3}
.card h3 a{color:var(--ink);text-decoration:none}
.card h3 a:hover,.card h3 a:focus{text-decoration:underline}
.meta{font-size:.84rem;color:var(--muted);margin:0}
.badge{display:inline-block;font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.05em;padding:2px 8px;border-radius:4px;background:#e0e7ff;color:#1e3a8a;margin-right:6px}
.badge.Critical{background:var(--crit);color:#fff}
.badge.High{background:#fde68a;color:#78350f}
figure{margin:18px 0}
figure img{width:100%;height:auto;border-radius:8px;aspect-ratio:16/9;object-fit:cover;background:var(--navy)}
figcaption{font-size:.8rem;color:var(--muted);margin-top:4px}
.box{background:#fff;border:1px solid var(--line);border-radius:10px;padding:16px 20px;margin:16px 0}
.note{background:#eef2ff;border-radius:8px;padding:12px 16px;font-size:.92rem}
.empty{background:#fff;border:1px dashed #9ca3af;border-radius:10px;padding:24px;color:var(--muted)}
footer{max-width:1100px;margin:0 auto;padding:20px;color:var(--muted);font-size:.85rem;border-top:1px solid var(--line)}
:focus-visible{outline:3px solid #f59e0b;outline-offset:2px}
@media (prefers-reduced-motion: reduce){*{transition:none!important;animation:none!important}}
"""


def _layout(cfg: dict, title: str, desc: str, body: str, base: str) -> str:
    site = esc(cfg["site_name"])
    nav = "".join(
        f'<a href="{base}index.html#{cid}">{esc(CATEGORIES[cid][0].split(" & ")[0].split(",")[0])}</a>'
        for cid in CATEGORY_ORDER if cid != "general"
    )
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title)} | {site}</title>
<meta name="description" content="{esc(desc)}">
<link rel="stylesheet" href="{base}style.css">
<link rel="alternate" type="application/rss+xml" title="{site}" href="{esc(cfg['site_url'])}/feed.xml">
</head>
<body>
<header><div class="wrap">
<a class="brand" href="{base}index.html">{site}</a>
<nav aria-label="Categories">{nav}</nav>
</div></header>
<main>
{body}
</main>
<footer>Automated briefing. Headlines and short excerpts come from public RSS feeds, and every story links to the original publisher. Not affiliated with any source. <a href="{base}feed.xml">RSS</a> · <a href="{base}status.json">Run status</a></footer>
</body>
</html>
"""


def _card(s: dict) -> str:
    img = s["image"] or cover_svg(CATEGORIES[s["category"]][0])
    names = ", ".join(dict.fromkeys(x["name"] for x in s["sources"]))
    return f"""<article class="card">
<img src="{esc(img)}" alt="" loading="lazy" decoding="async" referrerpolicy="no-referrer" width="640" height="360">
<div class="body">
<p class="meta"><span class="badge {esc(s['priority'])}">{esc(s['priority'])}</span>{esc(CATEGORIES[s['category']][0])}</p>
<h3><a href="story/{esc(s['id'])}.html">{esc(s['title'])}</a></h3>
<p class="meta">{esc(_short(s['summary'], 160))}</p>
<p class="meta">{esc(names)} · {esc(fmt_date(s['published']))}</p>
</div>
</article>"""


def index_page(stories: list[dict], cfg: dict, now: datetime, status: dict) -> str:
    top = stories[:3]
    parts = ['<h1>Security news, ranked and linked to the original sources</h1>',
             f'<p class="meta">Last automated update: {esc(now.strftime("%d %b %Y, %H:%M UTC"))}. '
             f'Feed status: {status["sources_ok"]} of {status["sources_total"]} sources reachable.</p>']
    if not stories:
        parts.append('<div class="empty">No stories yet. The next automated run will fill this page, or check the run status.</div>')
    else:
        parts.append('<h2 id="top">Top stories</h2><div class="grid">' + "".join(_card(s) for s in top) + "</div>")
        for cid in CATEGORY_ORDER:
            label = CATEGORIES[cid][0]
            items = [s for s in stories if s["category"] == cid][:6]
            parts.append(f'<h2 id="{cid}">{esc(label)}</h2>')
            if items:
                parts.append('<div class="grid">' + "".join(_card(s) for s in items) + "</div>")
            else:
                parts.append('<p class="meta">No stories in this category in the current window.</p>')
    return _layout(cfg, "Home", "Ranked cybersecurity news with links to original sources.", "\n".join(parts), "")


def story_page(s: dict, cfg: dict) -> str:
    cat_label = CATEGORIES[s["category"]][0]
    if s["image"]:
        img = s["image"]
        credit = f"Image from the publisher's feed: {s['image_source']}. Credit remains with the original publisher."
    else:
        img = cover_svg(cat_label)
        credit = "Generated category cover. The feed did not include an image."
    reasons = "".join(f"<li>{esc(r)}</li>" for r in s["reasons"]) or "<li>No scoring signals matched.</li>"
    srcs = "".join(
        f'<li><a href="{esc(x["url"])}" rel="nofollow noopener noreferrer" target="_blank">{esc(x["title"])}</a>'
        f' — {esc(x["name"])}, {esc(fmt_date(x["published"]))}</li>'
        for x in s["sources"]
    )
    if s["kev"]:
        kev_line = f"Listed in the CISA KEV catalog at the time of this run: {esc(', '.join(s['kev']))}."
    elif s["cves"] and s["kev_checked"]:
        kev_line = f"CVE(s) mentioned: {esc(', '.join(s['cves']))}. Not in the CISA KEV catalog at the time of this run."
    elif s["cves"]:
        kev_line = f"CVE(s) mentioned: {esc(', '.join(s['cves']))}. KEV check unavailable in this run."
    else:
        kev_line = "No CVE identifier found in the feed text."
    checks = "".join(f"<li>{esc(c)}</li>" for c in CHECKS[s["category"]])
    body = f"""<p class="meta"><a href="../index.html">← Back to home</a></p>
<p class="meta"><span class="badge {esc(s['priority'])}">{esc(s['priority'])}</span>{esc(cat_label)}</p>
<h1>{esc(s['title'])}</h1>
<p class="meta">Published: {esc(fmt_date(s['published']))} · Priority score {s['score']}</p>
<figure><img src="{esc(img)}" alt="" referrerpolicy="no-referrer" width="640" height="360"><figcaption>{esc(credit)}</figcaption></figure>
<h2>Summary</h2>
<p>{esc(s['summary']) or 'No excerpt available. Please read the original article.'}</p>
<p class="meta">Summary is the feed's excerpt, shortened. It is not a full article.</p>
<h2>Why it matters</h2>
<p>{esc(WHY[s['category']])}</p>
<h2>Generic checks</h2>
<p class="note">These are general checks for this category, not verified recommendations for this specific incident.</p>
<ul>{checks}</ul>
<h2>Why this priority</h2>
<div class="box"><p><strong>{esc(s['priority'])}</strong>. Criteria: Critical = CVE listed in CISA KEV, or exploitation reported by an official source. High = score 6 or more. Otherwise Standard.</p>
<ul>{reasons}</ul>
<p>{kev_line}</p></div>
<h2>Sources</h2>
<ul>{srcs}</ul>
<p class="note">Automated page. Verify facts in the original articles before acting on them.</p>"""
    desc = _short(s["summary"] or s["title"], 150)
    return _layout(cfg, s["title"], desc, body, "../")


def feed_xml(stories: list[dict], cfg: dict, now: datetime) -> str:
    site = cfg["site_url"].rstrip("/")
    items = []
    for s in stories[:40]:
        link = f"{site}/story/{s['id']}.html"
        pub = _date(s["published"]) or now
        items.append(
            "<item>"
            f"<title>{esc(s['title'])}</title>"
            f"<link>{esc(link)}</link>"
            f"<guid isPermaLink='true'>{esc(link)}</guid>"
            f"<pubDate>{format_datetime(pub)}</pubDate>"
            f"<category>{esc(CATEGORIES[s['category']][0])}</category>"
            f"<description>{esc(s['summary'])}</description>"
            "</item>"
        )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n<rss version="2.0"><channel>'
        f"<title>{esc(cfg['site_name'])}</title><link>{esc(site)}/</link>"
        f"<description>Ranked cybersecurity news with links to original sources</description>"
        f"<lastBuildDate>{format_datetime(now)}</lastBuildDate>"
        + "".join(items) + "</channel></rss>\n"
    )


def sitemap_xml(stories: list[dict], cfg: dict) -> str:
    site = cfg["site_url"].rstrip("/")
    urls = [f"{site}/"] + [f"{site}/story/{s['id']}.html" for s in stories]
    return ('<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
            + "".join(f"<url><loc>{esc(u)}</loc></url>" for u in urls) + "</urlset>\n")


def write_site(out: Path, stories: list[dict], cfg: dict, now: datetime, status: dict) -> None:
    (out / "story").mkdir(parents=True, exist_ok=True)
    keep = {f"{s['id']}.html" for s in stories}
    for f in (out / "story").glob("*.html"):
        if f.name not in keep:
            f.unlink()
    (out / "style.css").write_text(CSS.strip() + "\n", encoding="utf-8")
    (out / "index.html").write_text(index_page(stories, cfg, now, status), encoding="utf-8")
    for s in stories:
        (out / "story" / f"{s['id']}.html").write_text(story_page(s, cfg), encoding="utf-8")
    (out / "feed.xml").write_text(feed_xml(stories, cfg, now), encoding="utf-8")
    (out / "sitemap.xml").write_text(sitemap_xml(stories, cfg), encoding="utf-8")
    (out / "robots.txt").write_text(f"User-agent: *\nAllow: /\nSitemap: {cfg['site_url'].rstrip('/')}/sitemap.xml\n", encoding="utf-8")
    (out / "status.json").write_text(json.dumps(status, indent=2, ensure_ascii=False), encoding="utf-8")
    (out / ".nojekyll").write_text("", encoding="utf-8")


# ---------- main ----------

def run(cfg: dict, out: Path, data_file: Path, fixtures: Path | None, now: datetime) -> dict:
    fresh: list[dict] = []
    src_status: list[dict] = []
    for src in cfg["sources"]:
        try:
            data = (fixtures / f"{src['id']}.xml").read_bytes() if fixtures else fetch(src["url"])
            if not re.search(rb"<(rss|feed|rdf)", data[:2000], re.I):
                raise RuntimeError("response is not an RSS/Atom feed")
            items = parse_feed(data, src)[: cfg.get("max_items_per_feed", 30)]
            fresh += items
            src_status.append({"id": src["id"], "name": src["name"], "ok": True, "count": len(items)})
        except Exception as e:  # noqa: BLE001 - one bad feed must not stop the run
            src_status.append({"id": src["id"], "name": src["name"], "ok": False, "count": 0, "error": str(e)[:200]})

    kev, kev_err = load_kev(fixtures)
    kev_checked = kev_err is None

    stored = json.loads(data_file.read_text(encoding="utf-8"))["items"] if data_file.exists() else []
    items = merge(stored, fresh, now, cfg.get("retention_days", 7))
    data_file.parent.mkdir(parents=True, exist_ok=True)
    data_file.write_text(json.dumps({"items": items}, indent=1, ensure_ascii=False), encoding="utf-8")

    stories = [build_story(g, kev, kev_checked, now) for g in cluster(items)]
    stories.sort(key=lambda s: (s["score"], s["published"] or ""), reverse=True)

    warnings = quality_warnings(stories)
    if kev_err:
        warnings.append(kev_err)
    if "YOUR-GITHUB-USER" in cfg["site_url"]:
        warnings.append("feeds.json site_url is still the placeholder; RSS and sitemap links will be wrong")
    ok_count = sum(1 for s in src_status if s["ok"])
    status = {
        "generated": now.isoformat(timespec="seconds"),
        "sources_ok": ok_count,
        "sources_total": len(src_status),
        "sources": src_status,
        "stories": len(stories),
        "critical": sum(1 for s in stories if s["priority"] == "Critical"),
        "high": sum(1 for s in stories if s["priority"] == "High"),
        "kev_loaded": kev_checked,
        "warnings": warnings,
    }
    write_site(out, stories, cfg, now, status)
    return status


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--fixtures", type=Path, help="directory with <source-id>.xml files (offline test)")
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--data", type=Path, default=DATA)
    args = ap.parse_args()
    cfg = json.loads(CONFIG.read_text(encoding="utf-8"))
    now = datetime.now(timezone.utc)
    status = run(cfg, args.out, args.data, args.fixtures, now)
    print(json.dumps({k: status[k] for k in ("generated", "sources_ok", "sources_total", "stories", "critical", "high", "warnings")}, indent=2))


if __name__ == "__main__":
    main()
