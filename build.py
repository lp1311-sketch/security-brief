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
    "threats": ("Ransomware, Malware & Breaches", r"ransomware|malware|breach|phishing|stealer|botnet|extortion|data leak|spyware|hijack|backdoor|scam|theft|cyberattack|cyber attack|shellcode|loader|supply[- ]chain|tampered|money laundering|sanction|proxyjack|attackers|hackers"),
    "vulnerabilities": ("Vulnerabilities & Exploited CVEs", r"vulnerab|\bcve-|patch|exploit|flaw|\brce\b|zero-day|0-day|security update"),
    "ai": ("AI Security & Emerging Threats", r"\bai\b|\bllm|copilot|chatgpt|openai|anthropic|gemini|deepfake|generative|ai agent|ai model"),
    "microsoft": ("Microsoft & Enterprise", r"microsoft|windows|exchange|sharepoint|teams|office 365|m365|outlook|defender|azure"),
    "cloud": ("Cloud & Identity", r"cloud|identity|\bmfa\b|okta|\bsso\b|oauth|sign-in|entra|conditional access|tenant"),
    "general": ("Security News", r"$^"),  # fallback, never matches
}
CATEGORY_ORDER = ["threats", "vulnerabilities", "ai", "cloud", "microsoft", "general"]  # rendering order
# Scoring order: ties go to the first entry (AI before vulnerabilities before threats).
SCORE_ORDER = ["ai", "vulnerabilities", "threats", "cloud", "microsoft"]

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


def clean_excerpt(text: str) -> str:
    t = text.replace("\\[...\\]", " ").replace("[...]", " ").replace("[…]", " ").replace("\\[…\\]", " ")
    t = re.sub(r"\s+([,.;:!?])", r"\1", t)  # "Cryptomus ," -> "Cryptomus,"
    return re.sub(r"\s+", " ", t).strip()


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


# ---------- original analysis (Markdown content) ----------

CONTENT_DIR = ROOT / "content"
SITE_CONFIG = ROOT / "site.json"
SECTIONS = {
    "briefings": "Weekly M365 & Entra Briefing",
    "patch-tuesday": "Patch Tuesday Notes",
}


def fmt_day(iso: str | None) -> str:
    d = _date(iso)
    return d.strftime("%d %b %Y") if d else ""


def parse_front_matter(text: str) -> tuple[dict, str]:
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}, text
    end = next((i for i in range(1, len(lines)) if lines[i].strip() == "---"), None)
    if end is None:
        return {}, text
    meta: dict = {}
    for line in lines[1:end]:
        if ":" in line:
            k, v = line.split(":", 1)
            meta[k.strip().lower()] = v.strip().strip('"').strip("'")
    return meta, "\n".join(lines[end + 1:])


def inline_md(text: str) -> str:
    t = html.escape(text, quote=True)
    t = re.sub(r"`([^`]+)`", r"<code>\1</code>", t)
    t = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", t)
    t = re.sub(r"(?<![*\w])\*([^*]+)\*(?![*\w])", r"<em>\1</em>", t)

    def link(m: re.Match) -> str:
        label, url = m.group(1), m.group(2)
        pu = urlparse(url)
        if pu.scheme not in ("http", "https") or not pu.netloc:
            return label  # unsafe or relative links are shown as plain text
        return f'<a href="{url}" rel="nofollow noopener noreferrer" target="_blank">{label}</a>'

    return re.sub(r"\[([^\]]+)\]\(([^)\s]+)\)", link, t)


def md_to_html(md: str) -> str:
    out: list[str] = []
    para: list[str] = []
    items: list[str] = []
    code: list[str] = []
    in_code = False

    def flush() -> None:
        if para:
            out.append("<p>" + inline_md(" ".join(para)) + "</p>")
            para.clear()
        if items:
            out.append("<ul>" + "".join(f"<li>{inline_md(i)}</li>" for i in items) + "</ul>")
            items.clear()

    for raw in md.splitlines():
        line = raw.rstrip()
        if line.lstrip().startswith("```"):
            if in_code:
                out.append("<pre><code>" + html.escape("\n".join(code)) + "</code></pre>")
                code.clear()
                in_code = False
            else:
                flush()
                in_code = True
            continue
        if in_code:
            code.append(raw)
            continue
        if not line.strip():
            flush()
            continue
        if re.match(r"^\s*<!--.*-->\s*$", line):
            continue  # HTML comments (for example, publishing notes in templates) are never shown
        m = re.match(r"^(#{1,3})\s+(.*)$", line)
        if m:
            flush()
            level = min(len(m.group(1)) + 1, 4)
            out.append(f"<h{level}>{inline_md(m.group(2))}</h{level}>")
            continue
        if re.match(r"^\s*[-*]\s+", line):
            if para:
                out.append("<p>" + inline_md(" ".join(para)) + "</p>")
                para.clear()
            items.append(re.sub(r"^\s*[-*]\s+", "", line))
            continue
        if line.startswith(">"):
            flush()
            out.append(f"<blockquote>{inline_md(line[1:].strip())}</blockquote>")
            continue
        if items:
            flush()
        para.append(line.strip())
    flush()
    if in_code:
        out.append("<pre><code>" + html.escape("\n".join(code)) + "</code></pre>")
    return "\n".join(out)


def load_articles(content_dir: Path, warnings: list[str]) -> list[dict]:
    arts: list[dict] = []
    for sec in SECTIONS:
        d = content_dir / sec
        if not d.is_dir():
            continue
        for f in sorted(d.glob("*.md")):
            if f.name.startswith("_"):
                continue  # templates
            meta, body = parse_front_matter(f.read_text(encoding="utf-8"))
            if str(meta.get("draft", "true")).lower() != "false":
                continue  # drafts are never published; set draft: false to publish
            if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", f.stem):
                warnings.append(f"{sec}/{f.name}: file name must use lowercase letters, digits and hyphens")
                continue
            date = _date(meta.get("date"))
            if not meta.get("title") or not date:
                warnings.append(f"{sec}/{f.name}: title and date are required, article skipped")
                continue
            arts.append({
                "section": sec, "slug": f.stem, "title": meta["title"], "date": date.date().isoformat(),
                "summary": meta.get("summary", ""), "body": md_to_html(body), "_md": body,
            })
    arts.sort(key=lambda a: a["date"], reverse=True)
    return arts


def load_site_config(path: Path) -> dict:
    if not path.exists():
        return {"publisher": {}, "newsletter_form_action": ""}
    return json.loads(path.read_text(encoding="utf-8"))


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
        summary = _short(clean_excerpt(_clean(body_raw)), 320)
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


def categorize(title: str, summary: str = "", cves=()) -> str:
    t, sm = (title or "").lower(), (summary or "").lower()
    scores = {}
    for key in SCORE_ORDER:
        rx = CATEGORIES[key][1]
        scores[key] = 3 * len(set(re.findall(rx, t))) + len(set(re.findall(rx, sm)))
    if cves:
        scores["vulnerabilities"] += 2
    best = max(SCORE_ORDER, key=lambda k: scores[k])
    return best if scores[best] > 0 else "general"


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


M365_RE = re.compile(r"microsoft 365|m365|office 365|exchange online|sharepoint|onedrive|microsoft teams|outlook", re.I)
ENTRA_RE = re.compile(r"entra|azure ad|conditional access|sign-in|oauth|consent|\bmfa\b|identity|token", re.I)
DEFENDER_RE = re.compile(r"defender|\bedr\b|\bxdr\b|sentinel", re.I)


def story_tags(text: str, prio: str, category: str, kev_hit: bool, exploited: bool, has_cve: bool) -> list[str]:
    tags = []
    if prio == "Critical":
        tags.append("critical")
    if exploited or kev_hit:
        tags.append("exploited")
    if kev_hit or (exploited and has_cve):
        tags.append("patch-now")
    if M365_RE.search(text):
        tags.append("m365")
    if ENTRA_RE.search(text):
        tags.append("entra")
    if DEFENDER_RE.search(text):
        tags.append("defender")
    if category == "ai":
        tags.append("ai")
    return tags


def build_story(items: list[dict], kev: set[str], kev_checked: bool, now: datetime) -> dict:
    head = items[0]
    text = " ".join(f"{i['title']} {i['summary']}" for i in items)
    score, prio, reasons = score_story(items, kev, kev_checked, now)
    with_img = next((i for i in items if i["image"]), None)
    cves = sorted({c for i in items for c in i["cves"]})
    category = categorize(head["title"], head["summary"], cves)
    kev_hit = bool(set(cves) & kev) if kev_checked else False
    exploited = bool(EXPLOITED_RE.search(text))
    tags = story_tags(text, prio, category, kev_hit, exploited, bool(cves))
    return {
        "id": head["id"],
        "title": head["title"],
        "summary": head["summary"],
        "published": head["published"],
        "category": category,
        "tags": tags,
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
:root{--bg:#f5f6f8;--surface:#ffffff;--ink:#0f172a;--muted:#475569;--line:#e2e8f0;--accent:#1d4ed8;--brand:#0b1a33;--crit:#b91c1c;--high:#fde68a;--high-ink:#78350f;--chip:#e0e7ff;--chip-ink:#1e3a8a;--serif:Georgia,"Iowan Old Style","Times New Roman",serif;--sans:system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif;color-scheme:light}
[data-theme="dark"]{--bg:#0a1120;--surface:#111a2d;--ink:#e6edf7;--muted:#a3b3c9;--line:#243452;--accent:#7cb3ff;--brand:#060b16;--chip:#1e2d4d;--chip-ink:#bcd3ff;--high:#7c4a03;--high-ink:#fde68a;color-scheme:dark}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans);font-size:16px;line-height:1.6;-webkit-font-smoothing:antialiased}
a{color:var(--accent)}
.skip{position:absolute;left:-9999px}
.skip:focus{left:12px;top:12px;background:var(--surface);color:var(--ink);padding:8px 12px;z-index:10}
.wrap{max-width:1160px;margin:0 auto;padding:0 20px}
.site-header{position:sticky;top:0;z-index:5;background:var(--brand);color:#fff}
.site-header .wrap{display:flex;align-items:center;gap:16px;min-height:60px}
.brand{font-family:var(--serif);font-weight:700;font-size:1.25rem;color:#fff;text-decoration:none;white-space:nowrap}
.nav{display:flex;gap:4px;overflow-x:auto;flex:1 1 0;min-width:0;scrollbar-width:none}
.nav a{color:#cbd5e1;text-decoration:none;font-size:.9rem;padding:6px 10px;border-radius:6px;white-space:nowrap}
.nav a:hover,.nav a:focus-visible{color:#fff;background:rgba(255,255,255,.08)}
.theme-toggle{flex:none;margin-left:auto;background:transparent;color:#fff;border:1px solid #64748b;border-radius:999px;padding:6px 14px;font:inherit;font-size:.85rem;cursor:pointer;white-space:nowrap}
.theme-toggle:hover{background:rgba(255,255,255,.08)}
main.wrap{padding-top:32px;padding-bottom:64px}
.intro{margin-bottom:24px}
.intro h1,.prose h1{font-family:var(--serif);font-size:clamp(1.8rem,3.2vw,2.5rem);line-height:1.15;margin:.2em 0 .3em;letter-spacing:-.01em}
.section{margin-top:44px}
.section h2{font-family:var(--serif);font-size:1.35rem;margin:0 0 14px;padding-left:12px;border-left:4px solid var(--accent)}
.hero{display:grid;grid-template-columns:1.25fr 1fr;background:var(--surface);border:1px solid var(--line);border-radius:14px;overflow:hidden}
.hero-media img{width:100%;height:100%;min-height:260px;object-fit:cover;display:block;background:var(--brand)}
.hero-body{padding:28px;display:flex;flex-direction:column;gap:10px;justify-content:center}
.hero-body h2{font-family:var(--serif);font-size:clamp(1.5rem,2.6vw,2rem);line-height:1.2;margin:0}
.hero-body h2 a{color:var(--ink);text-decoration:none}
.hero-body h2 a:hover,.hero-body h2 a:focus-visible{text-decoration:underline}
.grid{display:grid;gap:18px;grid-template-columns:repeat(auto-fill,minmax(250px,1fr))}
.card{background:var(--surface);border:1px solid var(--line);border-radius:12px;overflow:hidden;display:flex;flex-direction:column;transition:border-color .15s}
.card:hover{border-color:var(--accent)}
.card img{width:100%;aspect-ratio:16/9;object-fit:cover;display:block;background:var(--brand)}
.card-body{padding:16px;display:flex;flex-direction:column;gap:8px;flex:1}
.card h3{font-family:var(--serif);font-size:1.12rem;line-height:1.3;margin:0}
.card h3 a{color:var(--ink);text-decoration:none}
.card h3 a:hover,.card h3 a:focus-visible{text-decoration:underline}
.summary{margin:0;color:var(--muted);font-size:.95rem}
.meta{margin:0;color:var(--muted);font-size:.84rem}
.kicker{margin:0;font-size:.8rem;color:var(--muted);display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.badge{display:inline-block;font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em;padding:3px 8px;border-radius:4px;background:var(--chip);color:var(--chip-ink)}
.badge.Critical{background:var(--crit);color:#fff}
.badge.High{background:var(--high);color:var(--high-ink)}
.note{background:var(--chip);color:var(--chip-ink);border-radius:8px;padding:12px 16px;font-size:.92rem}
.box{background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:16px 20px}
.empty{background:var(--surface);border:1px dashed var(--muted);border-radius:12px;padding:24px;color:var(--muted)}
.prose{max-width:760px;margin:0 auto}
.prose h2{font-family:var(--serif);font-size:1.3rem;margin:2rem 0 .6rem}
.prose figure{margin:24px 0}
.prose figure img{width:100%;aspect-ratio:16/9;object-fit:cover;border-radius:12px;background:var(--brand);display:block}
figcaption{font-size:.8rem;color:var(--muted);margin-top:6px}
.prose ul{padding-left:1.2rem}
.site-footer{border-top:1px solid var(--line);color:var(--muted);font-size:.85rem;padding:24px 0}
:focus-visible{outline:3px solid #f59e0b;outline-offset:2px}
@media (max-width:760px){
  .hero{grid-template-columns:1fr}
  .hero-media img{min-height:0;aspect-ratio:16/9}
  .hero-body{padding:20px}
  .site-header .wrap{flex-wrap:wrap;padding-top:10px;padding-bottom:10px}
  .theme-toggle{margin-left:0}
}
@media (prefers-reduced-motion:reduce){*{transition:none!important;scroll-behavior:auto!important}}
"""

THEME_JS = """(function(){
var root=document.documentElement,dark=false,saved=null;
try{saved=localStorage.getItem('sb-theme')}catch(e){}
dark=saved?saved==='dark':(window.matchMedia&&window.matchMedia('(prefers-color-scheme: dark)').matches);
function apply(){root.setAttribute('data-theme',dark?'dark':'light');
var b=document.getElementById('theme-toggle');
if(b){b.textContent=dark?'Light mode':'Dark mode';b.setAttribute('aria-pressed',String(dark));}}
apply();
document.addEventListener('DOMContentLoaded',function(){
var b=document.getElementById('theme-toggle');
if(b){b.addEventListener('click',function(){dark=!dark;try{localStorage.setItem('sb-theme',dark?'dark':'light')}catch(e){}apply();});}
apply();});
})();"""

SHORT_NAV = {"threats": "Threats", "vulnerabilities": "Vulnerabilities", "ai": "AI",
             "cloud": "Cloud & Identity", "microsoft": "Microsoft"}


def _layout(cfg: dict, title: str, desc: str, body: str, base: str) -> str:
    site = esc(cfg["site_name"])
    links = [f'<a href="{base}index.html#{cid}">{esc(SHORT_NAV[cid])}</a>'
             for cid in CATEGORY_ORDER if cid != "general"]
    links.append(f'<a href="{base}briefings/index.html">Briefings</a>')
    links.append(f'<a href="{base}patch-tuesday/index.html">Patch Tuesday</a>')
    nav = "".join(links)
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title)} | {site}</title>
<meta name="description" content="{esc(desc)}">
<script>{THEME_JS}</script>
<link rel="stylesheet" href="{base}style.css">
<link rel="alternate" type="application/rss+xml" title="{site}" href="{esc(cfg['site_url'])}/feed.xml">
</head>
<body>
<a class="skip" href="#main">Skip to content</a>
<header class="site-header"><div class="wrap">
<a class="brand" href="{base}index.html">{site}</a>
<nav class="nav" aria-label="Categories">{nav}</nav>
<button type="button" id="theme-toggle" class="theme-toggle" aria-pressed="false">Dark mode</button>
</div></header>
<main id="main" class="wrap">
{body}
</main>
<footer class="site-footer"><div class="wrap">Automated briefing. Headlines and short excerpts come from public RSS feeds, and every story links to the original publisher. Not affiliated with any source. &middot; <a href="{base}impressum.html">Impressum</a> &middot; <a href="{base}datenschutz.html">Privacy</a> &middot; <a href="{base}feed.xml">RSS</a> &middot; <a href="{base}status.json">Run status</a></div></footer>
</body>
</html>
"""


def _card(s: dict) -> str:
    img = s["image"] or cover_svg(CATEGORIES[s["category"]][0])
    names = ", ".join(dict.fromkeys(x["name"] for x in s["sources"]))
    return f"""<article class="card" data-tags="{esc(' '.join(s['tags']))}">
<img src="{esc(img)}" alt="" loading="lazy" decoding="async" referrerpolicy="no-referrer" width="640" height="360">
<div class="card-body">
<p class="kicker"><span class="badge {esc(s['priority'])}">{esc(s['priority'])}</span>{esc(CATEGORIES[s['category']][0])}</p>
<h3><a href="story/{esc(s['id'])}.html">{esc(s['title'])}</a></h3>
<p class="summary">{esc(_short(s['summary'], 150))}</p>
<p class="meta">{esc(names)} &middot; {esc(fmt_date(s['published']))}</p>
</div>
</article>"""


def _hero(s: dict) -> str:
    img = s["image"] or cover_svg(CATEGORIES[s["category"]][0])
    names = ", ".join(dict.fromkeys(x["name"] for x in s["sources"]))
    return f"""<section class="hero" aria-labelledby="hero-title" data-tags="{esc(' '.join(s['tags']))}">
<a class="hero-media" href="story/{esc(s['id'])}.html" tabindex="-1" aria-hidden="true"><img src="{esc(img)}" alt="" loading="eager" referrerpolicy="no-referrer" width="640" height="360"></a>
<div class="hero-body">
<p class="kicker"><span class="badge {esc(s['priority'])}">{esc(s['priority'])}</span>{esc(CATEGORIES[s['category']][0])}</p>
<h2 id="hero-title"><a href="story/{esc(s['id'])}.html">{esc(s['title'])}</a></h2>
<p class="summary">{esc(_short(s['summary'], 260))}</p>
<p class="meta">{esc(names)} &middot; {esc(fmt_date(s['published']))}</p>
</div>
</section>"""


EXTRA_CSS = """
:root{--btn-bg:#1d4ed8;--btn-ink:#ffffff}
[data-theme="dark"]{--btn-bg:#7cb3ff;--btn-ink:#06101f}
.lede{font-size:1.15rem;color:var(--muted);margin:0 0 1.2rem}
.subscribe{margin:40px 0 0;background:var(--surface);border:1px solid var(--line);border-radius:14px;padding:24px}
.subscribe h2{font-family:var(--serif);font-size:1.3rem;margin:0 0 6px}
.subscribe-form{display:flex;gap:8px;flex-wrap:wrap;margin:14px 0 8px}
.subscribe-form input{flex:1 1 220px;min-width:0;padding:10px 12px;border:1px solid var(--line);border-radius:8px;font:inherit;background:var(--bg);color:var(--ink)}
.subscribe-form button{padding:10px 18px;border:0;border-radius:8px;background:var(--btn-bg);color:var(--btn-ink);font:inherit;font-weight:600;cursor:pointer}
.subscribe-form button:hover{filter:brightness(1.08)}
.visually-hidden{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
.analysis-links{margin:12px 0 0}
.card-kicker{margin:0;font-size:.8rem;color:var(--muted)}
[hidden]{display:none!important}
.filters{display:flex;gap:8px;flex-wrap:wrap;margin:8px 0 4px}
.filters button{font:inherit;font-size:.88rem;padding:6px 14px;border-radius:999px;border:1px solid var(--line);background:var(--surface);color:var(--ink);cursor:pointer}
.filters button:hover{border-color:var(--accent)}
.filters button[aria-pressed="true"]{background:var(--btn-bg);color:var(--btn-ink);border-color:var(--btn-bg)}
"""


def _newsletter(site_cfg: dict, base: str) -> str:
    action = (site_cfg.get("newsletter_form_action") or "").strip()
    if not action.startswith("https://"):
        return ""  # no provider configured: no form is shown
    return f"""<section class="subscribe" aria-labelledby="subscribe-title">
<h2 id="subscribe-title">Get the analysis by email</h2>
<p class="summary">The weekly M365 and Entra briefing and the Patch Tuesday notes, written by the author.</p>
<form action="{esc(action)}" method="post" class="subscribe-form">
<label for="nl-email" class="visually-hidden">Email address</label>
<input id="nl-email" type="email" name="email" required autocomplete="email" placeholder="you@example.com">
<button type="submit">Subscribe</button>
</form>
<p class="meta">You can unsubscribe at any time. <a href="{base}datenschutz.html">Privacy notice</a></p>
</section>"""


def _article_card(a: dict, href: str) -> str:
    label = SECTIONS[a["section"]]
    return f"""<article class="card">
<div class="card-body">
<p class="card-kicker">{esc(label)}</p>
<h3><a href="{esc(href)}">{esc(a['title'])}</a></h3>
<p class="summary">{esc(_short(a['summary'], 180))}</p>
<p class="meta">{esc(fmt_day(a['date']))}</p>
</div>
</article>"""


def article_page(a: dict, cfg: dict, site_cfg: dict) -> str:
    base = "../../"
    label = SECTIONS[a["section"]]
    lede = f'<p class="lede">{esc(a["summary"])}</p>' if a["summary"] else ""
    body = (
        '<article class="prose">'
        f'<p class="kicker">{esc(label)} &middot; {esc(fmt_day(a["date"]))}</p>'
        f'<h1>{esc(a["title"])}</h1>{lede}{a["body"]}'
        f'<p class="meta"><a href="index.html">&larr; All {esc(label)}</a> &middot; <a href="../../index.html">Home</a></p>'
        "</article>"
    )
    body += _newsletter(site_cfg, base)
    return _layout(cfg, a["title"], _short(a["summary"] or a["title"], 150), body, base)


def section_page(sec: str, arts: list[dict], cfg: dict, site_cfg: dict) -> str:
    base = "../"
    label = SECTIONS[sec]
    cards = "".join(_article_card(a, f"{a['slug']}.html") for a in arts) or '<div class="empty">No published articles yet.</div>'
    body = (
        f'<section class="intro"><h1>{esc(label)}</h1><p class="meta">Original analysis, newest first.</p></section>'
        f'<div class="grid">{cards}</div>'
    ) + _newsletter(site_cfg, base)
    return _layout(cfg, label, f"{label}: original analysis.", body, base)


def legal_pages(site_cfg: dict, cfg: dict) -> dict[str, str]:
    p = site_cfg.get("publisher") or {}
    name = (p.get("name") or "").strip()
    addr = (p.get("address") or "").strip()
    mail = (p.get("email") or "").strip()
    addr_html = "<br>".join(esc(x) for x in addr.splitlines() if x.strip())
    if name and addr and mail:
        imp = (
            f"<p>Angaben gemäß § 5 DDG:</p>"
            f"<p>{esc(name)}<br>{addr_html}<br>E-Mail: {esc(mail)}</p>"
            f"<p>Verantwortlich für den Inhalt gemäß § 18 Abs. 2 MStV: {esc(name)}, {addr_html}</p>"
        )
        controller = f"{esc(name)}, {addr_html}, E-Mail: {esc(mail)}"
    else:
        imp = "<p>Impressum: Angaben werden ergänzt.</p>"
        controller = "siehe Impressum"
    impressum = (
        '<article class="prose"><h1>Impressum</h1>' + imp + "</article>"
    )
    privacy = (
        '<article class="prose"><h1>Datenschutzerklärung</h1>'
        "<h2>Verantwortlicher</h2>"
        f"<p>{controller}</p>"
        "<h2>Hosting und Server-Logs</h2>"
        "<p>Diese Seite wird über GitHub Pages bereitgestellt. Beim Aufruf verarbeitet der Hosting-Anbieter "
        "technisch notwendige Verbindungsdaten, zum Beispiel die IP-Adresse, in Server-Logs.</p>"
        "<h2>Vorschaubilder</h2>"
        "<p>Vorschaubilder einzelner Meldungen werden direkt von den Servern der jeweiligen Nachrichtenseiten geladen. "
        "Dabei erhalten diese Server Ihre IP-Adresse.</p>"
        "<h2>Cookies und Analyse</h2>"
        "<p>Diese Seite setzt keine Tracking-Cookies und verwendet kein Web-Analyse-Werkzeug.</p>"
        "<h2>Newsletter</h2>"
        "<p>Wenn Sie den Newsletter abonnieren, verarbeiten wir Ihre E-Mail-Adresse, um Ihnen den Newsletter zu senden. "
        "Die Anmeldung läuft über einen externen Newsletter-Anbieter, dessen Datenschutzhinweise ebenfalls gelten. "
        "Sie können sich jederzeit über den Link in jeder E-Mail abmelden.</p>"
        "<h2>Ihre Rechte</h2>"
        "<p>Sie haben das Recht auf Auskunft, Berichtigung, Löschung, Einschränkung der Verarbeitung, Widerspruch "
        "und Datenübertragbarkeit.</p>"
        "</article>"
    )
    return {
        "impressum.html": _layout(cfg, "Impressum", "Impressum", impressum, ""),
        "datenschutz.html": _layout(cfg, "Datenschutzerklärung", "Datenschutzerklärung", privacy, ""),
    }


FILTERS = [
    ("all", "All"), ("critical", "Critical"), ("exploited", "Actively exploited"), ("patch-now", "Patch now"),
    ("m365", "Microsoft 365"), ("entra", "Entra ID"), ("defender", "Defender"), ("ai", "AI security"),
]
FILTER_BAR = (
    '<div class="filters" id="filters" role="group" aria-label="Filter stories by topic">'
    + "".join(f'<button type="button" data-filter="{k}" aria-pressed="{"true" if k == "all" else "false"}">{esc(v)}</button>'
              for k, v in FILTERS)
    + '</div><p id="filter-empty" class="empty" hidden>No stories match this filter in the current window.</p>'
)
FILTER_JS = """(function(){
var bar=document.getElementById('filters');if(!bar)return;
var buttons=bar.querySelectorAll('button[data-filter]');
var items=document.querySelectorAll('[data-tags]');
var sections=document.querySelectorAll('[data-section]');
var empty=document.getElementById('filter-empty');
function apply(f){
  buttons.forEach(function(b){b.setAttribute('aria-pressed',String(b.getAttribute('data-filter')===f));});
  var shown=0;
  items.forEach(function(el){
    var tags=' '+(el.getAttribute('data-tags')||'')+' ';
    var ok=(f==='all')||tags.indexOf(' '+f+' ')>-1;
    el.hidden=!ok; if(ok){shown++;}
  });
  sections.forEach(function(sec){sec.hidden=!sec.querySelector('[data-tags]:not([hidden])');});
  if(empty){empty.hidden=shown>0;}
}
buttons.forEach(function(b){b.addEventListener('click',function(){apply(b.getAttribute('data-filter'));});});
apply('all');
})();"""


def index_page(stories: list[dict], cfg: dict, now: datetime, status: dict,
               articles: list[dict] | None = None, site_cfg: dict | None = None) -> str:
    articles = articles or []
    site_cfg = site_cfg or {}
    parts = [
        '<section class="intro"><h1>Security news, ranked</h1>'
        f'<p class="meta">Last content update: {esc(now.strftime("%d %b %Y, %H:%M UTC"))} &middot; '
        f'Feed status: {status["sources_ok"]} of {status["sources_total"]} sources reachable &middot; '
        "Checked automatically, updated when new stories arrive.</p></section>"
    ]
    if articles:
        parts.append(
            '<section class="section" id="analysis"><h2>From the analysis desk</h2><div class="grid">'
            + "".join(_article_card(a, f"{a['section']}/{a['slug']}.html") for a in articles[:3])
            + '</div><p class="analysis-links meta"><a href="briefings/index.html">All briefings</a> &middot; '
            '<a href="patch-tuesday/index.html">All Patch Tuesday notes</a></p></section>'
        )
    newsletter = _newsletter(site_cfg, "")
    if newsletter:
        parts.append(newsletter)
    if not stories:
        parts.append('<div class="empty">No news stories yet. The next automated check will fill this page.</div>')
    else:
        parts.append(FILTER_BAR)
        featured = stories[:4]
        parts.append('<section class="section" aria-label="Top news" data-section>' + _hero(featured[0]) + "</section>")
        if len(featured) > 1:
            parts.append('<section class="section" aria-label="More top stories" data-section><h2>Also in focus</h2><div class="grid">'
                         + "".join(_card(s) for s in featured[1:]) + "</div></section>")
        featured_ids = {s["id"] for s in featured}
        for cid in CATEGORY_ORDER:
            items = [s for s in stories if s["category"] == cid and s["id"] not in featured_ids][:6]
            if not items:
                continue
            parts.append(f'<section class="section" id="{cid}" data-section><h2>{esc(CATEGORIES[cid][0])}</h2>'
                         '<div class="grid">' + "".join(_card(s) for s in items) + "</div></section>")
        parts.append("<script>" + FILTER_JS + "</script>")
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
    return _layout(cfg, s["title"], desc, f'<article class="prose">{body}</article>', "../")


def feed_xml(stories: list[dict], cfg: dict, now: datetime, articles: list[dict] | None = None) -> str:
    site = cfg["site_url"].rstrip("/")
    entries = []
    for a in (articles or [])[:20]:
        link = f"{site}/{a['section']}/{a['slug']}.html"
        entries.append((a["title"], link, a["summary"] or a["title"], _date(a["date"]) or now, SECTIONS[a["section"]]))
    for s in stories[:40]:
        link = f"{site}/story/{s['id']}.html"
        entries.append((s["title"], link, s["summary"], _date(s["published"]) or now, CATEGORIES[s["category"]][0]))
    items = "".join(
        "<item>"
        f"<title>{esc(t)}</title><link>{esc(l)}</link><guid isPermaLink='true'>{esc(l)}</guid>"
        f"<pubDate>{format_datetime(p)}</pubDate><category>{esc(c)}</category><description>{esc(d)}</description>"
        "</item>"
        for t, l, d, p, c in entries
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n<rss version="2.0"><channel>'
        f"<title>{esc(cfg['site_name'])}</title><link>{esc(site)}/</link>"
        "<description>Original analysis and ranked cybersecurity news with links to original sources</description>"
        f"<lastBuildDate>{format_datetime(now)}</lastBuildDate>"
        + items + "</channel></rss>\n"
    )


def sitemap_xml(stories: list[dict], cfg: dict, articles: list[dict] | None = None) -> str:
    site = cfg["site_url"].rstrip("/")
    urls = [f"{site}/", f"{site}/briefings/index.html", f"{site}/patch-tuesday/index.html",
            f"{site}/impressum.html", f"{site}/datenschutz.html"]
    urls += [f"{site}/{a['section']}/{a['slug']}.html" for a in (articles or [])]
    urls += [f"{site}/story/{s['id']}.html" for s in stories]
    return ('<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
            + "".join(f"<url><loc>{esc(u)}</loc></url>" for u in urls) + "</urlset>\n")


def write_site(out: Path, stories: list[dict], cfg: dict, now: datetime, status: dict,
               articles: list[dict] | None = None, site_cfg: dict | None = None) -> None:
    articles = articles or []
    site_cfg = site_cfg or {}
    (out / "story").mkdir(parents=True, exist_ok=True)
    keep = {f"{s['id']}.html" for s in stories}
    for f in (out / "story").glob("*.html"):
        if f.name not in keep:
            f.unlink()
    (out / "style.css").write_text(CSS.strip() + "\n" + EXTRA_CSS, encoding="utf-8")
    (out / "index.html").write_text(index_page(stories, cfg, now, status, articles, site_cfg), encoding="utf-8")
    for s in stories:
        (out / "story" / f"{s['id']}.html").write_text(story_page(s, cfg), encoding="utf-8")
    for sec in SECTIONS:
        sec_articles = [a for a in articles if a["section"] == sec]
        d = out / sec
        d.mkdir(parents=True, exist_ok=True)
        wanted = {f"{a['slug']}.html" for a in sec_articles} | {"index.html"}
        for f in d.glob("*.html"):
            if f.name not in wanted:
                f.unlink()
        (d / "index.html").write_text(section_page(sec, sec_articles, cfg, site_cfg), encoding="utf-8")
        for a in sec_articles:
            (d / f"{a['slug']}.html").write_text(article_page(a, cfg, site_cfg), encoding="utf-8")
    for name, page in legal_pages(site_cfg, cfg).items():
        (out / name).write_text(page, encoding="utf-8")
    (out / "feed.xml").write_text(feed_xml(stories, cfg, now, articles), encoding="utf-8")
    (out / "sitemap.xml").write_text(sitemap_xml(stories, cfg, articles), encoding="utf-8")
    (out / "robots.txt").write_text(f"User-agent: *\nAllow: /\nSitemap: {cfg['site_url'].rstrip('/')}/sitemap.xml\n", encoding="utf-8")
    (out / "status.json").write_text(json.dumps(status, indent=2, ensure_ascii=False), encoding="utf-8")
    (out / ".nojekyll").write_text("", encoding="utf-8")


# ---------- main ----------

def run(cfg: dict, out: Path, data_file: Path, fixtures: Path | None, now: datetime,
        site_cfg: dict | None = None, content_dir: Path | None = None) -> dict:
    site_cfg = site_cfg or {}
    content_dir = content_dir or CONTENT_DIR
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
    items_text = json.dumps({"items": sorted(items, key=lambda i: i["link"])}, indent=1, ensure_ascii=False)

    stories = [build_story(g, kev, kev_checked, now) for g in cluster(items)]
    stories.sort(key=lambda s: (s["score"], s["published"] or ""), reverse=True)

    warnings = quality_warnings(stories)
    articles = load_articles(content_dir, warnings)
    publisher = site_cfg.get("publisher") or {}
    if not all((publisher.get(k) or "").strip() for k in ("name", "address", "email")):
        warnings.append("site.json publisher details incomplete: Impressum page is a placeholder")
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
        "analysis_articles": len(articles),
        "critical": sum(1 for s in stories if s["priority"] == "Critical"),
        "high": sum(1 for s in stories if s["priority"] == "High"),
        "kev_loaded": kev_checked,
        "warnings": warnings,
    }

    # Only touch tracked files when published content changes, so the repo
    # does not get a commit on every scheduled run.
    digest_src = json.dumps({
        "stories": [[s["id"], s["title"], s["summary"], s["published"], s["category"], s["priority"],
                     s["score"], s["image"], [x["url"] for x in s["sources"]]] for s in stories],
        "articles": [[a["section"], a["slug"], a["title"], a["date"], a["summary"], a["_md"]] for a in articles],
        "site": site_cfg,
        "render": "5.1",  # bump when the HTML/CSS/JS output changes, so the site rebuilds
    }, ensure_ascii=False, sort_keys=True)
    digest = hashlib.sha1(digest_src.encode("utf-8")).hexdigest()
    digest_file = data_file.parent / "digest.txt"
    prev_digest = digest_file.read_text(encoding="utf-8").strip() if digest_file.exists() else ""
    site_missing = not (out / "index.html").exists()
    status["changed"] = digest != prev_digest or site_missing
    if status["changed"]:
        data_file.parent.mkdir(parents=True, exist_ok=True)
        data_file.write_text(items_text, encoding="utf-8")
        digest_file.write_text(digest + "\n", encoding="utf-8")
        write_site(out, stories, cfg, now, status, articles, site_cfg)
    elif not data_file.exists() or data_file.read_text(encoding="utf-8") != items_text:
        data_file.write_text(items_text, encoding="utf-8")
    return status


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--fixtures", type=Path, help="directory with <source-id>.xml files (offline test)")
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--data", type=Path, default=DATA)
    args = ap.parse_args()
    cfg = json.loads(CONFIG.read_text(encoding="utf-8"))
    now = datetime.now(timezone.utc)
    site_cfg = load_site_config(SITE_CONFIG)
    status = run(cfg, args.out, args.data, args.fixtures, now, site_cfg)
    print(json.dumps({k: status[k] for k in ("generated", "sources_ok", "sources_total", "stories", "critical", "high", "warnings")}, indent=2))


if __name__ == "__main__":
    main()
