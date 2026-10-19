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
from urllib.parse import parse_qsl, quote, urlencode, urljoin, urlparse, urlunparse

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


def fallback_cover(s: dict) -> str:
    """Branded placeholder for stories without a usable preview image. Built from the story's own data."""
    cat = CATEGORIES[s["category"]][0]
    accent = {"Critical": "#ff5c5c", "High": "#fbbf24"}.get(s["priority"], "#5eead4")
    if s.get("vendors"):
        top, main = cat.upper(), s["vendors"][0]
    else:
        top, main = "SECURITY BRIEF", cat
    size = 46 if len(main) <= 14 else 34 if len(main) <= 24 else 26
    grid = "".join(f'<line x1="{x}" y1="0" x2="{x}" y2="360"/>' for x in range(0, 641, 64))
    grid += "".join(f'<line x1="0" y1="{y}" x2="640" y2="{y}"/>' for y in range(0, 361, 60))
    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" width="640" height="360" viewBox="0 0 640 360">'
        '<rect width="640" height="360" fill="#0b0f14"/>'
        f'<g stroke="#18202b" stroke-width="1">{grid}</g>'
        f'<rect width="8" height="360" fill="{accent}"/>'
        f'<text x="48" y="112" fill="{accent}" font-family="Arial,Helvetica,sans-serif" font-size="16" font-weight="700" letter-spacing="3">{esc(top)}</text>'
        f'<text x="48" y="196" fill="#f1f5f9" font-family="Arial,Helvetica,sans-serif" font-size="{size}" font-weight="700">{esc(main)}</text>'
        '<text x="48" y="318" fill="#64748b" font-family="Arial,Helvetica,sans-serif" font-size="13" letter-spacing="2">SECURITY BRIEF</text>'
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


OG_TAG_RE = re.compile(r"<meta\b[^>]*>", re.I)
OG_IMG_RE = re.compile(r"""(?:property|name)\s*=\s*["'](?:og:image|twitter:image)(?::secure_url|:src)?["']""", re.I)
CONTENT_ATTR_RE = re.compile(r"""content\s*=\s*["']([^"']+)["']""", re.I)
IMAGE_BUDGET = 12  # article pages read per run to find preview images


def fetch_preview_image(url: str, timeout: int = 10) -> str | None:
    """Read the article's own og:image / twitter:image meta tag. Only used when the feed has no image."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "text/html"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            page = r.read(300_000).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001 - a missing preview is not an error
        return None
    for m in OG_TAG_RE.finditer(page):
        tag = m.group(0)
        if OG_IMG_RE.search(tag):
            c = CONTENT_ATTR_RE.search(tag)
            if c:
                img = https_image(html.unescape(urljoin(url, c.group(1))))
                if img:
                    return img
    return None


def enrich_images(items: list[dict], budget: int = IMAGE_BUDGET) -> None:
    """Fill missing images from article pages, newest first. Each item is checked once, so the cost stays small."""
    for it in sorted(items, key=lambda i: i.get("published") or "", reverse=True):
        if budget <= 0:
            break
        if it.get("image") or it.get("image_checked"):
            continue
        it["image"] = fetch_preview_image(it["link"])
        it["image_checked"] = True
        budget -= 1


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


# Vendors/products frequently hit by exploited flaws in admin, remote-access and edge devices.
# Matching is on title + summary only. Microsoft is deliberately not listed: it is its own category.
VENDORS = {
    "BeyondTrust": r"beyondtrust",
    "ConnectWise": r"connectwise|screenconnect",
    "Fortinet": r"fortinet|fortigate|fortios|fortiweb|forticlient|fortimanager",
    "Palo Alto Networks": r"palo alto|pan-os|globalprotect",
    "Ivanti": r"ivanti|connect secure|endpoint manager mobile",
    "Citrix": r"citrix|netscaler",
    "Cisco": r"cisco|ios xe|asa\b",
    "SonicWall": r"sonicwall|sonicos",
    "Check Point": r"check point|checkpoint",
    "Zyxel": r"zyxel",
    "Juniper Networks": r"juniper",
    "F5": r"\bf5\b|big-ip",
    "Veeam": r"veeam",
    "VMware": r"vmware|vcenter|esxi",
    "Atlassian": r"atlassian|confluence|bitbucket|jira",
    "Oracle": r"oracle|weblogic",
    "SAP": r"\bsap\b",
    "SolarWinds": r"solarwinds",
    "Okta": r"\bokta\b",
    "Sophos": r"sophos",
    "Trend Micro": r"trend micro",
    "Google Chrome": r"chrome|chromium",
    "Apple": r"\bapple\b|\bios\b|macos|ipados|safari",
    "Adobe": r"\badobe\b|acrobat|\bcoldfusion\b",
    "Zoom": r"zoom (?:client|meetings?|workplace|video|rooms)",
}
VENDOR_RES = {name: re.compile(pat, re.I) for name, pat in VENDORS.items()}


def vendors_in(text: str) -> set[str]:
    return {name for name, rx in VENDOR_RES.items() if rx.search(text)}


def cluster(items: list[dict]) -> list[list[dict]]:
    """Group items about the same event. Newest first.

    Items join a group when they share a CVE, when their titles are very similar,
    or when they name the same vendor and share at least two meaningful title words
    (catches the same vulnerability reported under different headlines).
    """
    groups: list[dict] = []
    for it in sorted(items, key=lambda i: i.get("published") or "", reverse=True):
        toks = _tokens(it["title"])
        vend = vendors_in(f"{it['title']} {it.get('summary', '')}")
        home = None
        for g in groups:
            if set(it["cves"]) & g["cves"]:
                home = g
                break
            if vend and g["vendors"] and not (vend & g["vendors"]):
                continue  # both name a vendor and it is a different one: never merge
            if _jaccard(toks, g["tokens"]) >= 0.5:
                home = g
                break
            if vend and vend & g["vendors"]:
                shared = (toks & g["tokens"]) - {"vulnerability", "vulnerabilities", "flaw", "flaws", "bug"} \
                    - {w for v in VENDORS for w in re.findall(r"[a-z0-9]+", v.lower())}
                if len(shared) >= 2 and _jaccard(toks, g["tokens"]) >= 0.2:
                    home = g
                    break
        if home is None:
            home = {"items": [], "cves": set(), "tokens": toks, "vendors": set()}
            groups.append(home)
        home["items"].append(it)
        home["cves"] |= set(it["cves"])
        home["vendors"] |= vend
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
        "vendors": sorted(set().union(*(vendors_in(f"{i['title']} {i['summary']}") for i in items))),
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
:root{--bg:#f4f5f7;--surface:#ffffff;--surface-2:#eceff3;--ink:#0d1117;--muted:#5a6375;--line:#e1e5eb;--accent:#0f766e;--accent-ink:#ffffff;--crit:#c81e1e;--high:#9a5b00;--std:#475569;--sans:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;--r:16px;--shadow:0 1px 2px rgba(13,17,23,.06),0 14px 34px -16px rgba(13,17,23,.22);color-scheme:light}
[data-theme="dark"]{--bg:#090b0e;--surface:#12161c;--surface-2:#1a2028;--ink:#eef2f7;--muted:#9aa4b4;--line:#242b35;--accent:#5eead4;--accent-ink:#03201c;--crit:#ff6b6b;--high:#fbbf24;--std:#c5ceda;--shadow:0 1px 2px rgba(0,0,0,.5),0 18px 44px -18px rgba(0,0,0,.8);color-scheme:dark}
*{box-sizing:border-box}
html{scroll-behavior:smooth;-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans);font-size:16px;line-height:1.6;-webkit-font-smoothing:antialiased}
a{color:var(--accent)}
img{display:block;max-width:100%}
.skip{position:absolute;left:-9999px}
.skip:focus{left:12px;top:12px;background:var(--surface);color:var(--ink);padding:8px 12px;z-index:10;border-radius:8px}
.wrap{max-width:1200px;margin:0 auto;padding:0 20px}
.site-header{position:sticky;top:0;z-index:20;background:var(--bg);border-bottom:1px solid var(--line)}
@supports (backdrop-filter:blur(8px)){.site-header{background:color-mix(in srgb,var(--bg) 86%,transparent);backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px)}}
.bar{display:flex;align-items:center;gap:18px;min-height:64px}
.brand{display:inline-flex;align-items:center;gap:10px;font-weight:750;font-size:1.02rem;letter-spacing:-.01em;color:var(--ink);text-decoration:none;white-space:nowrap}
.mark{width:22px;height:22px;border-radius:7px;background:var(--accent);box-shadow:inset 0 0 0 5px var(--bg);flex:none}
.nav{display:flex;gap:2px;overflow-x:auto;flex:1 1 0;min-width:0;scrollbar-width:none}
.nav a{color:var(--muted);text-decoration:none;font-size:.9rem;font-weight:500;padding:7px 11px;border-radius:999px;white-space:nowrap}
.nav a:hover,.nav a:focus-visible{color:var(--ink);background:var(--surface-2)}
.theme-toggle{flex:none;margin-left:auto;font:inherit;font-size:.85rem;font-weight:550;color:var(--ink);background:var(--surface);border:1px solid var(--line);border-radius:999px;padding:7px 14px;cursor:pointer;white-space:nowrap}
.theme-toggle:hover{border-color:var(--accent)}
main.wrap{padding-top:32px;padding-bottom:72px}
.intro{margin-bottom:22px}
.intro h1,.prose h1{font-size:clamp(1.9rem,4vw,2.8rem);line-height:1.05;letter-spacing:-.03em;margin:0 0 8px;font-weight:780}
.intro .meta{font-size:.9rem}
.stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:0 0 22px}
.stat{background:var(--surface);border:1px solid var(--line);border-radius:14px;padding:14px 16px}
.stat b{display:block;font-size:1.65rem;line-height:1.1;font-weight:760;letter-spacing:-.02em;font-variant-numeric:tabular-nums}
.stat span{font-size:.8rem;color:var(--muted)}
.stat.crit b{color:var(--crit)}
.filters{display:flex;gap:8px;flex-wrap:wrap;margin:0 0 30px}
.filters button{font:inherit;font-size:.88rem;font-weight:550;display:inline-flex;align-items:center;gap:8px;padding:7px 8px 7px 13px;border-radius:999px;border:1px solid var(--line);background:var(--surface);color:var(--ink);cursor:pointer}
.filters button:hover{border-color:var(--accent)}
.filters button[aria-pressed="true"]{background:var(--ink);color:var(--bg);border-color:var(--ink)}
.count{font-size:.74rem;font-variant-numeric:tabular-nums;color:var(--muted);background:var(--surface-2);border-radius:999px;padding:1px 8px;min-width:24px;text-align:center}
.filters button[aria-pressed="true"] .count{background:color-mix(in srgb,var(--bg) 18%,transparent);color:inherit}
.section{margin-top:44px}
.section h2{font-size:1.02rem;font-weight:720;letter-spacing:-.01em;margin:0 0 16px;display:flex;align-items:center;gap:12px}
.section h2::after{content:"";flex:1;height:1px;background:var(--line)}
.hero{display:grid;grid-template-columns:minmax(0,1.25fr) minmax(0,1fr);background:var(--surface);border:1px solid var(--line);border-radius:22px;overflow:hidden;box-shadow:var(--shadow)}
.hero-media{display:block;background:var(--surface-2)}
.hero-media img{width:100%;height:100%;aspect-ratio:16/10;object-fit:cover}
.hero-body{padding:clamp(22px,3vw,38px);display:flex;flex-direction:column;gap:14px;justify-content:center}
.hero-body h2{font-size:clamp(1.6rem,2.8vw,2.3rem);line-height:1.12;letter-spacing:-.025em;margin:0;font-weight:760}
.hero-body h2 a{color:var(--ink);text-decoration:none}
.hero-body h2 a:hover,.hero-body h2 a:focus-visible{text-decoration:underline;text-underline-offset:4px}
.btn{display:inline-flex;align-items:center;gap:6px;align-self:flex-start;background:var(--ink);color:var(--bg);text-decoration:none;font-weight:600;font-size:.9rem;padding:9px 16px;border-radius:999px}
.btn:hover{opacity:.88}
.grid{display:grid;gap:18px;grid-template-columns:repeat(auto-fill,minmax(270px,1fr))}
.card{position:relative;background:var(--surface);border:1px solid var(--line);border-radius:var(--r);overflow:hidden;display:flex;flex-direction:column;transition:transform .18s ease,border-color .18s ease,box-shadow .18s ease}
.card:hover{transform:translateY(-2px);border-color:color-mix(in srgb,var(--accent) 45%,var(--line));box-shadow:var(--shadow)}
.card.prio-Critical{border-top:3px solid var(--crit)}
.card.prio-High{border-top:3px solid var(--high)}
.card-media{position:relative;display:block;background:var(--surface-2)}
.card-media img{width:100%;aspect-ratio:16/9;object-fit:cover}
.card-media .badge{position:absolute;left:12px;top:12px}
.card-body{padding:16px 18px 18px;display:flex;flex-direction:column;gap:8px;flex:1}
.card h3{font-size:1.05rem;line-height:1.3;letter-spacing:-.01em;margin:0;font-weight:700}
.card h3 a{color:var(--ink);text-decoration:none}
.card h3 a:hover,.card h3 a:focus-visible{text-decoration:underline;text-underline-offset:3px}
.summary{margin:0;color:var(--muted);font-size:.92rem;display:-webkit-box;-webkit-line-clamp:3;-webkit-box-orient:vertical;overflow:hidden}
.meta{margin:0;color:var(--muted);font-size:.82rem}
.kicker{margin:0;font-size:.78rem;color:var(--muted);display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.kicker .cat{font-weight:600;color:var(--ink)}
.card-kicker{margin:0;font-size:.78rem;color:var(--muted);font-weight:600}
.badge{display:inline-flex;align-items:center;font-size:.66rem;font-weight:760;text-transform:uppercase;letter-spacing:.07em;padding:4px 9px;border-radius:999px;background:var(--surface);color:var(--std);box-shadow:0 1px 3px rgba(0,0,0,.18)}
.badge.Critical{color:var(--crit)}
.badge.High{color:var(--high)}
.note{background:var(--surface-2);color:var(--muted);border-radius:12px;padding:12px 16px;font-size:.9rem}
.box{background:var(--surface);border:1px solid var(--line);border-radius:var(--r);padding:16px 20px}
.empty{background:var(--surface);border:1px dashed var(--line);border-radius:var(--r);padding:24px;color:var(--muted)}
.prose{max-width:780px;margin:0 auto}
.prose h2{font-size:1.12rem;letter-spacing:-.01em;margin:2.2rem 0 .7rem}
.prose figure{margin:24px 0}
.prose figure img{width:100%;aspect-ratio:16/9;object-fit:cover;border-radius:var(--r);background:var(--surface-2)}
figcaption{font-size:.8rem;color:var(--muted);margin-top:8px}
.prose ul{padding-left:1.2rem}
.site-footer{border-top:1px solid var(--line);color:var(--muted);font-size:.84rem;padding:28px 0}
:focus-visible{outline:2px solid var(--accent);outline-offset:3px}
@media (max-width:900px){
  .hero{grid-template-columns:1fr}
  .stats{grid-template-columns:repeat(2,minmax(0,1fr))}
}
@media (max-width:640px){
  .bar{flex-wrap:wrap;padding:10px 0;row-gap:8px}
  .nav{order:3;flex-basis:100%}
  .grid{grid-template-columns:1fr}
}
@media (prefers-reduced-motion:reduce){*{transition:none!important;scroll-behavior:auto!important}.card:hover{transform:none}}
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


def _layout(cfg: dict, title: str, desc: str, body: str, base: str, image: str | None = None) -> str:
    site = esc(cfg["site_name"])
    links = [f'<a href="{base}index.html#{cid}">{esc(SHORT_NAV[cid])}</a>'
             for cid in CATEGORY_ORDER if cid != "general"]
    links.append(f'<a href="{base}briefings/index.html">Briefings</a>')
    links.append(f'<a href="{base}patch-tuesday/index.html">Patch Tuesday</a>')
    links.insert(0, f'<a href="{base}today/index.html">Today</a>')
    links.insert(1, f'<a href="{base}saved/index.html">Saved</a>')
    nav = "".join(links)
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title)} | {site}</title>
<meta name="description" content="{esc(desc)}">
{_og_tags(cfg, title, desc, image)}
<script>{THEME_JS}</script>
<link rel="stylesheet" href="{base}style.css">
<link rel="alternate" type="application/rss+xml" title="{site}" href="{esc(cfg['site_url'])}/feed.xml">
</head>
<body>
<a class="skip" href="#main">Skip to content</a>
<header class="site-header"><div class="wrap bar">
<a class="brand" href="{base}index.html"><span class="mark" aria-hidden="true"></span>{site}</a>
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


def search_text(s: dict) -> str:
    return " ".join([s["title"], s["summary"], " ".join(s.get("vendors", [])), CATEGORIES[s["category"]][0]]).lower()


def _save_button(s: dict) -> str:
    return f'<button type="button" class="save" data-save="{esc(s["id"])}" aria-pressed="false">Save</button>'


def _card(s: dict) -> str:
    img = s["image"] or fallback_cover(s)
    names = ", ".join(dict.fromkeys(x["name"] for x in s["sources"]))
    prio = esc(s["priority"])
    return f"""<article class="card prio-{prio}" data-tags="{esc(' '.join(s['tags']))}" data-search="{esc(search_text(s))}">
<a class="card-media" href="story/{esc(s['id'])}.html" tabindex="-1" aria-hidden="true"><img src="{esc(img)}" alt="" loading="lazy" decoding="async" referrerpolicy="no-referrer" width="640" height="360"><span class="badge {prio}">{prio}</span></a>
<div class="card-body">
<p class="kicker"><span class="cat">{esc(CATEGORIES[s['category']][0])}</span></p>
<h3><a href="story/{esc(s['id'])}.html">{esc(s['title'])}</a></h3>
<p class="summary">{esc(_short(s['summary'], 170))}</p>
<p class="meta">{esc(names)} &middot; {esc(fmt_date(s['published']))}</p>
{_save_button(s)}
</div>
</article>"""


def _hero(s: dict) -> str:
    img = s["image"] or fallback_cover(s)
    names = ", ".join(dict.fromkeys(x["name"] for x in s["sources"]))
    prio = esc(s["priority"])
    return f"""<section class="hero" aria-labelledby="hero-title" data-tags="{esc(' '.join(s['tags']))}" data-search="{esc(search_text(s))}">
<a class="hero-media" href="story/{esc(s['id'])}.html" tabindex="-1" aria-hidden="true"><img src="{esc(img)}" alt="" loading="eager" referrerpolicy="no-referrer" width="640" height="360"></a>
<div class="hero-body">
<p class="kicker"><span class="badge {prio}">{prio}</span><span class="cat">{esc(CATEGORIES[s['category']][0])}</span></p>
<h2 id="hero-title"><a href="story/{esc(s['id'])}.html">{esc(s['title'])}</a></h2>
<p class="summary">{esc(_short(s['summary'], 240))}</p>
<p class="meta">{esc(names)} &middot; {esc(fmt_date(s['published']))}</p>
<div class="actions"><a class="btn" href="story/{esc(s['id'])}.html">Read the brief &rarr;</a>{_save_button(s)}</div>
</div>
</section>"""


EXTRA_CSS = """
.lede{font-size:1.15rem;color:var(--muted);margin:0 0 1.2rem}
.subscribe{margin:40px 0 0;background:var(--surface);border:1px solid var(--line);border-radius:var(--r);padding:24px}
.subscribe h2{font-size:1.2rem;margin:0 0 6px}
.subscribe-form{display:flex;gap:8px;flex-wrap:wrap;margin:14px 0 8px}
.subscribe-form input{flex:1 1 220px;min-width:0;padding:10px 12px;border:1px solid var(--line);border-radius:10px;font:inherit;background:var(--bg);color:var(--ink)}
.subscribe-form button{padding:10px 18px;border:0;border-radius:10px;background:var(--ink);color:var(--bg);font:inherit;font-weight:600;cursor:pointer}
.subscribe-form button:hover{opacity:.88}
.visually-hidden{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
.analysis-links{margin:14px 0 0}
[hidden]{display:none!important}
.toolbar{margin:0 0 12px}
.search{width:100%;font:inherit;font-size:.95rem;padding:11px 14px;border-radius:12px;border:1px solid var(--line);background:var(--surface);color:var(--ink)}
.search:focus{border-color:var(--accent)}
.actions{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-top:4px}
.save{align-self:flex-start;font:inherit;font-size:.8rem;font-weight:600;background:transparent;border:1px solid var(--line);color:var(--muted);border-radius:999px;padding:5px 12px;cursor:pointer}
.save:hover{color:var(--ink);border-color:var(--ink)}
.save[aria-pressed="true"]{color:var(--accent);border-color:var(--accent)}
.card-body .save{margin-top:4px}
.todo-list{display:grid;gap:14px}
.todo{background:var(--surface);border:1px solid var(--line);border-left:4px solid var(--std);border-radius:var(--r);padding:18px 20px}
.todo.kind-patch{border-left-color:var(--crit)}
.todo.kind-investigate{border-left-color:var(--high)}
.todo.kind-review{border-left-color:var(--accent)}
.todo h2{font-size:1.1rem;line-height:1.3;margin:8px 0 8px;font-weight:700;letter-spacing:-.01em}
.todo h2 a{color:var(--ink);text-decoration:none}
.todo h2 a:hover,.todo h2 a:focus-visible{text-decoration:underline;text-underline-offset:3px}
.todo-action{margin:0 0 8px;font-size:.95rem}
.todo-kind{display:inline-block;font-size:.7rem;font-weight:760;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);margin-right:6px}
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
        "<h2>Merkliste</h2>"
        "<p>Gespeicherte Meldungen (Merkliste) werden nur lokal in Ihrem Browser gespeichert (Local Storage). "
        "Sie werden nicht an uns oder einen Dienst übertragen. Das Löschen der Browserdaten entfernt die Liste.</p>"
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
def filter_bar(stories: list[dict]) -> str:
    buttons = []
    for key, label in FILTERS:
        n = len(stories) if key == "all" else sum(1 for s in stories if key in s["tags"])
        pressed = "true" if key == "all" else "false"
        buttons.append(f'<button type="button" data-filter="{key}" aria-pressed="{pressed}">{esc(label)} <span class="count">{n}</span></button>')
    search = ('<div class="toolbar"><label class="visually-hidden" for="story-search">Search stories</label>'
              '<input id="story-search" class="search" type="search" placeholder="Search title, vendor or topic" autocomplete="off"></div>')
    return (search + '<div class="filters" id="filters" role="group" aria-label="Filter stories by topic">'
            + "".join(buttons) + '</div><p id="filter-empty" class="empty" hidden>No stories match this filter in the current window.</p>')


FILTER_JS = """(function(){
var bar=document.getElementById('filters');
var search=document.getElementById('story-search');
var buttons=bar?bar.querySelectorAll('button[data-filter]'):[];
var items=document.querySelectorAll('[data-tags]');
var sections=document.querySelectorAll('[data-section]');
var empty=document.getElementById('filter-empty');
var current='all';
function apply(){
  var q=(search?search.value:'').trim().toLowerCase();
  var shown=0;
  items.forEach(function(el){
    var tags=' '+(el.getAttribute('data-tags')||'')+' ';
    var text=el.getAttribute('data-search')||'';
    var ok=(current==='all'||tags.indexOf(' '+current+' ')>-1)&&(!q||text.indexOf(q)>-1);
    el.hidden=!ok; if(ok){shown++;}
  });
  sections.forEach(function(sec){sec.hidden=!sec.querySelector('[data-tags]:not([hidden])');});
  if(empty){empty.hidden=shown>0;}
}
buttons.forEach(function(b){b.addEventListener('click',function(){
  current=b.getAttribute('data-filter');
  buttons.forEach(function(x){x.setAttribute('aria-pressed',String(x===b));});
  apply();
});});
if(search){search.addEventListener('input',apply);}
var KEY='sb-saved';
function readSaved(){try{return JSON.parse(localStorage.getItem(KEY)||'[]');}catch(e){return [];}}
function writeSaved(a){try{localStorage.setItem(KEY,JSON.stringify(a));}catch(e){}}
var saves=document.querySelectorAll('button[data-save]');
function paint(){var saved=readSaved();saves.forEach(function(b){
  var on=saved.indexOf(b.getAttribute('data-save'))>-1;
  b.setAttribute('aria-pressed',String(on));b.textContent=on?'Saved':'Save';});}
saves.forEach(function(b){b.addEventListener('click',function(){
  var id=b.getAttribute('data-save');var a=readSaved();var i=a.indexOf(id);
  if(i>-1){a.splice(i,1);}else{a.push(id);}
  writeSaved(a);paint();
});});
paint();
apply();
})();"""


ACTION_RANK = {"patch": 0, "investigate": 1, "review": 2, "monitor": 3}
ACTION_LABEL = {"patch": "Patch now", "investigate": "Investigate", "review": "Review", "monitor": "Monitor"}


def affected(s: dict) -> tuple[str, str]:
    """(label, target phrase for the suggestion, whether a named product was found)."""
    if s.get("vendors"):
        return s["vendors"][0], s["vendors"][0] + " products", True
    tags = set(s["tags"])
    for tag, name in (("m365", "Microsoft 365"), ("entra", "Entra ID"), ("defender", "Microsoft Defender")):
        if tag in tags:
            return name, name, True
    return CATEGORIES[s["category"]][0], "your environment", False


def suggest_action(s: dict) -> dict:
    """Rule-based suggestion. Each rule reads a visible signal (KEV list, exploitation wording, product tags).
    The text is a starting point for the reader, not a verified recommendation."""
    tags = set(s["tags"])
    label, target, named = affected(s)
    check = f"Check whether {target} is affected."
    if s.get("kev"):
        kind, text = "patch", (f"This CVE is in CISA's Known Exploited Vulnerabilities catalog. {check} "
                               "Apply the vendor fix from the original advisory.")
    elif "patch-now" in tags:
        kind, text = "patch", (f"Exploitation is reported and a CVE is named. {check} "
                               "Apply the vendor fix from the original advisory.")
    elif "exploited" in tags:
        kind, text = "investigate", (f"Attacks are reported. {check} "
                                     "Compare your logs and detections with the indicators in the original report.")
    elif tags & {"m365", "entra", "defender"}:
        kind, text = "review", f"{check} Use the original report as the reference for configuration and logs."
    else:
        kind, text = "monitor", "No immediate action identified in the source reports. Keep for awareness."
    return {"kind": kind, "label": ACTION_LABEL[kind], "text": text, "product": label, "named": named}


def today_page(stories: list[dict], cfg: dict, now: datetime, limit: int = 5) -> str:
    ranked = sorted(stories, key=lambda s: (ACTION_RANK[suggest_action(s)["kind"]], -s["score"]))[:limit]
    rows = []
    for s in ranked:
        a = suggest_action(s)
        src = s["sources"][0]
        prio = esc(s["priority"])
        rows.append(
            f'<article class="todo kind-{a["kind"]}">'
            f'<p class="kicker"><span class="badge {prio}">{prio}</span><span class="cat">{esc(CATEGORIES[s["category"]][0])}</span></p>'
            f'<h2><a href="../story/{esc(s["id"])}.html">{esc(s["title"])}</a></h2>'
            f'<p class="todo-action"><span class="todo-kind">{esc(a["label"])}</span> {esc(a["text"])}</p>'
            f'<p class="meta">{"Affected" if a["named"] else "Area"}: {esc(a["product"])} &middot; Source: '
            f'<a href="{esc(src["url"])}" rel="nofollow noopener noreferrer" target="_blank">{esc(src["name"])}</a>'
            f' &middot; {esc(fmt_date(src["published"]))}</p>'
            "</article>"
        )
    body = (
        '<section class="intro"><h1>Today: what to do</h1>'
        f'<p class="meta">Last content update: {esc(now.strftime("%d %b %Y, %H:%M UTC"))}. '
        "The top five stories by action need, then by score. Suggestions come from simple rules on the headline and "
        "source text, not from a person. Check the original advisory before you act.</p></section>"
        + ('<div class="todo-list">' + "".join(rows) + "</div>" if rows else
           '<div class="empty">No stories in the current window.</div>')
    )
    return _layout(cfg, "Today: what to do", "The five stories that need action today, with sources.", body, "../")


def _og_tags(cfg: dict, title: str, desc: str, image: str | None) -> str:
    site = esc(cfg["site_name"])
    tags = [
        f'<meta property="og:site_name" content="{site}">',
        '<meta property="og:type" content="website">',
        f'<meta property="og:title" content="{esc(title)}">',
        f'<meta property="og:description" content="{esc(desc)}">',
    ]
    if image and image.startswith("https://"):
        tags.append(f'<meta property="og:image" content="{esc(image)}">')
        tags.append('<meta name="twitter:card" content="summary_large_image">')
    else:
        tags.append('<meta name="twitter:card" content="summary">')
    return "\n".join(tags)


SAVED_JS = """(function(){
var KEY='sb-saved';
var list=document.getElementById('saved-list');
var empty=document.getElementById('saved-empty');
var note=document.getElementById('saved-note');
var saved=[];
try{saved=JSON.parse(localStorage.getItem(KEY)||'[]');}catch(e){saved=[];}
function save(a){try{localStorage.setItem(KEY,JSON.stringify(a));}catch(e){}}
function el(tag,cls,text){var n=document.createElement(tag);if(cls){n.className=cls;}if(text!==undefined){n.textContent=text;}return n;}
fetch('../stories.json',{cache:'no-store'}).then(function(r){return r.json();}).then(function(data){
  var byId={};(data.stories||[]).forEach(function(s){byId[s.id]=s;});
  var found=saved.filter(function(id){return !!byId[id];});
  var missing=saved.length-found.length;
  if(!found.length){empty.hidden=false;}
  found.forEach(function(id){
    var s=byId[id];
    var card=el('article','card prio-'+s.priority);
    var body=el('div','card-body');
    var kick=el('p','kicker');kick.appendChild(el('span','badge '+s.priority,s.priority));kick.appendChild(el('span','cat',s.category));
    var h=el('h3');var a=el('a','',s.title);a.href='../'+s.url;h.appendChild(a);
    var sum=el('p','summary',s.summary);
    var meta=el('p','meta',s.sources+' \u00b7 '+s.date);
    var rm=el('button','save','Remove');rm.type='button';rm.setAttribute('aria-pressed','true');
    rm.addEventListener('click',function(){
      saved=saved.filter(function(x){return x!==id;});save(saved);card.remove();
      if(!list.children.length){empty.hidden=false;}
    });
    body.appendChild(kick);body.appendChild(h);body.appendChild(sum);body.appendChild(meta);body.appendChild(rm);
    card.appendChild(body);list.appendChild(card);
  });
  if(missing>0){note.hidden=false;note.textContent=missing+(missing===1?' saved story is':' saved stories are')+' no longer in the current window, so they are not shown. Saved items are kept in this browser only.';}
}).catch(function(){
  note.hidden=false;note.textContent='The story index could not be loaded. Please try again later.';
});
})();"""


def saved_page(cfg: dict) -> str:
    body = (
        '<section class="intro"><h1>Saved stories</h1>'
        '<p class="meta">Saved in this browser only. Nothing is sent to us. '
        "Stories leave the current window after about a week, and then they are no longer listed here.</p></section>"
        '<p id="saved-note" class="note" hidden></p>'
        '<div class="grid" id="saved-list"></div>'
        '<p id="saved-empty" class="empty" hidden>Nothing saved yet. Use <strong>Save</strong> on a story to keep it here.</p>'
        f"<script>{SAVED_JS}</script>"
    )
    return _layout(cfg, "Saved stories", "Stories you saved in this browser.", body, "../")


def stories_index(stories: list[dict]) -> str:
    rows = [{
        "id": s["id"], "title": s["title"], "summary": _short(s["summary"], 170), "priority": s["priority"],
        "category": CATEGORIES[s["category"]][0], "date": fmt_date(s["published"]),
        "sources": ", ".join(dict.fromkeys(x["name"] for x in s["sources"])), "url": f"story/{s['id']}.html",
    } for s in stories]
    return json.dumps({"stories": rows}, ensure_ascii=False, indent=1)


def index_page(stories: list[dict], cfg: dict, now: datetime, status: dict,
               articles: list[dict] | None = None, site_cfg: dict | None = None) -> str:
    articles = articles or []
    site_cfg = site_cfg or {}
    crit = sum(1 for s in stories if s["priority"] == "Critical")
    exploited = sum(1 for s in stories if "exploited" in s["tags"])
    parts = [
        '<section class="intro"><h1>Security news, ranked</h1>'
        f'<p class="meta">Last content update: {esc(now.strftime("%d %b %Y, %H:%M UTC"))} &middot; '
        "Checked automatically every 20 minutes. Every story links to its original source.</p>"
        '<p><a class="btn" href="today/index.html">Today: what to do &rarr;</a></p></section>',
        '<div class="stats" aria-label="Summary">'
        f'<div class="stat"><b>{len(stories)}</b><span>stories in the current window</span></div>'
        f'<div class="stat crit"><b>{crit}</b><span>critical</span></div>'
        f'<div class="stat"><b>{exploited}</b><span>actively exploited</span></div>'
        f'<div class="stat"><b>{status["sources_ok"]}/{status["sources_total"]}</b><span>sources reachable</span></div>'
        "</div>",
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
        parts.append(filter_bar(stories))
        featured = stories[:4]
        parts.append('<section class="section" aria-label="Top story" data-section>' + _hero(featured[0]) + "</section>")
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
        credit = f"Image: {s['image_source']}. Credit remains with the original publisher."
    else:
        img = fallback_cover(s)
        credit = "Illustration: no preview image was available for this story."
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
    return _layout(cfg, s["title"], desc, f'<article class="prose">{body}</article>', "../", image=s["image"])


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
    (out / "today").mkdir(parents=True, exist_ok=True)
    (out / "today" / "index.html").write_text(today_page(stories, cfg, now), encoding="utf-8")
    (out / "saved").mkdir(parents=True, exist_ok=True)
    (out / "saved" / "index.html").write_text(saved_page(cfg), encoding="utf-8")
    (out / "stories.json").write_text(stories_index(stories), encoding="utf-8")
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
    if fixtures is None:  # live runs only; offline tests never touch the network
        enrich_images(items)
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
        "render": "5.5",  # bump when the HTML/CSS/JS output changes, so the site rebuilds
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
