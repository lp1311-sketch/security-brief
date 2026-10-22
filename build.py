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
import textwrap
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
# Exploitation CLAIMS only. Generic words like "zero-day" or "in the wild" describe disclosure or context,
# not proof of exploitation, so they no longer trigger this signal on their own.
EXPLOITED_RE = re.compile(r"actively exploited|exploited in the wild|exploited in attacks|in active exploitation|"
                          r"exploitation (?:in the wild|detected|observed|reported|attempts)|being exploited|under active attack", re.I)

# Category id -> (label, first-match regex). Checked in CATEGORY_ORDER.
CATEGORIES = {
    "threats": ("Attacks & Breaches", r"ransomware|malware|breach|phishing|stealer|botnet|extortion|data leak|spyware|hijack|backdoor|scam|theft|cyberattack|cyber attack|shellcode|loader|supply[- ]chain|tampered|money laundering|sanction|proxyjack|attackers|hackers"),
    "vulnerabilities": ("Patch Radar", r"vulnerab|\bcve-|patch|exploit|flaw|\brce\b|zero-day|0-day|security update"),
    "ai": ("AI Risk Lab", r"\bai\b|\bllm|copilot|chatgpt|openai|anthropic|gemini|deepfake|generative|ai agent|ai model"),
    "microsoft": ("Microsoft", r"microsoft|windows|exchange|sharepoint|teams|office 365|m365|outlook|defender|azure|entra|azure ad|conditional access|\bmfa\b|tenant|identity|sign-in|oauth"),
    "general": ("Industry & Research", r"$^"),  # fallback for stories without a clear category
}
CATEGORY_ORDER = ["threats", "vulnerabilities", "ai", "microsoft", "general"]  # rendering order
# Scoring order: ties go to the first entry (AI before vulnerabilities before threats).
SCORE_ORDER = ["ai", "vulnerabilities", "threats", "microsoft"]

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


WHY_RULES = [
    # (regex on title+summary, sentence). Each sentence is tied to a concrete signal in the feed text.
    (r"\b(personal|customer|employee|patient)\b.*\b(data|information|records?)\b|\brecords\b.*\b(exposed|stolen|leak)",
     "Personal data is involved. If you hold data from this organization, or a supplier of yours is affected, "
     "check whether a GDPR breach notification (Art. 33, within 72 hours of becoming aware) could apply, and involve your DPO."),
    (r"\b(ransom\w*|extort\w*)\b",
     "Ransomware intrusions commonly start with stolen credentials, exposed remote-access services or phishing. "
     "Look for new admin accounts, unusual logons and mass file changes in the affected period."),
    (r"\b(npm|pypi|package|plugin|extension|download|supply[- ]chain|backdoor)\w*",
     "A compromised package or download runs with the rights of whoever installs it. "
     "Check whether you use the named package or version, and review installation and endpoint logs."),
    (r"\b(oauth|consent|token|session cookie|app registration|service principal)\b",
     "Token and consent abuse can work without any malware. In Entra ID, review sign-in logs and enterprise applications "
     "for unexpected consent grants, new app registrations or new credentials."),
    (r"\b(api keys?|secrets?|credentials?|passwords?)\b",
     "Exposed keys or passwords stay valid until rotated. Rotate the affected keys and check their usage logs for unexpected calls."),
    (r"\b(web ?shells?|remote code execution|rce)\b",
     "A web shell or code-execution flaw gives an attacker control of the server. "
     "Check web server logs and the server for unknown files or processes."),
]


def why_it_matters(s: dict) -> str:
    """Story-specific reasoning, built only from signals in the feed text and the rule tags.
    Falls back to the category sentence when no signal matches."""
    text = f"{s.get('title', '')} {s.get('summary', '')}".lower()
    sentences = []
    if s.get("kev"):
        sentences.append("The CVE is listed in CISA's Known Exploited Vulnerabilities catalog, so exploitation is confirmed.")
    elif "exploited" in s.get("tags", []):
        sentences.append("The report describes active exploitation, so waiting for the next regular cycle carries risk.")
    if s.get("cves"):
        sentences.append(f"It concerns {', '.join(s['cves'][:3])}: compare the affected versions in the advisory with your inventory.")
    for pattern, sentence in WHY_RULES:
        if re.search(pattern, text):
            sentences.append(sentence)
        if len(sentences) >= 3:
            break
    if not sentences:
        return WHY[s.get("category", "general")]
    return " ".join(sentences[:3])


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


STOP_WORDS = {"the", "and", "for", "with", "from", "that", "this", "new", "after", "over", "into", "using",
              "how", "why", "what", "your", "their", "are", "was", "has", "have", "exploit", "attack", "attacks",
              "flaw", "flaws", "bug", "bugs", "hackers", "hacker", "security", "update", "updates"}


def cover_keyword(s: dict) -> str:
    """Pick the most useful short label for a cover: CVE ID, vendor, or the most specific title word."""
    cve = re.search(r"CVE-\d{4}-\d{4,7}", s.get("title", ""), re.I)
    if cve:
        return cve.group(0).upper()
    if s.get("vendors"):
        return s["vendors"][0]
    words = [w for w in re.findall(r"[A-Za-z][A-Za-z0-9+-]{3,}", s.get("title", ""))
             if w.lower() not in STOP_WORDS]
    return max(words, key=len) if words else CATEGORIES[s["category"]][0]


def fallback_cover(s: dict) -> str:
    """Branded placeholder for stories without a usable preview image. Built from the story's own data."""
    cat = CATEGORIES[s["category"]][0]
    accent = {"Critical": "#ff5c5c", "High": "#fbbf24"}.get(s["priority"], "#5eead4")
    top, main = cat.upper(), cover_keyword(s)
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
    "briefings": "Security Analysis",
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


def _article_candidates(content_dir: Path):
    """Yield (section_hint, path). Folder files use their folder as the section.
    Flat files in the repository root (uploaded without folders) use the front matter
    'section:' key, and default to briefings when that key is missing."""
    for sec in SECTIONS:
        d = content_dir / sec
        if d.is_dir():
            for f in sorted(d.glob("*.md")):
                yield sec, f
    for f in sorted(content_dir.parent.glob("*.md")):
        if f.name.startswith("_") or f.name.lower().startswith("readme"):
            continue
        yield None, f


def load_articles(content_dir: Path, warnings: list[str]) -> list[dict]:
    arts: list[dict] = []
    for sec_hint, f in _article_candidates(content_dir):
        if True:
            if f.name.startswith("_"):
                continue  # templates
            meta, body = parse_front_matter(f.read_text(encoding="utf-8"))
            sec = sec_hint or str(meta.get("section", "")).strip()
            if not sec:
                sec = "patch-tuesday" if "patch-tuesday" in f.stem else "briefings"
            if sec not in SECTIONS:
                warnings.append(f"{f.name}: unknown section '{sec}', article skipped")
                continue
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


PAGE_BUDGET = 20  # article pages read per run for instructions (each item once)
SCRIPT_RE = re.compile(r"<(script|style|nav|footer|header|form)\b.*?</\1\s*>", re.I | re.S)
BLOCK_RE = re.compile(r"<(p|li)\b[^>]*>(.*?)</\1\s*>", re.I | re.S)
INSTR_ACTION_RE = re.compile(
    r"\b(update|upgrade|patch|apply|install|disable|enable|block|restrict|rotate|reset|revoke|mitigat\w*|"
    r"workaround|recommend\w*|advis\w*|should|must|turn off|remove|enforce|configure|migrate|uninstall)\b", re.I)
INSTR_STRONG_RE = re.compile(
    r"\b(recommend\w*|advis\w*|must|should|apply|workaround|mitigation|upgrade to|update to|KB\d{6,7}|version \d)", re.I)
INSTR_SKIP_RE = re.compile(
    r"subscribe|newsletter|cookie|sign up|follow us|advertis|sponsor|read more|related|share this|copyright|"
    r"all rights reserved|click here", re.I)


def fetch_page(url: str, timeout: int = 10) -> str:
    """Article HTML for instruction extraction. A failed page is simply empty, never an error."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "text/html"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read(300_000).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return ""


def extract_instructions(page: str, limit: int = 4) -> list[str]:
    """Sentences from the article body that tell the reader what to do. Quoted verbatim, rule-based.
    Sentences with more strong signals (recommend, must, KB numbers, versions) come first."""
    body = _strip_aside(SCRIPT_RE.sub(" ", page or ""))
    found: list[tuple[int, int, str]] = []
    order = 0
    for m in BLOCK_RE.finditer(body):
        for sent in re.split(r"(?<=[.!?])\s+(?=[A-Z0-9\"'(])", _clean(m.group(2))):
            sent = sent.strip()
            if not 60 <= len(sent) <= 320:
                continue
            if not INSTR_ACTION_RE.search(sent) or INSTR_SKIP_RE.search(sent):
                continue
            found.append((len(INSTR_STRONG_RE.findall(sent)), order, sent))
            order += 1
    found.sort(key=lambda f: (-f[0], f[1]))
    out: list[str] = []
    seen: set[str] = set()
    for _, _, sent in found:
        if sent.lower() in seen:
            continue
        seen.add(sent.lower())
        out.append(sent)
        if len(out) == limit:
            break
    return out


def enrich_instructions(items: list[dict], budget: int = PAGE_BUDGET) -> None:
    """Read each new article once and keep its real instructions. Newest first."""
    for it in sorted(items, key=lambda i: i.get("published") or "", reverse=True):
        if budget <= 0:
            break
        if it.get("instructions_checked"):
            continue
        it["instructions"] = extract_instructions(fetch_page(it["link"]))
        it["instructions_checked"] = True
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


ASIDE_RE = re.compile(r"<aside\b[^>]*>.*?</aside>", re.I | re.S)


def _strip_aside(raw_html: str) -> str:
    """Drop table-of-contents <aside> blocks that some feeds put inside the article body."""
    return ASIDE_RE.sub(" ", raw_html or "")


SECURITY_RE = re.compile(r"secur|vulnerab|patch|exploit|malware|phish|attack|breach|threat|ransom|identity|\\bmfa\\b|cve|zero-day|attacker|incident|compromis|defen[cs]e|token|credential|botnet|backdoor", re.I)


def is_security_item(item: dict) -> bool:
    return bool(SECURITY_RE.search(f"{item.get('title', '')} {item.get('summary', '')}"))


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

        # Microsoft Security Blog starts content:encoded with a table-of-contents <aside>.
        # Remove those blocks before choosing the summary, image and CVE ids.
        cleaned = {n: _strip_aside(raw(n)) for n in ("encoded", "description", "summary", "content")}
        body_raw = next((cleaned[n] for n in ("encoded", "description", "summary", "content") if cleaned[n].strip()), "")
        all_raw = " ".join(cleaned.values())

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
            m = IMG_RE.search(all_raw)
            if m:
                image = https_image(m.group(1))

        date = _date(raw("pubdate") or raw("published") or raw("updated") or raw("date"))
        summary = _short(clean_excerpt(_clean(body_raw)), 320)
        cves = sorted({c.upper() for c in CVE_RE.findall(f"{title} {all_raw}")})

        out.append({
            "id": hashlib.sha1(link.encode()).hexdigest()[:12],
            "source": src["id"],
            "source_name": src["name"],
            "official": bool(src.get("official")),
            "source_type": src.get("type", "advisory" if src.get("official") else "news"),
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
    # Vendor blogs are never treated as official advisories, even if flagged, so they cannot trigger Critical by themselves.
    official = any(i["official"] and i.get("source_type") != "vendor_blog" for i in items)
    # Critical via exploitation needs the claim in an OFFICIAL item itself, not anywhere in a clustered story.
    official_exploit = official and any(i["official"] and i.get("source_type") != "vendor_blog" and EXPLOITED_RE.search(f"{i['title']} {i['summary']}") for i in items)
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
    if kev_hit or official_exploit:
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
    if category == "microsoft" or re.search(CATEGORIES["microsoft"][1], text, re.I):
        tags.append("microsoft")
    if DEFENDER_RE.search(text):
        tags.append("defender")
    if category == "ai":
        tags.append("ai")
    return tags


def content_type_of(items: list[dict]) -> str:
    """Label for a story: Advisory if any advisory source, Vendor blog if only vendor blogs, else News."""
    types = {i.get("source_type", "news") for i in items}
    if "advisory" in types:
        return "Advisory"
    if types == {"vendor_blog"}:
        return "Vendor blog"
    return "News"


def source_health_note(status: dict) -> str:
    """Plain-language line for the homepage. Empty when every source worked."""
    failed = [s["name"] for s in status.get("sources", []) if not s.get("ok")]
    if not failed:
        return ""
    names = ", ".join(failed)
    return (f"{len(failed)} source(s) did not update in the last run: {names}. "
            "Stories from them may be missing. See status.json for details.")


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
    official_exploit_sources = sorted({
        i["source_name"] for i in items
        if i.get("official") and i.get("source_type") != "vendor_blog"
        and EXPLOITED_RE.search(f"{i['title']} {i['summary']}")
    })
    priority_basis = []
    if kev_hit:
        priority_basis.append("CISA KEV listing: " + ", ".join(sorted(set(cves) & kev)))
    if official_exploit_sources:
        priority_basis.append("Official source reports exploitation: " + ", ".join(official_exploit_sources))
    if prio == "High":
        priority_basis.append(f"Editorial attention score {score} reached the High threshold (not CVSS)")
    if prio == "Standard":
        if kev_checked:
            priority_basis.append("No KEV or official-exploitation trigger; editorial score below High threshold")
        else:
            priority_basis.append("No official-exploitation trigger; KEV lookup unavailable, so this label is provisional")
    return {
        "id": head["id"],
        "title": head["title"],
        "summary": head["summary"],
        "published": head["published"],
        "category": category,
        "content_type": content_type_of(items),
        "tags": tags,
        "priority": prio,
        "score": score,
        "reasons": reasons,
        "priority_basis": priority_basis,
        "cves": cves,
        "vendors": sorted(set().union(*(vendors_in(f"{i['title']} {i['summary']}") for i in items))),
        "kev": sorted(set(cves) & kev) if kev_checked else [],
        "kev_checked": kev_checked,
        "image": with_img["image"] if with_img else None,
        "image_source": with_img["source_name"] if with_img else None,
        "instructions": _story_instructions(items),
        "sources": [
            {"name": i["source_name"], "title": i["title"], "url": i["link"], "published": i["published"]}
            for i in items
        ],
    }


def _story_instructions(items: list[dict]) -> list[dict]:
    src = next((i for i in items if i.get("instructions")), None)
    if not src:
        return []
    return [{"text": t, "source": src["source_name"], "url": src["link"]} for t in src["instructions"]]


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
.resource-card{max-width:780px;border-left:3px solid var(--accent)}
.resource-card .card-body{padding:22px}
.resource-card .summary{-webkit-line-clamp:unset;max-width:680px}
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
.notice{border-left:3px solid var(--high);padding:10px 14px;margin:0 0 24px;background:var(--surface);border-radius:var(--r)}
.type{color:var(--muted);font-weight:550}
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
  .cve-table th:nth-child(5),.cve-table td:nth-child(5),.cve-table th:nth-child(6),.cve-table td:nth-child(6){display:none}
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
             "microsoft": "Microsoft"}


def _layout(cfg: dict, title: str, desc: str, body: str, base: str, image: str | None = None) -> str:
    site = esc(cfg["site_name"])
    year = datetime.now(timezone.utc).year
    links = [f'<a href="{base}category/{cid}/index.html">{esc(SHORT_NAV[cid])}</a>'
             for cid in CATEGORY_ORDER if cid != "general"]
    links.append(f'<a href="{base}stories/index.html">All stories</a>')
    links.append(f'<a href="{base}briefings/index.html">Analysis</a>')
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
<script>document.documentElement.classList.add("js");</script>
<script>{THEME_JS}</script>
<link rel="stylesheet" href="{base}style.css">
<link rel="icon" href="{base}favicon.svg" type="image/svg+xml">
<link rel="alternate" type="application/rss+xml" title="{site}" href="{esc(cfg['site_url'])}/feed.xml">
</head>
<body>
<div class="fx" aria-hidden="true"><i class="orb o1"></i><i class="orb o2"></i><i class="orb o3"></i><i class="fly f1"></i><i class="fly f2"></i><i class="fly f3"></i><svg class="fx-circuit" viewBox="0 0 1000 600" preserveAspectRatio="none" aria-hidden="true"><path class="g" d="M0 120 H260 L300 160 H520 L560 120 H1000"/><path class="r" d="M0 430 H180 L220 390 H430 L470 430 H760 L800 470 H1000" style="animation-delay:-6s"/><path class="b" d="M120 600 V470 L160 430 V260 L200 220 V0" style="animation-delay:-11s"/><path class="g" d="M1000 300 H820 L780 340 H640 L600 300 H380" style="animation-delay:-3s"/><circle cx="300" cy="160" r="4" fill="#22c55e"/><circle cx="470" cy="430" r="4" fill="#ef4444"/><circle cx="200" cy="220" r="4" fill="#38bdf8"/><circle cx="600" cy="300" r="4" fill="#22c55e"/></svg></div>
<a class="skip" href="#main">Skip to content</a>
<header class="site-header"><div class="wrap bar">
<a class="brand" href="{base}index.html"><img class="logo-img" src="{base}favicon.svg" width="30" height="30" alt="" aria-hidden="true">{site}</a>
<nav class="nav" aria-label="Categories">{nav}</nav>
<button type="button" id="theme-toggle" class="theme-toggle" aria-pressed="false">Dark mode</button>
</div></header>
<div class="banner" role="region" aria-label="Site highlights"><div class="wrap banner-in"><span class="banner-tag"><i class="led g" aria-hidden="true"></i>Live feed</span><p class="banner-text" id="banner-text" aria-live="off">Feeds are checked every 20 minutes.</p><a class="banner-action" href="{base}today/index.html"><i class="led r" aria-hidden="true"></i>Action today</a><button type="button" class="banner-pause" id="banner-pause" aria-pressed="false" aria-label="Pause banner">Pause</button></div></div>
<main id="main" class="wrap">
{body}
</main>
<script>{BANNER_JS}</script>
<script>{FX_JS}</script>
<footer class="site-footer"><div class="wrap"><p>&copy; {year} Leon Pavesic. Design, analysis and texts on this site are protected by copyright. Headlines, short excerpts and images belong to their original publishers and are linked to the source. Not affiliated with any source.</p><p><a href="{base}impressum.html">Impressum</a> &middot; <a href="{base}datenschutz.html">Privacy</a> &middot; <a href="{base}corrections.html">Corrections</a> &middot; <a href="{base}feed.xml">RSS</a> &middot; <a href="mailto:leon.pavesic@gmx.de">Contact</a> &middot; <a href="https://www.linkedin.com/in/leon-pavesic/" rel="me noopener noreferrer" target="_blank">LinkedIn</a> &middot; <a href="https://www.xing.com/profile/Leon_Pavesic" rel="me noopener noreferrer" target="_blank">XING</a></p></div></footer>
</body>
</html>
"""


def search_text(s: dict) -> str:
    return " ".join([s["title"], s["summary"], " ".join(s.get("vendors", [])), CATEGORIES[s["category"]][0]]).lower()


def _save_button(s: dict) -> str:
    icon = ('<svg width="14" height="14" viewBox="0 0 24 24" aria-hidden="true" focusable="false">'
            '<path d="M6 3h12v18l-6-4-6 4z" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/></svg>')
    return (f'<button type="button" class="save" data-save="{esc(s["id"])}" aria-pressed="false">'
            f'{icon}<span>Save</span></button>')


def _filter_data(s: dict) -> str:
    d = _date(s.get("published"))
    published = d.isoformat() if d else ""
    rank = {"Critical": 0, "High": 1, "Standard": 2}.get(s.get("priority"), 3)
    important = s.get("priority") in {"Critical", "High"} or bool(set(s.get("tags", [])) & {"exploited", "patch-now"})
    return (f'data-tags="{esc(" ".join(s.get("tags", [])))}" data-search="{esc(search_text(s))}" '
            f'data-published="{esc(published)}" data-priority="{esc(s.get("priority", "Standard"))}" '
            f'data-priority-rank="{rank}" data-score="{int(s.get("score", 0))}" '
            f'data-important="{str(important).lower()}"')


def priority_summary(s: dict) -> str:
    basis = s.get("priority_basis", [])
    if s.get("kev"):
        return "KEV-listed: " + ", ".join(s["kev"])
    official = next((x for x in basis if x.startswith("Official source reports exploitation:")), None)
    if official:
        return official
    if s.get("priority") == "High":
        return f"Editorial attention score {s.get('score', 0)}; not CVSS"
    if not s.get("kev_checked", False):
        return "No trigger found in available data; KEV check unavailable"
    return "No elevated-priority trigger identified in feed data"


def _card(s: dict) -> str:
    img = s["image"] or fallback_cover(s)
    names = ", ".join(dict.fromkeys(x["name"] for x in s["sources"]))
    prio = esc(s["priority"])
    fb = f' data-fallback="{esc(fallback_cover(s))}" onerror="this.onerror=null;this.src=this.dataset.fallback"'
    attrs = _filter_data(s)
    return f"""<article class="card prio-{prio}" {attrs}>
<a class="card-media" href="story/{esc(s['id'])}.html" tabindex="-1" aria-hidden="true"><img src="{esc(img)}"{fb} alt="" loading="lazy" decoding="async" referrerpolicy="no-referrer" width="640" height="360"><span class="badge {prio}">{prio}</span></a>
<div class="card-body">
<p class="kicker"><span class="cat">{esc(CATEGORIES[s['category']][0])}</span> <span class="type">{esc(s.get('content_type', 'News'))}</span></p>
<h3><a href="story/{esc(s['id'])}.html">{esc(s['title'])}</a></h3>
<p class="summary">{esc(_short(s['summary'], 170))}</p>
<p class="priority-note"><strong>Editorial priority:</strong> {esc(priority_summary(s))}</p>
<p class="meta">{esc(names)} &middot; {esc(fmt_date(s['published']))}</p>
{_save_button(s)}
</div>
</article>"""


def _hero(s: dict) -> str:
    img = s["image"] or fallback_cover(s)
    names = ", ".join(dict.fromkeys(x["name"] for x in s["sources"]))
    prio = esc(s["priority"])
    fb = f' data-fallback="{esc(fallback_cover(s))}" onerror="this.onerror=null;this.src=this.dataset.fallback"'
    attrs = _filter_data(s)
    return f"""<section class="hero" aria-labelledby="hero-title" {attrs}>
<a class="hero-media" href="story/{esc(s['id'])}.html" tabindex="-1" aria-hidden="true"><img src="{esc(img)}"{fb} alt="" loading="eager" referrerpolicy="no-referrer" width="640" height="360"></a>
<div class="hero-body">
<p class="kicker"><span class="badge {prio}">{prio}</span><span class="cat">{esc(CATEGORIES[s['category']][0])}</span></p>
<h2 id="hero-title"><a href="story/{esc(s['id'])}.html">{esc(s['title'])}</a></h2>
<p class="summary">{esc(_short(s['summary'], 240))}</p>
<p class="priority-note"><strong>Editorial priority:</strong> {esc(priority_summary(s))}</p>
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
.toolbar{position:relative;margin:0 0 14px}
.toolbar>svg{position:absolute;left:18px;top:50%;transform:translateY(-50%);color:var(--muted);pointer-events:none}
.search{display:block;width:100%;height:52px;font:inherit;font-size:1rem;padding:0 20px 0 48px;border-radius:999px;border:1px solid var(--line);background:var(--surface);color:var(--ink);box-shadow:var(--shadow);transition:border-color .15s,box-shadow .15s}
.search::placeholder{color:var(--muted);opacity:1}
.search:hover{border-color:color-mix(in srgb,var(--accent) 45%,var(--line))}
.search:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 4px color-mix(in srgb,var(--accent) 22%,transparent)}
.search::-webkit-search-cancel-button{cursor:pointer}
.actions{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-top:4px}
.save{display:inline-flex;align-items:center;gap:7px;align-self:flex-start;font:inherit;font-size:.82rem;font-weight:600;line-height:1;background:var(--surface);border:1px solid var(--line);color:var(--ink);border-radius:999px;padding:8px 14px 8px 12px;cursor:pointer;transition:background .15s,border-color .15s,color .15s}
.save svg{flex:none}
.save path{transition:fill .15s}
.save:hover{border-color:var(--accent);color:var(--accent)}
.save:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.save[aria-pressed="true"]{background:var(--accent);border-color:var(--accent);color:var(--accent-ink)}
.save[aria-pressed="true"] path{fill:currentColor}
.save.remove{color:var(--muted)}
.save.remove:hover{color:var(--crit);border-color:var(--crit)}
.card-body .save{margin-top:6px}
.table-wrap{overflow-x:auto;border:1px solid var(--line);border-radius:var(--r);background:var(--surface)}
.cve-table{width:100%;border-collapse:collapse;font-size:.9rem}
.cve-table th,.cve-table td{text-align:left;padding:11px 14px;border-bottom:1px solid var(--line);vertical-align:top}
.cve-table th{font-size:.72rem;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);font-weight:700;background:var(--surface-2);white-space:nowrap}
.cve-table tr:last-child td{border-bottom:0}
.cve-table td a{color:var(--ink);text-decoration:none}
.cve-table td a.cve-id{text-decoration:underline;font-weight:650}
.cve-title{font-weight:650;margin-bottom:4px}
.cve-blurb{margin:0}
.cve-legend ul{margin:8px 0 8px 18px}
.cve-legend li{margin:4px 0}
.cve-counts{margin:14px 0 10px}
.badge.KEV{color:var(--crit)}
.badge.Exploited{color:var(--high)}
.badge.None{color:var(--muted)}
.cve-table td a:hover{text-decoration:underline}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.85rem;white-space:nowrap}
.todo-list{display:grid;gap:14px}
.todo{background:var(--surface);border:1px solid var(--line);border-left:4px solid var(--std);border-radius:var(--r);padding:18px 20px}
.todo.kind-patch{border-left-color:var(--crit)}
.todo.kind-investigate{border-left-color:var(--high)}
.todo.kind-review{border-left-color:var(--accent)}
.todo.kind-patch-normal{border-left-color:var(--high)}
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


DONATE_LABELS = {"paypal": "PayPal", "buymeacoffee": "Buy me a coffee", "kofi": "Ko-fi",
                 "github": "GitHub Sponsors", "other": "Donate"}


def donation_links(site_cfg: dict) -> list[tuple[str, str]]:
    """Only https links the owner configured in site.json are shown. Nothing is shown by default."""
    out = []
    for d in site_cfg.get("donations") or []:
        url = str(d.get("url", "")).strip()
        if not url.startswith("https://"):
            continue
        label = str(d.get("label") or DONATE_LABELS.get(str(d.get("provider", "other")).lower(), "Donate"))
        out.append((label, url))
    return out


def _donate(site_cfg: dict, base: str = "") -> str:
    links = donation_links(site_cfg)
    if not links:
        return ""
    qr = str(site_cfg.get("donation_qr") or "").strip()
    qr_html = ""
    if qr and not qr.startswith(("/", "..")) and (ROOT / qr).is_file():
        qr_html = (f'<figure class="donate-qr"><img src="{base}{esc(qr)}" width="160" height="160" '
                   f'alt="QR code linking to the Buy me a coffee page" loading="lazy"></figure>')
    items = "".join(f'<li><a class="donate-btn" href="{esc(url)}" rel="noopener noreferrer" target="_blank">'
                    f'{esc(label)} &rarr;</a></li>' for label, url in links)
    text = str(site_cfg.get("donation_text") or
               "Security Brief is free to read. Donations are voluntary and do not change what is covered.")
    return ('<section class="support" aria-labelledby="support-title"><h2 id="support-title">Support this site</h2>'
            f'<p class="summary">{esc(text)}</p>'
            f'<ul class="donate-grid">{items}</ul>{qr_html}</section>')


# ---------- article covers (branded, generated from the article's own title) ----------
SECTION_COLORS = {"patch-tuesday": "#38bdf8", "briefings": "#22c55e"}


def article_cover(a: dict) -> str:
    accent = SECTION_COLORS.get(a.get("section"), "#5eead4")
    label = SECTIONS.get(a.get("section"), "Analysis")
    title = a.get("title") or label
    lines = textwrap.wrap(title, 26) or [title]
    if len(lines) > 3:
        lines = lines[:3]
        lines[2] = lines[2][:23].rstrip() + "..."
    text = "".join(
        f'<text x="48" y="{170 + i * 44}" fill="#f1f5f9" font-family="Arial,Helvetica,sans-serif" '
        f'font-size="32" font-weight="700">{esc(t)}</text>' for i, t in enumerate(lines))
    grid = "".join(f'<line x1="{x}" y1="0" x2="{x}" y2="360"/>' for x in range(0, 641, 64))
    grid += "".join(f'<line x1="0" y1="{y}" x2="640" y2="{y}"/>' for y in range(0, 361, 60))
    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" width="640" height="360" viewBox="0 0 640 360">'
        '<rect width="640" height="360" fill="#0b0f14"/>'
        f'<g stroke="#18202b" stroke-width="1">{grid}</g>'
        f'<path d="M 360 320 Q 470 40 612 110" fill="none" stroke="{accent}" stroke-width="1.5" '
        'stroke-dasharray="4 6" opacity=".75"/>'
        f'<circle cx="612" cy="110" r="5" fill="{accent}"/>'
        '<circle cx="596" cy="36" r="6" fill="#22c55e"/><circle cx="618" cy="36" r="6" fill="#ef4444" opacity=".85"/>'
        f'<rect width="8" height="360" fill="{accent}"/>'
        f'<text x="48" y="112" fill="{accent}" font-family="Arial,Helvetica,sans-serif" font-size="16" '
        f'font-weight="700" letter-spacing="3">{esc(label.upper())}</text>'
        f'{text}'
        '<text x="48" y="318" fill="#64748b" font-family="Arial,Helvetica,sans-serif" font-size="13" '
        'letter-spacing="2">SECURITY BRIEF  |  ANALYSIS</text>'
        "</svg>"
    )
    return "data:image/svg+xml;charset=utf-8," + quote(svg)


def _article_card(a: dict, href: str) -> str:
    label = SECTIONS[a["section"]]
    return f"""<article class="card">
<a class="card-media" href="{esc(href)}" tabindex="-1" aria-hidden="true"><img src="{esc(article_cover(a))}" alt="" loading="lazy" decoding="async" width="640" height="360"></a>
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
    header = (
        '<section class="hero article-hero" aria-labelledby="article-title">'
        f'<div class="hero-media"><img src="{esc(article_cover(a))}" alt="" width="640" height="360"></div>'
        f'<div class="hero-body"><p class="kicker"><span class="cat">{esc(label)}</span>'
        f'<span class="type">{esc(fmt_day(a["date"]))}</span></p>'
        f'<h1 id="article-title" class="article-title">{esc(a["title"])}</h1>{lede}</div></section>'
    )
    body = (
        header
        + '<article class="prose">' + a["body"]
        + f'<p class="meta"><a href="index.html">&larr; All {esc(label)}</a> &middot; <a href="../../index.html">Home</a></p>'
        + "</article>"
    )
    body += _donate(site_cfg, base) + _newsletter(site_cfg, base)
    return _layout(cfg, a["title"], _short(a["summary"] or a["title"], 150), body, base)


def msrc_cve_rows(stories: list[dict]) -> list[dict]:
    """Stories from the Microsoft Security Response Center feed that name at least one CVE. KEV first, then score."""
    rows = [s for s in stories
            if s["cves"] and any(x["name"] == "Microsoft Security Response Center" for x in s["sources"])]
    return sorted(rows, key=lambda s: (not s["kev"], -s["score"]))


SUG_URL = "https://msrc.microsoft.com/update-guide/vulnerability/{cve}"
REVISION_RE = re.compile(r"informational change|^\s*(updated|revised)\b", re.I)
MD_LINK_RE = re.compile(r"\[([^\]]+)\]\([^)]*\)")
MSRC_NAME = "Microsoft Security Response Center"


def is_revision(s: dict) -> bool:
    """Microsoft re-posts an existing entry to change links or acknowledgements. That is not a new fix."""
    return bool(REVISION_RE.search(s.get("summary") or ""))


def primary_cves(s: dict) -> list[str]:
    """CVE IDs named in the entry title. Other IDs in the body are shown as 'also named', not as rows."""
    named = sorted({c.upper() for c in CVE_RE.findall(s["title"])})
    return named or sorted(s["cves"])[:1]


def _cve_status(s: dict) -> tuple[str, str, str]:
    """(badge text, css class, plain meaning) for the exploitation signal in this run."""
    if s["kev"]:
        return ("KEV", "KEV", "Listed in CISA's Known Exploited Vulnerabilities catalog at the time of this run. Patch first.")
    if "exploited" in s["tags"]:
        return ("Exploited", "Exploited", "A source in this run reports exploitation, but the CVE is not in the KEV catalog.")
    return ("Not reported", "None", "No exploitation signal in this run. This does not mean the flaw is safe.")


def _cve_blurb(s: dict) -> str:
    text = " ".join((s.get("summary") or "").split())
    text = MD_LINK_RE.sub(r"\1", text)  # feed text contains markdown links; show the link text only
    if not text or text.rstrip(".").lower() == s["title"].rstrip(".").lower():
        return "The feed gives no description. Open the Security Update Guide entry for details."
    return _short(text, 220)


def cve_entries(rows: list[dict]) -> list[tuple[str, dict]]:
    """One (CVE, entry) pair per CVE. Newest entry wins for duplicates. New CVEs first (KEV, then score), revisions last."""
    seen: dict[str, dict] = {}
    for s in sorted(rows, key=lambda x: x.get("published") or "", reverse=True):
        for cve in primary_cves(s):
            seen.setdefault(cve, s)
    entries = list(seen.items())
    entries.sort(key=lambda e: (is_revision(e[1]), not e[1]["kev"], -e[1]["score"]))
    return entries


def cve_table(rows: list[dict]) -> str:
    legend = (
        '<section class="section" id="cve-table"><h2>Microsoft CVEs in the current window</h2>'
        '<div class="box cve-legend"><p><strong>How to read this table</strong></p><ul>'
        "<li><strong>CVE</strong> links to the Microsoft Security Update Guide entry. That page is the authority for "
        "affected products, severity (CVSS) and fixes. The feed used here does not include CVSS scores.</li>"
        "<li><strong>KEV</strong>: listed in CISA's Known Exploited Vulnerabilities catalog at the time of this run. "
        "Treat it as patch first.</li>"
        "<li><strong>Exploited</strong>: a source in this run reports exploitation, but the CVE is not in KEV.</li>"
        "<li><strong>Not reported</strong>: no exploitation signal in this run. This does not mean the flaw is safe.</li>"
        "<li><strong>Priority</strong>: Critical = KEV, or exploitation reported by an official source. "
        "High = score 6 or more. Standard = everything else. The suggested order follows the priority.</li>"
        "<li><strong>Also named</strong>: other CVE IDs in the same entry. They are listed there, not as separate rows.</li>"
        "<li><strong>Revision</strong>: Microsoft changed an existing entry, for example links or acknowledgements. "
        "No new fix is implied.</li>"
        "<li><strong>Feed date</strong>: the feed gives one time per entry. CVEs in the same entry share it.</li>"
        "</ul><p class=\"meta\">This is the Microsoft Security Response Center feed only, not the complete Patch Tuesday "
        "list. Use the Security Update Guide for the full list.</p></div>"
    )
    entries = cve_entries(rows)
    if not entries:
        return legend + '<div class="empty">No Microsoft CVE entries in the current window.</div></section>'
    new = [(c, s) for c, s in entries if not is_revision(s)]
    n_rev = len(entries) - len(new)
    n_kev = sum(1 for _, s in new if s["kev"])
    n_crit = sum(1 for _, s in new if s["priority"] == "Critical")
    n_high = sum(1 for _, s in new if s["priority"] == "High")
    counts = (f'<p class="meta cve-counts">{len(new)} new CVE{"s" if len(new) != 1 else ""} · '
              f"{n_kev} KEV · {n_crit} Critical · {n_high} High")
    if n_rev:
        counts += f" · {n_rev} revision{'s' if n_rev != 1 else ''} (no new fix)"
    counts += "</p>"
    trs = []
    for cve, s in entries:
        label, cls, meaning = _cve_status(s)
        others = [c for c in s["cves"] if c not in primary_cves(s)]
        also = ""
        if others:
            shown = ", ".join(others[:8]) + (f" and {len(others) - 8} more" if len(others) > 8 else "")
            also = f'<p class="meta cve-also">Also named in this entry: {esc(shown)}</p>'
        if is_revision(s):
            prio_cell = ('<span class="badge None">Revision</span>'
                         '<div class="meta">Check only if you already track this product</div>')
        else:
            prio = esc(s["priority"])
            order = {"Critical": "1 · Patch first", "High": "2 · This cycle"}.get(s["priority"], "3 · Normal cycle")
            prio_cell = f'<span class="badge {prio}">{prio}</span><div class="meta">{esc(order)}</div>'
        trs.append(
            "<tr>"
            f'<td class="mono"><a class="cve-id" href="{SUG_URL.format(cve=esc(cve))}" target="_blank" '
            f'rel="noopener noreferrer">{esc(cve)}</a></td>'
            f'<td><div class="cve-title">{esc(s["title"])}</div><p class="meta cve-blurb">{esc(_cve_blurb(s))}</p>{also}</td>'
            f'<td><span class="badge {cls}" title="{esc(meaning)}">{esc(label)}</span></td>'
            f"<td>{prio_cell}</td>"
            f'<td class="meta">{esc(fmt_date(s["published"]))}</td>'
            f'<td><a href="../story/{esc(s["id"])}.html">Story</a></td>'
            "</tr>"
        )
    return (legend + counts + '<div class="table-wrap"><table class="cve-table"><thead><tr>'
            '<th scope="col">CVE</th><th scope="col">What it is</th><th scope="col">Exploitation</th>'
            '<th scope="col">Priority</th><th scope="col">Feed date</th><th scope="col">Details</th></tr></thead><tbody>'
            + "".join(trs) + "</tbody></table></div></section>")

def _article_hero(a: dict, href: str) -> str:
    return (f'<section class="hero" aria-labelledby="hero-title"><a class="hero-media" href="{esc(href)}" tabindex="-1" aria-hidden="true">'
            f'<img src="{esc(article_cover(a))}" alt="" loading="eager" width="640" height="360"></a>'
            f'<div class="hero-body"><p class="kicker"><span class="cat">{esc(SECTIONS[a["section"]])}</span></p>'
            f'<h2 id="hero-title"><a href="{esc(href)}">{esc(a["title"])}</a></h2>'
            f'<p class="summary">{esc(_short(a["summary"] or "", 240))}</p>'
            f'<p class="meta">{esc(fmt_day(a["date"]))}</p>'
            f'<div class="actions"><a class="btn" href="{esc(href)}">Read the analysis &rarr;</a></div></div></section>')


def section_page(sec: str, arts: list[dict], cfg: dict, site_cfg: dict,
                 cve_rows: list[dict] | None = None) -> str:
    base = "../"
    label = SECTIONS[sec]
    if arts:
        listing = _article_hero(arts[0], f"{arts[0]['slug']}.html")
        if len(arts) > 1:
            cards = "".join(_article_card(a, f"{a['slug']}.html") for a in arts[1:])
            listing += f'<section class="section"><h2>More analysis</h2><div class="grid">{cards}</div></section>'
    else:
        listing = '<div class="empty">No published articles yet.</div>'
    cve_block = cve_table(cve_rows) if cve_rows is not None else ""
    body = (
        f'<section class="intro"><p class="kicker">Analysis desk</p><h1>{esc(label)}</h1>'
        f'<p class="lede">Original analysis, newest first.</p></section>'
        + listing + cve_block
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
        '<article class="prose"><h1>Impressum</h1>' + imp
        + "<h2>Urheberrecht</h2>"
        "<p>Die Gestaltung, die Auswahl sowie die eigenen Analysen und Texte dieser Website sind urheberrechtlich geschützt. "
        "Jede Verwertung außerhalb der Grenzen des Urheberrechts bedarf der schriftlichen Zustimmung des Verantwortlichen.</p>"
        "<p>Schlagzeilen, Textauszüge, Vorschaubilder und Logos stammen von den jeweiligen Quellen und bleiben deren Eigentum. "
        "Jede Meldung verlinkt auf den Originalartikel. Zitate sind kurz gehalten und als solche gekennzeichnet.</p>"
        "<h2>Haftung für Inhalte</h2>"
        "<p>Die Inhalte werden automatisch aus öffentlichen RSS-Feeds übernommen und gekürzt. Für Richtigkeit, Vollständigkeit "
        "und Aktualität der Inhalte, insbesondere der Originalquellen, wird keine Gewähr übernommen. "
        "Die Angaben ersetzen keine individuelle Sicherheitsberatung.</p>"
        "<h2>Haftung für Links</h2>"
        "<p>Für die Inhalte verlinkter externer Seiten sind ausschließlich deren Betreiber verantwortlich.</p>"
        "</article>"
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
    entries = site_cfg.get("corrections") or []
    if entries:
        items = "".join(
            "<li><strong>" + esc(str(e.get("date", ""))) + "</strong> – " + esc(str(e.get("note", ""))) + "</li>"
            for e in entries
        )
        corr_body = "<ul>" + items + "</ul>"
    else:
        corr_body = "<p>Bisher keine Korrekturen.</p>"
    corrections = (
        '<article class="prose"><h1>Korrekturen</h1>'
        "<p>Wir korrigieren Fehler, sobald wir sie bemerken. Jede Korrektur wird hier mit Datum und Hinweis festgehalten.</p>"
        + corr_body + "</article>"
    )
    return {
        "corrections.html": _layout(cfg, "Korrekturen", "Korrekturen", corrections, ""),
        "impressum.html": _layout(cfg, "Impressum", "Impressum", impressum, ""),
        "datenschutz.html": _layout(cfg, "Datenschutzerklärung", "Datenschutzerklärung", privacy, ""),
    }


DESIGN_CSS = """
.logo-img{width:30px;height:30px;flex:none;border-radius:8px}
.brand{gap:10px;font-weight:760;letter-spacing:-.01em}
.card{transition:transform .2s ease,box-shadow .2s ease,border-color .2s ease}
.card:hover{transform:translateY(-2px);box-shadow:0 12px 32px rgba(2,8,23,.18);border-color:var(--accent)}
.section-more{margin:14px 0 0;font-size:.92rem}
.section-more a{font-weight:650;text-decoration:none}
.section-more a:hover{text-decoration:underline}
.nav a[aria-current="page"]{color:var(--accent)}
:focus-visible{outline:3px solid var(--accent);outline-offset:3px}
.hero{position:relative;overflow:hidden;isolation:isolate}
.hero::before{content:"";position:absolute;inset:-40%;z-index:-1;pointer-events:none;background:radial-gradient(circle at 28% 32%,rgba(56,189,248,.22),transparent 42%),radial-gradient(circle at 72% 64%,rgba(94,234,212,.16),transparent 40%);animation:drift 18s ease-in-out infinite alternate}
@keyframes drift{to{transform:translate3d(-4%,3%,0) scale(1.06)}}
.logo-img{animation:float 6s ease-in-out infinite}
@keyframes float{50%{transform:translateY(-4px)}}
.card{backdrop-filter:blur(6px);-webkit-backdrop-filter:blur(6px)}
.stats .stat{animation:float 7s ease-in-out infinite}
.stats .stat:nth-child(2){animation-delay:-2s}.stats .stat:nth-child(3){animation-delay:-4s}.stats .stat:nth-child(4){animation-delay:-6s}
@media (prefers-reduced-motion:reduce){.card,.card:hover,.hero::before,.logo-img,.stats .stat{transition:none;transform:none;animation:none}}
"""
EXTRA_CSS += """
.filter-tools{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;margin:-18px 0 12px}
.filter-tools label{display:flex;flex-direction:column;gap:6px;color:var(--muted);font-size:.78rem;font-weight:650}
.filter-tools select{min-height:42px;width:100%;padding:8px 11px;border:1px solid var(--line);border-radius:10px;background:var(--surface);color:var(--ink);font:inherit;font-size:.88rem}
.filter-tools select:focus-visible,.important-only input:focus-visible{outline:3px solid color-mix(in srgb,var(--accent) 55%,transparent);outline-offset:2px}
.filter-tools .important-only{display:flex;flex-direction:row;align-items:center;gap:9px;padding:9px 12px;border:1px solid var(--line);border-radius:10px;background:var(--surface);color:var(--ink);font-size:.88rem}
.important-only input{width:18px;height:18px;accent-color:var(--accent)}
.important-only .hint{color:var(--muted);font-size:.74rem;font-weight:450}
.filter-count{margin:-4px 0 18px;color:var(--muted);font-size:.82rem;font-variant-numeric:tabular-nums}
.priority-note{margin:0 0 8px;color:var(--muted);font-size:.78rem;line-height:1.4}
.freshness{display:flex;gap:4px;flex-wrap:wrap;align-items:baseline}
@media(max-width:760px){.filter-tools{grid-template-columns:1fr 1fr}.filter-tools .important-only{grid-column:1/-1;flex-wrap:wrap}.card .meta{overflow-wrap:anywhere}.save{min-height:40px}}
@media(max-width:460px){.filter-tools{grid-template-columns:1fr}.filter-tools .important-only{grid-column:auto}}
"""

FAVICON_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="14" fill="#0b1d3a"/><path d="M32 12 L48 18 V31 C48 42 41 50 32 54 C23 50 16 42 16 31 V18 Z" fill="none" stroke="#38bdf8" stroke-width="4" stroke-linejoin="round"/><path d="M24 31 L30 37 L41 25" fill="none" stroke="#38bdf8" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/></svg>"""
LOGO_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 360 80" role="img" aria-label="Security Brief"><rect x="0" y="8" width="64" height="64" rx="14" fill="#0b1d3a"/><path d="M32 20 L48 26 V39 C48 50 41 58 32 62 C23 58 16 50 16 39 V26 Z" fill="none" stroke="#38bdf8" stroke-width="4" stroke-linejoin="round"/><path d="M24 39 L30 45 L41 33" fill="none" stroke="#38bdf8" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><text x="80" y="38" font-family="Arial, Helvetica, sans-serif" font-size="28" font-weight="700" fill="#0b1d3a">Security Brief</text><text x="80" y="58" font-family="Arial, Helvetica, sans-serif" font-size="12" letter-spacing="2.4" fill="#475569">THREATS · ACTIONS · EVIDENCE</text></svg>"""


FILTERS = [
    ("all", "All"), ("critical", "Critical (editorial)"), ("exploited", "Exploitation reported"), ("patch-now", "Patch now"),
    ("microsoft", "Microsoft"), ("defender", "Defender"), ("ai", "AI security"),
]
def filter_bar(stories: list[dict]) -> str:
    buttons = []
    for key, label in FILTERS:
        n = len(stories) if key == "all" else sum(1 for story in stories if key in story["tags"])
        if key != "all" and n == 0:
            continue
        pressed = "true" if key == "all" else "false"
        buttons.append(f'<button type="button" data-filter="{key}" aria-pressed="{pressed}">{esc(label)} <span class="count">{n}</span></button>')
    search = ('<div class="toolbar"><label class="visually-hidden" for="story-search">Search stories</label>'
              '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" '
              'stroke-linecap="round" aria-hidden="true" focusable="false"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></svg>'
              '<input id="story-search" class="search" type="search" placeholder="Search stories, vendors or topics" '
              'autocomplete="off" spellcheck="false"></div>')
    controls = """<div class="filter-tools" aria-label="Additional story filters">
<label>Time range <select id="date-filter"><option value="168">Last 7 days</option><option value="72">Last 72 hours</option><option value="24">Last 24 hours</option><option value="0">All in current feed</option></select></label>
<label>Sort by <select id="sort-filter"><option value="priority">Priority, then newest</option><option value="date">Newest first</option></select></label>
<label class="important-only"><input id="important-only" type="checkbox"> Important only <span class="hint">Critical, High, or exploitation / patch signal</span></label>
</div><p id="filter-count" class="filter-count" aria-live="polite"></p>"""
    return (search + '<div class="filters" id="filters" role="group" aria-label="Filter stories by topic">'
            + "".join(buttons) + '</div>' + controls
            + '<p id="filter-empty" class="empty" hidden>No stories match these filters in the current window.</p>')


FILTER_JS = """(function(){
var bar=document.getElementById('filters');
var search=document.getElementById('story-search');
var range=document.getElementById('date-filter');
var sort=document.getElementById('sort-filter');
var important=document.getElementById('important-only');
var buttons=bar?bar.querySelectorAll('button[data-filter]'):[];
var items=Array.prototype.slice.call(document.querySelectorAll('[data-tags]'));
var sections=document.querySelectorAll('[data-section]');
var empty=document.getElementById('filter-empty');
var count=document.getElementById('filter-count');
var current='all';
function timestamp(el){var value=el.getAttribute('data-published');return value?Date.parse(value):NaN;}
function compare(a,b){
  if(sort&&sort.value==='priority'){
    var rankA=Number(a.getAttribute('data-priority-rank')||9),rankB=Number(b.getAttribute('data-priority-rank')||9);
    if(rankA!==rankB)return rankA-rankB;
    var scoreA=Number(a.getAttribute('data-score')||0),scoreB=Number(b.getAttribute('data-score')||0);
    if(scoreA!==scoreB)return scoreB-scoreA;
  }
  return (timestamp(b)||0)-(timestamp(a)||0);
}
function reorder(){
  document.querySelectorAll('.grid').forEach(function(grid){
    var cards=Array.prototype.filter.call(grid.children,function(el){return el.hasAttribute('data-tags');});
    cards.sort(compare).forEach(function(card){grid.appendChild(card);});
  });
}
function apply(){
  var q=(search?search.value:'').trim().toLowerCase();
  var hours=range?Number(range.value):168;
  var cutoff=hours>0?Date.now()-hours*3600000:0;
  var shown=0;
  items.forEach(function(el){
    var tags=' '+(el.getAttribute('data-tags')||'')+' ';
    var text=el.getAttribute('data-search')||'';
    var date=timestamp(el);
    var inRange=!cutoff||(Number.isFinite(date)&&date>=cutoff);
    var isImportant=el.getAttribute('data-important')==='true';
    var ok=(current==='all'||tags.indexOf(' '+current+' ')>-1)&&(!q||text.indexOf(q)>-1)&&inRange&&(!important||!important.checked||isImportant);
    el.hidden=!ok;if(ok)shown++;
  });
  sections.forEach(function(sec){sec.hidden=!sec.querySelector('[data-tags]:not([hidden])');});
  if(empty)empty.hidden=shown>0;
  if(count)count.textContent=shown+' stories shown';
}
buttons.forEach(function(b){b.addEventListener('click',function(){
  current=b.getAttribute('data-filter');
  buttons.forEach(function(x){x.setAttribute('aria-pressed',String(x===b));});
  apply();
});});
if(search)search.addEventListener('input',apply);
if(range)range.addEventListener('change',apply);
if(important)important.addEventListener('change',apply);
if(sort)sort.addEventListener('change',function(){reorder();apply();});
var KEY='sb-saved';
function readSaved(){try{return JSON.parse(localStorage.getItem(KEY)||'[]');}catch(e){return [];}}
function writeSaved(a){try{localStorage.setItem(KEY,JSON.stringify(a));}catch(e){}}
var saves=document.querySelectorAll('button[data-save]');
function paint(){var saved=readSaved();saves.forEach(function(b){
  var on=saved.indexOf(b.getAttribute('data-save'))>-1;
  var label=b.querySelector('span');b.setAttribute('aria-pressed',String(on));if(label)label.textContent=on?'Saved':'Save';});}
saves.forEach(function(b){b.addEventListener('click',function(){
  var id=b.getAttribute('data-save');var a=readSaved();var i=a.indexOf(id);
  if(i>-1)a.splice(i,1);else a.push(id);writeSaved(a);paint();
});});
reorder();paint();apply();
})();"""


FEED_STATUS_JS = """(function(){
var el=document.getElementById('feed-freshness');if(!el)return;
function stamp(value){var d=new Date(value);return isNaN(d.getTime())?'time unavailable':new Intl.DateTimeFormat(undefined,{day:'2-digit',month:'short',year:'numeric',hour:'2-digit',minute:'2-digit',timeZone:'UTC',timeZoneName:'short'}).format(d);}
fetch('status.json?fresh='+Date.now(),{cache:'no-store'}).then(function(r){if(!r.ok)throw Error('status unavailable');return r.json();}).then(function(s){
  var ok=Number(s.sources_ok||0),total=Number(s.sources_total||0);
  el.textContent='Last feed check: '+stamp(s.last_check_at||s.generated)+' · '+ok+'/'+total+' sources succeeded in that run. ';
  var a=document.createElement('a');a.href='status.json';a.textContent='Details';el.appendChild(a);
}).catch(function(){el.textContent='Latest feed-check status is unavailable; displayed stories remain accessible.';});
})();"""


ACTION_RANK = {"patch": 0, "investigate": 1, "patch-normal": 2, "review": 3, "monitor": 4}
ACTION_LABEL = {"patch": "Patch now", "investigate": "Investigate", "patch-normal": "Patch in normal cycle",
                "review": "Review", "monitor": "Monitor"}


def affected(s: dict) -> tuple[str, str]:
    """(label, target phrase for the suggestion, whether a named product was found)."""
    if s.get("vendors"):
        return s["vendors"][0], s["vendors"][0] + " products", True
    tags = set(s["tags"])
    for tag, name in (("microsoft", "Microsoft"), ("defender", "Microsoft Defender")):
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
    elif s.get("cves") and any(x.get("name") == "Microsoft Security Response Center" for x in s["sources"]) and is_revision(s):
        kind, text = "monitor", ("Microsoft revised this entry without a new fix. "
                                 "Check the Security Update Guide only if you already track this product.")
    elif s.get("cves") and any(x.get("name") == "Microsoft Security Response Center" for x in s["sources"]):
        # Microsoft's own security update list: a fix exists, so it is never "no action".
        kind, text = "patch-normal", (f"Microsoft lists this CVE in its security update list. {check} "
                                      "Plan the fix for your next regular update window.")
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
    var rm=el('button','save remove','Remove');rm.type='button';
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
        "priority_score": s["score"], "priority_basis": s.get("priority_basis", []),
        "tags": s["tags"], "kev": s.get("kev", []),
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
        f'<p class="meta">Last content publication: {esc(fmt_date(status.get("content_published_at") or now.isoformat()))}. '
        "Feed checks run every 20 minutes; this timestamp changes only when published story or analysis content changes. Editorial priority is not CVSS or tenant-specific risk.</p>"
        '<p class="meta freshness" id="feed-freshness" role="status">Loading the latest feed-check result&hellip;</p>'
        '<p><a class="btn" href="today/index.html">Today: what to do &rarr;</a></p></section>',
        '<div class="stats" aria-label="Summary">'
        f'<div class="stat"><b>{len(stories)}</b><span>stories in the current window</span></div>'
        f'<div class="stat crit"><b>{crit}</b><span>critical (editorial)</span></div>'
        f'<div class="stat"><b>{exploited}</b><span>exploitation reported</span></div>'
        f'<div class="stat"><b>{status.get("sources_total", 0)}</b><span>sources monitored</span></div>'
        "</div>",
    ]
    parts.append(_donate(site_cfg))
    if articles:
        parts.append(
            '<section class="section" id="analysis"><h2>From the analysis desk</h2><div class="grid">'
            + "".join(_article_card(a, f"{a['section']}/{a['slug']}.html") for a in articles[:3])
            + '</div><p class="analysis-links meta"><a href="briefings/index.html">All analysis</a> &middot; '
            '<a href="patch-tuesday/index.html">All Patch Tuesday notes</a></p></section>'
        )
    parts.append(
        '<section class="section" id="free-downloads" aria-labelledby="free-download-title">'
        '<h2 id="free-download-title">Free field guide</h2>'
        '<article class="card resource-card"><div class="card-body">'
        '<p class="card-kicker">PRINTABLE WORKSHEET &middot; VERSION 1.0</p>'
        '<h3>Microsoft 365 Identity Incident Triage</h3>'
        '<p class="summary">Evidence-first checks for suspicious sign-ins, Entra audit activity, app access, mailbox persistence, containment and verification.</p>'
        '<p class="meta">3 pages &middot; Updated 22 October 2026 &middot; Includes Microsoft Learn references</p>'
        '<a class="btn" href="m365-identity-incident-triage-checklist.pdf" download>Download the free PDF &rarr;</a>'
        '</div></article></section>'
    )
    newsletter = _newsletter(site_cfg, "")
    if newsletter:
        parts.append(newsletter)
    if not stories:
        parts.append('<div class="empty">No news stories yet. The next automated check will fill this page.</div>')
    else:
        parts.append(f'<p class="meta browse-all"><a class="btn" href="stories/index.html">Browse and filter all {len(stories)} stories &rarr;</a></p>')
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
            total = sum(1 for s in stories if s["category"] == cid)
            parts.append(f'<section class="section" id="{cid}" data-section><h2>{esc(CATEGORIES[cid][0])}</h2>'
                         '<div class="grid">' + "".join(_card(s) for s in items) + "</div>"
                         f'<p class="section-more"><a href="category/{cid}/index.html">All {total} {esc(CATEGORIES[cid][0])} stories &rarr;</a></p></section>')
    parts.append("<script>" + FEED_STATUS_JS + "</script>")
    return _layout(cfg, "Home", "Ranked cybersecurity news with links to original sources.", "\n".join(parts), "")


def listing_page(stories: list[dict], cfg: dict, base: str, title: str, intro: str) -> str:
    parts = [f'<section class="intro"><h1>{esc(title)}</h1><p class="meta">{esc(intro)}</p>'
             '<p class="meta">Filters apply to every story shown in this listing. Editorial priority is not CVSS or environment-specific risk.</p></section>']
    if not stories:
        parts.append('<div class="empty">No stories in this section in the current window.</div>')
    else:
        parts.append(filter_bar(stories))
        parts.append('<section class="section" data-section aria-label="Stories"><div class="grid">'
                     + "".join(_card(s) for s in stories) + "</div></section>")
        parts.append("<script>" + FILTER_JS + "</script>")
    return _layout(cfg, title, intro, "\n".join(parts), base)


def story_page(s: dict, cfg: dict) -> str:
    cat_label = CATEGORIES[s["category"]][0]
    if s["image"]:
        img = s["image"]
        credit = f"Image: {s['image_source']}. Credit remains with the original publisher."
        fb_attr = f' data-fallback="{esc(fallback_cover(s))}" onerror="this.onerror=null;this.src=this.dataset.fallback"'
    else:
        img = fallback_cover(s)
        fb_attr = ""
        credit = "Illustration: no preview image was available for this story."
    reasons = "".join(f"<li>{esc(r)}</li>" for r in s["reasons"]) or "<li>No scoring signals matched.</li>"
    srcs = "".join(
        f'<li><a href="{esc(x["url"])}" rel="nofollow noopener noreferrer" target="_blank">{esc(x["title"])}</a>'
        f' — {esc(x["name"])}, {esc(fmt_date(x["published"]))}'
        + (' <span class="dead">(link not found at last check)</span>' if x.get("link_status") == "dead" else "")
        + "</li>"
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
    instr = s.get("instructions") or []
    if instr:
        items_html = "".join(
            f'<li>&ldquo;{esc(x["text"])}&rdquo; <span class="meta">— <a href="{esc(x["url"])}" '
            f'rel="nofollow noopener noreferrer" target="_blank">{esc(x["source"])}</a></span></li>'
            for x in instr)
        instr_block = ("<h2>Instructions from the source</h2>"
                       "<p class=\"note\">Sentences quoted word for word from the original article. "
                       "Check each one against the article before you act.</p>"
                       f"<ul>{items_html}</ul>")
    else:
        instr_block = ("<h2>Instructions from the source</h2>"
                       "<p class=\"note\">We found no specific instructions in the source article. "
                       "Open the original and look for a recommendation or a fix.</p>")
    if any(x.get("name") == MSRC_NAME for x in s["sources"]) and s["cves"]:
        sug = "".join(
            f'<li><a href="{SUG_URL.format(cve=esc(c))}" rel="noopener noreferrer" target="_blank">{esc(c)}</a>'
            f" — affected products, fixes and KB links</li>" for c in s["cves"])
        instr_block += ("<p>Microsoft's official fix details for this entry are on the Security Update Guide:</p>"
                        f"<ul>{sug}</ul>")
    body = f"""<p class="meta"><a href="../index.html">← Back to home</a></p>
<p class="meta"><span class="badge {esc(s['priority'])}">{esc(s['priority'])}</span>{esc(cat_label)}</p>
<h1>{esc(s['title'])}</h1>
<p class="meta">Published: {esc(fmt_date(s['published']))} · Priority score {s['score']}</p>
<figure><img src="{esc(img)}"{fb_attr} alt="" referrerpolicy="no-referrer" width="640" height="360"><figcaption>{esc(credit)}</figcaption></figure>
<h2>Summary</h2>
<p>{esc(s['summary']) or 'No excerpt available. Please read the original article.'}</p>
<p class="meta">Summary is the feed's excerpt, shortened. It is not a full article.</p>
<h2>Why it matters</h2>
<p>{esc(why_it_matters(s))}</p>
{instr_block}
<h2>Why this priority</h2>
<div class="box"><p><strong>Editorial triage priority: {esc(s['priority'])}.</strong> This is not a CVSS severity score and does not establish risk to your environment. Critical requires a CISA KEV listing or exploitation reported by an official source; High uses the site's editorial attention score threshold (6), which includes context such as recency and enterprise relevance.</p>
<ul>{''.join(f'<li>{esc(x)}</li>' for x in s.get('priority_basis', []))}</ul>
<p><strong>Scoring signals:</strong></p><ul>{reasons}</ul>
<p>{kev_line}</p><p>CVSS and vendor fix status are not inferred when the feed does not provide them; verify affected versions and remediation in the linked primary advisory.</p></div>
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
            f"{site}/impressum.html", f"{site}/datenschutz.html", f"{site}/corrections.html",
            f"{site}/m365-identity-incident-triage-checklist.pdf"]
    urls += [f"{site}/{a['section']}/{a['slug']}.html" for a in (articles or [])]
    urls += [f"{site}/story/{s['id']}.html" for s in stories]
    urls += [f"{site}/stories/index.html"] + [f"{site}/category/{c}/index.html" for c in CATEGORY_ORDER]
    return ('<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
            + "".join(f"<url><loc>{esc(u)}</loc></url>" for u in urls) + "</urlset>\n")


FX_JS = """(function(){
var reduce=window.matchMedia&&matchMedia('(prefers-reduced-motion: reduce)').matches;
var bar=document.createElement('div');bar.className='progress';bar.setAttribute('aria-hidden','true');document.body.appendChild(bar);
function prog(){var h=document.documentElement,max=h.scrollHeight-h.clientHeight;bar.style.transform='scaleX('+(max>0?Math.min(1,h.scrollTop/max):0)+')';}
window.addEventListener('scroll',prog,{passive:true});prog();
if(!reduce&&'IntersectionObserver' in window){
var io=new IntersectionObserver(function(es){es.forEach(function(e){if(e.isIntersecting){e.target.classList.add('in');io.unobserve(e.target);}});},{threshold:.1});
document.querySelectorAll('.card,.hero,.stat').forEach(function(el){el.classList.add('reveal');io.observe(el);});}
if(!reduce){document.querySelectorAll('.card').forEach(function(c){c.addEventListener('pointermove',function(ev){var r=c.getBoundingClientRect();c.style.setProperty('--mx',(ev.clientX-r.left)+'px');c.style.setProperty('--my',(ev.clientY-r.top)+'px');});});}
})();"""

FX_CSS = """
main,.site-footer{position:relative;z-index:1}
body::before{content:"";position:fixed;inset:0;z-index:0;pointer-events:none;opacity:.55;background-image:linear-gradient(var(--line) 1px,transparent 1px),linear-gradient(90deg,var(--line) 1px,transparent 1px);background-size:56px 56px;-webkit-mask-image:radial-gradient(ellipse at 50% 0%,#000 25%,transparent 72%);mask-image:radial-gradient(ellipse at 50% 0%,#000 25%,transparent 72%)}
.fx{position:fixed;inset:0;z-index:0;pointer-events:none;overflow:hidden}
.orb{position:absolute;border-radius:50%;filter:blur(72px);opacity:.3;animation:orbit 26s ease-in-out infinite}
.orb.o1{width:420px;height:420px;background:#22c55e;left:-130px;top:8vh}
.orb.o2{width:380px;height:380px;background:#ef4444;right:-150px;top:42vh;opacity:.18;animation-duration:32s;animation-delay:-8s}
.orb.o3{width:300px;height:300px;background:#38bdf8;left:42%;bottom:-130px;opacity:.16;animation-duration:38s;animation-delay:-14s}
@keyframes orbit{0%,100%{transform:translate3d(0,0,0)}50%{transform:translate3d(40px,-30px,0)}}
.fly{position:absolute;left:-12%;width:110px;height:2px;border-radius:2px;opacity:0;animation:fly 16s linear infinite}
.fly::after{content:"";position:absolute;right:-4px;top:-3px;width:8px;height:8px;border-radius:50%;box-shadow:0 0 12px 2px currentColor;background:currentColor}
.fly.f1{top:24vh;color:#22c55e;background:linear-gradient(90deg,transparent,#22c55e)}
.fly.f2{top:60vh;color:#ef4444;background:linear-gradient(90deg,transparent,#ef4444);animation-delay:-6s;animation-duration:20s}
.fly.f3{top:82vh;color:#38bdf8;background:linear-gradient(90deg,transparent,#38bdf8);animation-delay:-10s;animation-duration:24s}
@keyframes fly{0%{transform:translateX(0);opacity:0}8%{opacity:.85}92%{opacity:.85}100%{transform:translateX(130vw);opacity:0}}
.live{display:inline-flex;align-items:center;gap:7px;font-size:.78rem;font-weight:650;color:var(--muted);text-decoration:none;white-space:nowrap;padding:6px 11px;border:1px solid var(--line);border-radius:999px;background:var(--surface)}
a.live:hover{color:var(--ink);border-color:var(--crit)}
.led{display:inline-block;width:8px;height:8px;border-radius:50%;flex:none;animation:blink 2.4s ease-in-out infinite}
.led.g{background:#22c55e;box-shadow:0 0 10px #22c55e}
.led.r{background:#ef4444;box-shadow:0 0 10px #ef4444;animation-name:alarm}
@keyframes blink{50%{opacity:.35}}
@keyframes alarm{0%,100%{opacity:1}50%{opacity:.35}}
@media (max-width:900px){.live{display:none}}
.intro h1,.prose h1{background:linear-gradient(90deg,var(--ink) 40%,#38bdf8 75%,#22c55e);-webkit-background-clip:text;background-clip:text;color:transparent}
.card{position:relative;overflow:hidden}
.card::after{content:"";position:absolute;inset:0;pointer-events:none;background:linear-gradient(115deg,transparent 35%,rgba(56,189,248,.14) 50%,transparent 65%);transform:translateX(-100%);transition:transform .7s ease}
.card:hover::after{transform:translateX(100%)}
.support{position:relative;margin:40px 0 0;background:var(--surface);border:1px solid var(--line);border-radius:var(--r);padding:24px;overflow:hidden}
.support h2{margin:0 0 6px;font-size:1.2rem}
.donate-grid{display:flex;flex-wrap:wrap;gap:10px;margin:14px 0 0;padding:0;list-style:none}
.donate-btn{display:inline-flex;align-items:center;gap:8px;padding:10px 16px;border-radius:999px;border:1px solid var(--line);background:var(--surface-2);color:var(--ink);text-decoration:none;font-weight:650;font-size:.92rem}
.donate-btn:hover{border-color:#22c55e;box-shadow:0 0 18px rgba(34,197,94,.28)}
.banner{position:relative;z-index:1;border-bottom:1px solid var(--line);background:color-mix(in srgb,var(--surface) 80%,transparent)}
.banner-in{display:flex;align-items:center;gap:14px;min-height:40px;padding-top:6px;padding-bottom:6px}
.banner-tag{display:inline-flex;align-items:center;gap:8px;font-size:.72rem;font-weight:760;text-transform:uppercase;letter-spacing:.08em;color:var(--ink);white-space:nowrap}
.banner-text{margin:0;flex:1;min-width:0;font-size:.88rem;color:var(--muted);transition:opacity .25s ease;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.banner-pause{font:inherit;font-size:.74rem;font-weight:650;color:var(--muted);background:none;border:1px solid var(--line);border-radius:999px;padding:4px 10px;cursor:pointer;white-space:nowrap}
.banner-pause:hover{color:var(--ink);border-color:var(--accent)}
@media (max-width:640px){.banner-tag{display:none}}
.nav{-webkit-mask-image:linear-gradient(90deg,#000 88%,transparent);mask-image:linear-gradient(90deg,#000 88%,transparent);padding-right:28px}
.banner-action{display:inline-flex;align-items:center;gap:7px;font-size:.76rem;font-weight:700;color:var(--ink);text-decoration:none;border:1px solid color-mix(in srgb,#ef4444 50%,var(--line));border-radius:999px;padding:4px 11px;white-space:nowrap;background:color-mix(in srgb,#ef4444 10%,var(--surface))}
.banner-action:hover{box-shadow:0 0 16px rgba(239,68,68,.35)}
.fx-circuit{position:fixed;inset:0;width:100%;height:100%;z-index:0;opacity:.5}
.fx-circuit path{fill:none;stroke-width:1.2;stroke-dasharray:4 16;animation:flow 22s linear infinite}
.fx-circuit path.g{stroke:#22c55e}.fx-circuit path.r{stroke:#ef4444}.fx-circuit path.b{stroke:#38bdf8}
.fx-circuit circle{animation:node 3.2s ease-in-out infinite}
@keyframes flow{to{stroke-dashoffset:-400}}
@keyframes node{50%{opacity:.25}}
.hero{position:relative}
.hero::after{content:"";position:absolute;left:0;right:0;top:-120px;height:120px;pointer-events:none;background:linear-gradient(180deg,transparent,rgba(94,234,212,.10),transparent);animation:scan 7s linear infinite}
@keyframes scan{to{transform:translateY(calc(100% + 240px))}}
.card:hover{box-shadow:0 0 0 1px rgba(34,197,94,.35),0 16px 40px -14px rgba(56,189,248,.45)}
.card-media img{transition:transform .5s ease}
.card:hover .card-media img{transform:scale(1.04)}
.card-media{overflow:hidden}
@media (prefers-reduced-motion:reduce){.fx-circuit path,.fx-circuit circle,.hero::after{animation:none!important}.fx-circuit path{stroke-dasharray:none}.card-media img{transition:none}.card:hover .card-media img{transform:none}}
.progress{position:fixed;left:0;top:0;height:3px;width:100%;z-index:40;transform-origin:0 50%;transform:scaleX(0);background:linear-gradient(90deg,#22c55e,#38bdf8,#ef4444);box-shadow:0 0 12px rgba(56,189,248,.6);pointer-events:none}
.js .reveal{opacity:0;transform:translateY(14px);transition:opacity .6s ease,transform .6s ease}
.js .reveal.in{opacity:1;transform:none}
.card::before{content:"";position:absolute;inset:0;pointer-events:none;opacity:0;transition:opacity .3s ease;background:radial-gradient(260px circle at var(--mx,50%) var(--my,50%),rgba(94,234,212,.14),transparent 60%)}
.card:hover::before{opacity:1}
.dead{color:var(--crit);font-size:.85rem;font-weight:600}
.article-title{font-size:clamp(1.7rem,3.2vw,2.5rem);line-height:1.1;letter-spacing:-.025em;margin:0;font-weight:760;background:none;-webkit-text-fill-color:var(--ink)}
.article-hero .hero-body{justify-content:center}
.article-hero .hero-media img{aspect-ratio:16/9}
.intro .kicker{margin-bottom:6px}
@media (prefers-reduced-motion:reduce){.js .reveal{opacity:1;transform:none;transition:none}.progress{display:none}}
@media (prefers-reduced-motion:reduce){body::before,.orb,.fly,.led,.card::after{animation:none!important;transition:none!important}.fly,.card::after{display:none}}
"""
BANNER_JS = """(function(){
var msgs=["Feeds are checked every 20 minutes.","Every story links to its original source.","Patch Tuesday notes and weekly analysis are written by hand, not by AI.","Read the Today page for what needs action now.","Corrections are published openly."];
var el=document.getElementById('banner-text'),btn=document.getElementById('banner-pause');
if(!el||!btn)return;
var i=0,paused=false,reduce=window.matchMedia&&matchMedia('(prefers-reduced-motion: reduce)').matches;
function show(){el.style.opacity=0;setTimeout(function(){el.textContent=msgs[i];el.style.opacity=1;},250);}
var t=setInterval(function(){if(paused)return;i=(i+1)%msgs.length;show();},6000);
btn.addEventListener('click',function(){paused=!paused;btn.setAttribute('aria-pressed',String(paused));btn.textContent=paused?'Play':'Pause';btn.setAttribute('aria-label',paused?'Play banner':'Pause banner');});
if(reduce){paused=true;btn.setAttribute('aria-pressed','true');btn.textContent='Play';}
})();"""

DESIGN_CSS += FX_CSS


def write_site(out: Path, stories: list[dict], cfg: dict, now: datetime, status: dict,
               articles: list[dict] | None = None, site_cfg: dict | None = None) -> None:
    articles = articles or []
    site_cfg = site_cfg or {}
    (out / "story").mkdir(parents=True, exist_ok=True)
    # Story pages are kept even after a story leaves the 7-day window, so old links never 404.
    (out / "style.css").write_text(CSS.strip() + "\n" + EXTRA_CSS + "\n" + DESIGN_CSS, encoding="utf-8")
    (out / "favicon.svg").write_text(FAVICON_SVG, encoding="utf-8")
    # Optional root-level QR image: keep deployment simple for repository web uploads.
    import shutil
    qr_asset = ROOT / "buymeacoffee-qr.png"
    if qr_asset.is_file():
        shutil.copyfile(qr_asset, out / qr_asset.name)
    resource_pdf = ROOT / "m365-identity-incident-triage-checklist.pdf"
    if resource_pdf.is_file():
        shutil.copyfile(resource_pdf, out / resource_pdf.name)
    # Google Search Console HTML-file verification must be present at the public site root.
    verification_file = ROOT / "google06dce61680795c6c.html"
    if verification_file.is_file():
        shutil.copyfile(verification_file, out / verification_file.name)
    (out / "logo.svg").write_text(LOGO_SVG, encoding="utf-8")
    (out / "index.html").write_text(index_page(stories, cfg, now, status, articles, site_cfg), encoding="utf-8")
    (out / "today").mkdir(parents=True, exist_ok=True)
    (out / "today" / "index.html").write_text(today_page(stories, cfg, now), encoding="utf-8")
    (out / "saved").mkdir(parents=True, exist_ok=True)
    (out / "saved" / "index.html").write_text(saved_page(cfg), encoding="utf-8")
    (out / "stories.json").write_text(stories_index(stories), encoding="utf-8")
    for s in stories:
        (out / "story" / f"{s['id']}.html").write_text(story_page(s, cfg), encoding="utf-8")
    (out / "stories").mkdir(parents=True, exist_ok=True)
    (out / "stories" / "index.html").write_text(
        listing_page(stories, cfg, "../", "All stories",
                     f"{len(stories)} stories in the current window, ranked by priority. Every story links to its original source."),
        encoding="utf-8")
    for cid in CATEGORY_ORDER:
        subset = [s for s in stories if s["category"] == cid]
        d = out / "category" / cid
        d.mkdir(parents=True, exist_ok=True)
        (d / "index.html").write_text(
            listing_page(subset, cfg, "../../", CATEGORIES[cid][0],
                         f"{len(subset)} stories in this category. Use the chips to narrow by topic."),
            encoding="utf-8")
    for sec in SECTIONS:
        sec_articles = [a for a in articles if a["section"] == sec]
        d = out / sec
        d.mkdir(parents=True, exist_ok=True)
        wanted = {f"{a['slug']}.html" for a in sec_articles} | {"index.html"}
        for f in d.glob("*.html"):
            if f.name not in wanted:
                f.unlink()
        (d / "index.html").write_text(
            section_page(sec, sec_articles, cfg, site_cfg,
                         cve_rows=msrc_cve_rows(stories) if sec == "patch-tuesday" else None),
            encoding="utf-8")
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

LINK_CACHE_DAYS = 7
DEAD_CODES = {404, 410}


def _probe(url: str, timeout: int = 8) -> str:
    """'ok', 'dead' (404/410 from the publisher) or 'unverified' (blocked, slow or unreachable)."""
    for method in ("HEAD", "GET"):
        try:
            req = urllib.request.Request(url, method=method, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return "ok" if r.status < 400 else "unverified"
        except urllib.error.HTTPError as e:
            if e.code in DEAD_CODES:
                return "dead"
            if e.code in (403, 405, 429):
                continue
            return "unverified"
        except Exception:
            return "unverified"
    return "unverified"


def check_source_links(stories: list[dict], cache_path: Path, now: datetime, budget: int = 40) -> None:
    """Checks each original source link at most once a week, a few per run, and stores the result."""
    cache = json.loads(cache_path.read_text(encoding="utf-8")) if cache_path.exists() else {}
    checked = 0
    for s in stories:
        for x in s.get("sources", []):
            url = x.get("url", "")
            entry = cache.get(url)
            fresh = bool(entry) and (now - datetime.fromisoformat(entry["at"])).days < LINK_CACHE_DAYS
            if not fresh and checked < budget:
                cache[url] = {"status": _probe(url), "at": now.isoformat()}
                checked += 1
            x["link_status"] = (cache.get(url) or {}).get("status", "unchecked")
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(json.dumps(cache, indent=1, sort_keys=True), encoding="utf-8")


def run(cfg: dict, out: Path, data_file: Path, fixtures: Path | None, now: datetime,
        site_cfg: dict | None = None, content_dir: Path | None = None) -> dict:
    site_cfg = site_cfg or {}
    content_dir = content_dir or CONTENT_DIR
    fresh: list[dict] = []
    src_status: list[dict] = []
    previous_status_file = out / "status.json"
    try:
        previous_status = json.loads(previous_status_file.read_text(encoding="utf-8")) if previous_status_file.exists() else {}
        source_health = {entry.get("id"): entry.get("last_success_at")
                         for entry in previous_status.get("sources", []) if entry.get("id") and entry.get("last_success_at")}
    except (OSError, json.JSONDecodeError):
        source_health = {}
    for src in cfg["sources"]:
        try:
            data = (fixtures / f"{src['id']}.xml").read_bytes() if fixtures else fetch(src["url"])
            if not re.search(rb"<(rss|feed|rdf)", data[:2000], re.I):
                raise RuntimeError("response is not an RSS/Atom feed")
            items = parse_feed(data, src)
            if src.get("require_security"):  # broad vendor blogs: keep security posts only
                items = [i for i in items if is_security_item(i)]
            items = items[: cfg.get("max_items_per_feed", 30)]
            fresh += items
            last_success = now.isoformat(timespec="seconds")
            source_health[src["id"]] = last_success
            src_status.append({"id": src["id"], "name": src["name"], "ok": True, "count": len(items),
                               "last_attempt_at": now.isoformat(timespec="seconds"), "last_success_at": last_success})
        except Exception as e:  # noqa: BLE001 - one bad feed must not stop the run
            src_status.append({"id": src["id"], "name": src["name"], "ok": False, "count": 0,
                               "error": str(e)[:200], "last_attempt_at": now.isoformat(timespec="seconds"),
                               "last_success_at": source_health.get(src["id"])})

    kev, kev_err = load_kev(fixtures)
    kev_checked = kev_err is None

    stored = json.loads(data_file.read_text(encoding="utf-8"))["items"] if data_file.exists() else []
    items = merge(stored, fresh, now, cfg.get("retention_days", 7))
    if fixtures is None:  # live runs only; offline tests never touch the network
        enrich_images(items)
        enrich_instructions(items)
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
        "last_check_at": now.isoformat(timespec="seconds"),
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

    # Static story pages change only when content changes. status.json is
    # refreshed every run below so the feed-check timestamp never goes stale.
    digest_src = json.dumps({
        "stories": [[s["id"], s["title"], s["summary"], s["published"], s["category"], s["priority"],
                     s["score"], s["image"], [x["url"] for x in s["sources"]]] for s in stories],
        "articles": [[a["section"], a["slug"], a["title"], a["date"], a["summary"], a["_md"]] for a in articles],
        "site": site_cfg,
        "render": "5.29",  # bump when the HTML/CSS/JS output changes, so the site rebuilds
    }, ensure_ascii=False, sort_keys=True)
    if fixtures is None:
        check_source_links(stories, data_file.parent / "linkcheck.json", now)
    digest = hashlib.sha1(digest_src.encode("utf-8")).hexdigest()
    digest_file = data_file.parent / "digest.txt"
    prev_digest = digest_file.read_text(encoding="utf-8").strip() if digest_file.exists() else ""
    site_missing = not (out / "index.html").exists()
    status["changed"] = digest != prev_digest or site_missing
    publication_file = data_file.parent / "content-publication.json"
    try:
        publication_state = json.loads(publication_file.read_text(encoding="utf-8")) if publication_file.exists() else {}
    except (OSError, json.JSONDecodeError):
        publication_state = {}
    content_published_at = publication_state.get("content_published_at")
    if status["changed"] or not content_published_at:
        content_published_at = now.isoformat(timespec="seconds")
        publication_state = {"digest": digest, "content_published_at": content_published_at}
        data_file.parent.mkdir(parents=True, exist_ok=True)
        publication_file.write_text(json.dumps(publication_state, indent=2) + "\n", encoding="utf-8")
    status["content_published_at"] = content_published_at
    data_file.parent.mkdir(parents=True, exist_ok=True)
    if status["changed"]:
        data_file.write_text(items_text, encoding="utf-8")
        digest_file.write_text(digest + "\n", encoding="utf-8")
        write_site(out, stories, cfg, now, status, articles, site_cfg)
    elif not data_file.exists() or data_file.read_text(encoding="utf-8") != items_text:
        data_file.write_text(items_text, encoding="utf-8")
    # Keep feed status fresh even when the story/content digest did not change.
    out.mkdir(parents=True, exist_ok=True)
    (out / "status.json").write_text(json.dumps(status, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
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
