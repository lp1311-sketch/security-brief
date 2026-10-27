import type { FeedItem, Source } from "./types";

const ENTITIES: Record<string, string> = {
  amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " ", "#39": "'",
  rsquo: "’", lsquo: "‘", rdquo: "”", ldquo: "“", hellip: "…", ndash: "–", mdash: "—",
};

export function decode(s: string): string {
  return s
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1")
    .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(Number(d)))
    .replace(/&([a-z0-9#]+);/gi, (m, e) => ENTITIES[e.toLowerCase()] ?? m);
}

export function stripHtml(s: string): string {
  return decode(decode(s))
    .replace(/<script[\s\S]*?<\/script>|<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

export function normalizeUrl(u: string): string {
  try {
    const url = new URL(u.trim());
    url.hash = "";
    url.hostname = url.hostname.toLowerCase().replace(/^www\./, "");
    [...url.searchParams.keys()].forEach((k) => {
      if (/^(utm_|fbclid|gclid|ref$|source$)/i.test(k)) url.searchParams.delete(k);
    });
    url.protocol = "https:";
    return url.toString().replace(/\/$/, "");
  } catch {
    return u.trim();
  }
}

export function extractCves(text: string): string[] {
  const m = text.toUpperCase().match(/CVE-\d{4}-\d{4,7}/g) ?? [];
  return [...new Set(m)];
}

function tag(block: string, names: string[]): string {
  for (const n of names) {
    const m = block.match(new RegExp(`<${n}(?:\\s[^>]*)?>([\\s\\S]*?)</${n}>`, "i"));
    if (m) return m[1] ?? "";
  }
  return "";
}

function atomLink(block: string): string {
  const links = [...block.matchAll(/<link\b([^>]*)\/?>/gi)].map((m) => m[1] ?? "");
  const pick = links.find((a) => /rel=["']alternate["']/.test(a)) ?? links.find((a) => !/rel=/.test(a)) ?? links[0];
  return pick?.match(/href=["']([^"']+)["']/)?.[1] ?? "";
}

function toIso(s: string): string | null {
  if (!s) return null;
  const d = new Date(decode(s).trim());
  return isNaN(d.getTime()) ? null : d.toISOString();
}

export function excerpt(text: string, max = 280): string {
  if (text.length <= max) return text;
  const cut = text.slice(0, max);
  return cut.slice(0, cut.lastIndexOf(" ")).replace(/[,;:.\s]+$/, "") + "…";
}

/** Minimal RSS 2.0 / Atom parser — no DOM required, runs in Workers and Node. */
export function parseFeed(xml: string, source: Source, retrievedAt: string): FeedItem[] {
  const blocks = [...xml.matchAll(/<(item|entry)\b[\s\S]*?<\/\1>/gi)].map((m) => m[0]);
  const out: FeedItem[] = [];
  for (const b of blocks) {
    const title = stripHtml(tag(b, ["title"]));
    let link = stripHtml(tag(b, ["link"]));
    if (!/^https?:/i.test(link)) link = atomLink(b);
    if (!/^https?:/i.test(link)) link = stripHtml(tag(b, ["guid", "id"]));
    if (!title || !/^https?:/i.test(link)) continue;
    const body = stripHtml(tag(b, ["description", "summary", "content:encoded", "content"]));
    const ex = excerpt(body.replace(/The post .* appeared first on .*$/i, "").trim());
    out.push({
      id: normalizeUrl(link),
      title,
      link,
      sourceId: source.id,
      sourceName: source.name,
      official: source.official,
      publishedAt: toIso(tag(b, ["pubDate", "published", "dc:date", "updated"])),
      retrievedAt,
      excerpt: ex,
      cves: extractCves(`${title} ${body}`),
    });
  }
  return out;
}
