import { parseFeed } from "./parse";
import { clusterItems } from "./rank";
import { KEV_URL, SOURCES } from "./sources";
import type { FeedItem, NewsSnapshot, SourceStatus } from "./types";

const UA = "CyberBriefBot/1.0 (+RSS reader; respects feed syndication)";

async function fetchText(url: string, attempts = 2): Promise<string> {
  let last: unknown;
  for (let i = 0; i < attempts; i++) {
    try {
      const res = await fetch(url, {
        headers: { "user-agent": UA, accept: "application/rss+xml, application/atom+xml, application/xml, text/xml, application/json" },
        signal: AbortSignal.timeout(10000),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.text();
    } catch (e) {
      last = e;
    }
  }
  throw last;
}

export async function loadKev(): Promise<Set<string>> {
  const json = JSON.parse(await fetchText(KEV_URL)) as { vulnerabilities?: { cveID: string }[] };
  return new Set((json.vulnerabilities ?? []).map((v) => v.cveID.toUpperCase()));
}

export async function runPipeline(): Promise<NewsSnapshot> {
  const retrievedAt = new Date().toISOString();
  const [kevRes, ...feedRes] = await Promise.allSettled([
    loadKev(),
    ...SOURCES.map(async (s) => {
      const xml = await fetchText(s.url);
      if (!/<(rss|feed|rdf)/i.test(xml)) throw new Error("Response is not a feed");
      return parseFeed(xml, s, retrievedAt);
    }),
  ]);
  const items: FeedItem[] = [];
  const sources: SourceStatus[] = SOURCES.map((s, i) => {
    const r = feedRes[i]!;
    if (r.status === "fulfilled") {
      items.push(...r.value.slice(0, s.id === "msrc" ? 15 : 40));
      return { id: s.id, name: s.name, ok: true, count: r.value.length };
    }
    return { id: s.id, name: s.name, ok: false, count: 0, error: String(((r as PromiseRejectedResult).reason as Error)?.message ?? r.reason) };
  });
  const kev = kevRes.status === "fulfilled" ? kevRes.value : new Set<string>();
  const clusters = clusterItems(items, kev).sort(
    (a, b) => (b.publishedAt ?? "").localeCompare(a.publishedAt ?? ""),
  );
  return { clusters, sources, kevLoaded: kevRes.status === "fulfilled", fetchedAt: retrievedAt };
}
