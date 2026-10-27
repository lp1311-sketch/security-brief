import { describe, expect, it } from "vitest";
import { clusterItems, HIGH_PRIORITY_THRESHOLD, priorityFor } from "@/lib/news/rank";
import { normalizeUrl } from "@/lib/news/parse";
import type { FeedItem } from "@/lib/news/types";

const item = (o: Partial<FeedItem>): FeedItem => ({
  id: o.link ?? "https://x.test/a", title: "t", link: "https://x.test/a", sourceId: "a", sourceName: "A",
  official: false, publishedAt: new Date().toISOString(), retrievedAt: new Date().toISOString(), excerpt: "", cves: [], ...o,
});

describe("priority rules", () => {
  it("Critical when a CVE is in CISA KEV", () => {
    expect(priorityFor({ kevCves: ["CVE-2024-1"], officialExploit: false, score: 0 })).toBe("Critical");
  });
  it("Critical when an official source reports exploitation", () => {
    expect(priorityFor({ kevCves: [], officialExploit: true, score: 0 })).toBe("Critical");
  });
  it("High Priority at the threshold, Standard below, never Critical from score alone", () => {
    expect(priorityFor({ kevCves: [], officialExploit: false, score: HIGH_PRIORITY_THRESHOLD })).toBe("High Priority");
    expect(priorityFor({ kevCves: [], officialExploit: false, score: HIGH_PRIORITY_THRESHOLD - 1 })).toBe("Standard");
    expect(priorityFor({ kevCves: [], officialExploit: false, score: 999 })).toBe("High Priority");
  });
});

describe("dedupe and clustering", () => {
  it("strips tracking params and www when normalizing", () => {
    expect(normalizeUrl("http://www.Ex.com/a/?utm_source=rss#x")).toBe("https://ex.com/a");
  });
  it("groups reports sharing a CVE from different sources", () => {
    const c = clusterItems([
      item({ link: "https://a.test/1", title: "Fortinet patches flaw", cves: ["CVE-2025-1111"] }),
      item({ link: "https://b.test/2", sourceId: "b", title: "Hackers abuse bug", cves: ["CVE-2025-1111"] }),
    ], new Set(["CVE-2025-1111"]));
    expect(c).toHaveLength(1);
    expect(c[0]?.priority).toBe("Critical");
  });
});
