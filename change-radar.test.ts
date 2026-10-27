import { describe, expect, it } from "vitest";
import { parseChangeFeed } from "@/lib/news/change-radar";

const fetchedAt = "2026-01-01T12:00:00.000Z";

describe("Microsoft public roadmap feed parsing", () => {
  it("extracts an explicit product, stage and feature ID from a public feed entry", () => {
    const xml = `<?xml version="1.0"?><rss><channel><item>
      <title>New Microsoft Teams meeting feature</title>
      <link>https://www.microsoft.com/microsoft-365/roadmap?featureid=123456</link>
      <description><![CDATA[Teams feature is rolling out to tenants.]]></description>
      <pubDate>Thu, 01 Jan 2026 10:00:00 GMT</pubDate>
    </item></channel></rss>`;
    const snapshot = parseChangeFeed(xml, fetchedAt);
    expect(snapshot.ok).toBe(true);
    expect(snapshot.updates).toHaveLength(1);
    expect(snapshot.updates[0]?.products).toContain("Teams");
    expect(snapshot.updates[0]?.stage).toBe("Rolling out");
    expect(snapshot.updates[0]?.featureId).toBe("123456");
  });

  it("does not invent a stage when the feed omits one", () => {
    const xml = `<rss><channel><item>
      <title>Microsoft 365 admin experience update</title>
      <link>https://www.microsoft.com/microsoft-365/roadmap</link>
      <description>Updated admin experience for Microsoft 365.</description>
    </item></channel></rss>`;
    expect(parseChangeFeed(xml, fetchedAt).updates[0]?.stage).toBeNull();
  });

  it("rejects a non-feed response", () => {
    expect(() => parseChangeFeed("not xml", fetchedAt)).toThrow("RSS/Atom feed");
  });
});
