import { parseFeed } from "./parse";
import type { Source } from "./types";

export const MICROSOFT_ROADMAP_URL = "https://www.microsoft.com/releasecommunications/api/v2/M365/rss";
export const MICROSOFT_ROADMAP_PAGE = "https://www.microsoft.com/microsoft-365/roadmap";
export const MESSAGE_CENTER_DOCS = "https://learn.microsoft.com/en-us/microsoft-365/admin/manage/message-center?view=o365-worldwide";
export const GRAPH_SERVICE_COMMUNICATIONS_DOCS = "https://learn.microsoft.com/en-us/graph/service-communications-concept-overview";

const roadmapSource: Source = {
  id: "microsoft-365-roadmap",
  name: "Microsoft 365 Roadmap (public)",
  url: MICROSOFT_ROADMAP_URL,
  site: MICROSOFT_ROADMAP_PAGE,
  official: true,
};

export const CHANGE_PRODUCTS = [
  "Teams", "Exchange", "SharePoint", "OneDrive", "Entra ID", "Intune",
  "Defender", "Purview", "Copilot", "Outlook", "Microsoft 365 Apps", "Microsoft 365",
] as const;
export type ChangeProduct = (typeof CHANGE_PRODUCTS)[number];
export type RoadmapStage = "Preview" | "In development" | "Rolling out" | "Generally available" | "Launched";

export interface ChangeUpdate {
  id: string;
  title: string;
  link: string;
  summary: string;
  feedDate: string | null;
  products: ChangeProduct[];
  stage: RoadmapStage | null;
  featureId: string | null;
}

export interface ChangeRadarSnapshot {
  updates: ChangeUpdate[];
  fetchedAt: string;
  ok: boolean;
  error?: string;
}

function productsIn(text: string): ChangeProduct[] {
  const checks: [ChangeProduct, RegExp][] = [
    ["Teams", /\bteams\b/i],
    ["Exchange", /\bexchange\b/i],
    ["SharePoint", /\bsharepoint\b/i],
    ["OneDrive", /\bonedrive\b/i],
    ["Entra ID", /\bentra\b|azure active directory/i],
    ["Intune", /\bintune\b/i],
    ["Defender", /\bdefender\b/i],
    ["Purview", /\bpurview\b/i],
    ["Copilot", /\bcopilot\b/i],
    ["Outlook", /\boutlook\b/i],
    ["Microsoft 365 Apps", /microsoft 365 apps|office apps/i],
  ];
  const found = checks.filter(([, pattern]) => pattern.test(text)).map(([name]) => name);
  return found.length ? found : ["Microsoft 365"];
}

function stageIn(text: string): RoadmapStage | null {
  // Only show a stage when the public feed text explicitly says one.
  if (/\brolling out\b|\brollout in progress\b/i.test(text)) return "Rolling out";
  if (/\b(in development|under development)\b/i.test(text)) return "In development";
  if (/\b(generally available|general availability)\b/i.test(text)) return "Generally available";
  if (/\blaunched\b|\bavailable to all customers\b/i.test(text)) return "Launched";
  if (/\b(public preview|preview available|in preview)\b/i.test(text)) return "Preview";
  return null;
}

function featureIdFrom(link: string, text: string): string | null {
  try {
    const url = new URL(link);
    const queryId = url.searchParams.get("featureid") ?? url.searchParams.get("featureId");
    if (queryId && /^\d{4,8}$/.test(queryId)) return queryId;
  } catch {
    // The feed parser already restricts links to HTTP(S); this is only defensive.
  }
  return text.match(/\bfeature\s*(?:id|#)\s*[:#]?\s*(\d{4,8})\b/i)?.[1] ?? null;
}

export function parseChangeFeed(xml: string, fetchedAt: string): ChangeRadarSnapshot {
  if (!/<(rss|feed|rdf)\b/i.test(xml)) {
    throw new Error("Microsoft endpoint did not return an RSS/Atom feed");
  }
  const entries = parseFeed(xml, roadmapSource, fetchedAt);
  const updates = entries.map((entry): ChangeUpdate => {
    const text = `${entry.title} ${entry.excerpt}`;
    return {
      id: entry.id,
      title: entry.title,
      link: entry.link,
      summary: entry.excerpt,
      feedDate: entry.publishedAt,
      products: productsIn(text),
      stage: stageIn(text),
      featureId: featureIdFrom(entry.link, text),
    };
  }).sort((a, b) => (b.feedDate ?? "").localeCompare(a.feedDate ?? ""));
  return { updates, fetchedAt, ok: true };
}

export async function loadChangeRadar(): Promise<ChangeRadarSnapshot> {
  const fetchedAt = new Date().toISOString();
  try {
    const response = await fetch(MICROSOFT_ROADMAP_URL, {
      headers: {
        "user-agent": "CyberBrief/1.0 (+public Microsoft roadmap RSS reader)",
        accept: "application/rss+xml, application/atom+xml, application/xml, text/xml",
      },
      signal: AbortSignal.timeout(10000),
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return parseChangeFeed(await response.text(), fetchedAt);
  } catch (error) {
    return {
      updates: [],
      fetchedAt,
      ok: false,
      error: error instanceof Error ? error.message : "Feed request failed",
    };
  }
}
