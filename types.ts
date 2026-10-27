export type CategoryId = "microsoft" | "vulnerabilities" | "threats" | "cloud" | "ai" | "general";

export interface Source {
  id: string;
  name: string;
  url: string; // feed URL
  site: string;
  official: boolean; // vendor / government advisory publisher
}

export interface FeedItem {
  id: string; // normalized URL
  title: string;
  link: string;
  sourceId: string;
  sourceName: string;
  official: boolean;
  publishedAt: string | null; // as stated by the source; null if the feed omitted it
  retrievedAt: string;
  excerpt: string;
  cves: string[];
}

export type Priority = "Critical" | "High Priority" | "Standard";

export interface Cluster {
  id: string;
  title: string;
  items: FeedItem[];
  categories: CategoryId[];
  cves: string[];
  kevCves: string[];
  score: number;
  priority: Priority;
  reasons: string[];
  publishedAt: string | null;
  summary: string;
}

export interface SourceStatus {
  id: string;
  name: string;
  ok: boolean;
  count: number;
  error?: string;
}

export interface NewsSnapshot {
  clusters: Cluster[];
  sources: SourceStatus[];
  kevLoaded: boolean;
  fetchedAt: string;
}
