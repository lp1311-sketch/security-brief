import type { CategoryId, Cluster, FeedItem, Priority } from "./types";

/**
 * Transparent editorial scoring. Every point awarded is recorded as a reason
 * shown to readers. Popularity is NOT used: RSS feeds carry no reliable view data.
 * CVSS is NOT used: feeds do not carry verified scores, and we never guess one.
 */
export const WEIGHTS = {
  kevConfirmed: 40,
  exploitationReported: 20,
  officialSource: 15,
  ransomwareOrBreach: 12,
  microsoft: 10,
  enterpriseProduct: 8,
  cloudIdentity: 8,
  cveReferenced: 5,
  perExtraSource: 8,
  maxMultiSource: 24,
  recency24h: 15,
  recency72h: 8,
} as const;

export const HIGH_PRIORITY_THRESHOLD = 45;

const RX = {
  exploit: /actively exploited|exploited in the wild|under active exploitation|zero[- ]day|0-day|exploitation (?:of|attempts)|being exploited/i,
  confirmedExploit: /actively exploited|exploited in the wild|under active exploitation|being exploited|known exploited/i,
  ransom: /ransomware|data breach|breach(?:ed)?|leak(?:ed)? data|extortion|stolen data/i,
  malware: /malware|botnet|trojan|infostealer|stealer|backdoor|rootkit|spyware|wiper|loader/i,
  microsoft: /microsoft|windows|entra|azure|exchange|sharepoint|office 365|microsoft 365|m365|outlook|teams|defender|patch tuesday|active directory/i,
  enterprise: /fortinet|fortigate|cisco|ivanti|citrix|netscaler|vmware|palo alto|sonicwall|juniper|f5 big-ip|oracle|sap\b|atlassian|confluence|jira|veeam|okta|crowdstrike/i,
  cloud: /cloud|aws|gcp|google cloud|kubernetes|identity|oauth|sso|mfa|token|entra|okta|saml|iam\b|credential/i,
  ai: /\bai\b|artificial intelligence|llm|chatgpt|gemini|copilot|machine learning|prompt injection|deepfake|genai|model/i,
  vuln: /vulnerabilit|cve-|patch|flaw|bug|advisory|exploit|rce|remote code/i,
};

const text = (items: FeedItem[]) => items.map((i) => `${i.title} ${i.excerpt}`).join(" ");

export function categorize(items: FeedItem[]): CategoryId[] {
  const t = text(items);
  const cats: CategoryId[] = [];
  if (RX.vuln.test(t) || items.some((i) => i.cves.length)) cats.push("vulnerabilities");
  if (RX.microsoft.test(t) || RX.enterprise.test(t) || items.some((i) => i.sourceId === "msrc")) cats.push("microsoft");
  if (RX.ransom.test(t) || RX.malware.test(t)) cats.push("threats");
  if (RX.cloud.test(t) || items.some((i) => i.sourceId === "google-cloud")) cats.push("cloud");
  if (RX.ai.test(t)) cats.push("ai");
  if (!cats.length) cats.push("general");
  return cats;
}

export interface ScoreResult {
  score: number;
  priority: Priority;
  reasons: string[];
  kevCves: string[];
}

export function scoreCluster(items: FeedItem[], kev: Set<string>, now = Date.now()): ScoreResult {
  const t = text(items);
  const reasons: string[] = [];
  let score = 0;
  const add = (pts: number, why: string) => {
    score += pts;
    reasons.push(`+${pts} ${why}`);
  };

  const cves = [...new Set(items.flatMap((i) => i.cves))];
  const kevCves = cves.filter((c) => kev.has(c));
  const officialItems = items.filter((i) => i.official);
  const exploitReported = RX.exploit.test(t);

  if (kevCves.length) add(WEIGHTS.kevConfirmed, `Exploitation confirmed in CISA KEV (${kevCves.join(", ")})`);
  if (exploitReported) add(WEIGHTS.exploitationReported, "Sources report exploitation or a zero-day");
  if (officialItems.length) add(WEIGHTS.officialSource, "Official advisory or vendor publication");
  if (RX.ransom.test(t)) add(WEIGHTS.ransomwareOrBreach, "Ransomware, extortion or data breach");
  if (RX.microsoft.test(t)) add(WEIGHTS.microsoft, "Microsoft / Windows / identity relevance");
  if (RX.enterprise.test(t)) add(WEIGHTS.enterpriseProduct, "Widely deployed enterprise product");
  if (RX.cloud.test(t)) add(WEIGHTS.cloudIdentity, "Cloud or identity relevance");
  if (cves.length) add(WEIGHTS.cveReferenced, `References ${cves.length} CVE identifier(s)`);

  const sources = new Set(items.map((i) => i.sourceId)).size;
  if (sources > 1)
    add(Math.min(WEIGHTS.maxMultiSource, (sources - 1) * WEIGHTS.perExtraSource), `Reported by ${sources} independent sources`);

  const newest = Math.max(...items.map((i) => (i.publishedAt ? Date.parse(i.publishedAt) : 0)));
  const ageH = newest ? (now - newest) / 36e5 : Infinity;
  if (ageH <= 24) add(WEIGHTS.recency24h, "Published within 24 hours");
  else if (ageH <= 72) add(WEIGHTS.recency72h, "Published within 72 hours");

  return { score, priority: priorityFor({ kevCves, officialExploit: officialItems.some((i) => RX.confirmedExploit.test(`${i.title} ${i.excerpt}`)), score }), reasons, kevCves };
}

/**
 * Documented label criteria:
 *  Critical      — a referenced CVE is listed in CISA's Known Exploited Vulnerabilities
 *                  catalog, OR an official source (CISA, MSRC, Google) itself reports exploitation.
 *  High Priority — score >= HIGH_PRIORITY_THRESHOLD.
 *  Standard      — everything else.
 */
export function priorityFor(p: { kevCves: string[]; officialExploit: boolean; score: number }): Priority {
  if (p.kevCves.length > 0 || p.officialExploit) return "Critical";
  if (p.score >= HIGH_PRIORITY_THRESHOLD) return "High Priority";
  return "Standard";
}

// ---------- clustering ----------
const STOP = new Set("a an the and or of to in on for with by from as at is are was be new now via after over its it this that how why what more than says report reports update updates security hackers hacker attack attacks".split(" "));
const tokens = (s: string) =>
  new Set(s.toLowerCase().replace(/[^a-z0-9\- ]/g, " ").split(/\s+/).filter((w) => w.length > 2 && !STOP.has(w)));

export function similarity(a: string, b: string): number {
  const A = tokens(a), B = tokens(b);
  if (!A.size || !B.size) return 0;
  let inter = 0;
  A.forEach((w) => B.has(w) && inter++);
  return inter / (A.size + B.size - inter);
}

const WINDOW = 4 * 864e5;

export function clusterItems(items: FeedItem[], kev: Set<string>, now = Date.now()): Cluster[] {
  // dedupe by normalized URL first
  const unique = [...new Map(items.map((i) => [i.id, i])).values()];
  unique.sort((a, b) => (b.publishedAt ?? "").localeCompare(a.publishedAt ?? ""));
  const groups: FeedItem[][] = [];
  for (const it of unique) {
    const t = it.publishedAt ? Date.parse(it.publishedAt) : now;
    const g = groups.find((grp) =>
      grp.some((o) => {
        const ot = o.publishedAt ? Date.parse(o.publishedAt) : now;
        if (Math.abs(ot - t) > WINDOW) return false;
        if (it.cves.length && it.cves.some((c) => o.cves.includes(c))) return true;
        return similarity(it.title, o.title) >= 0.45;
      }),
    );
    if (g) g.push(it);
    else groups.push([it]);
  }
  return groups.map((grp) => {
    const lead = grp.find((i) => i.official) ?? grp[0]!;
    const s = scoreCluster(grp, kev, now);
    const newest = grp.map((i) => i.publishedAt).filter(Boolean).sort().at(-1) ?? null;
    return {
      id: hashId(grp[grp.length - 1]!.id),
      title: lead.title,
      items: grp,
      categories: categorize(grp),
      cves: [...new Set(grp.flatMap((i) => i.cves))],
      kevCves: s.kevCves,
      score: s.score,
      priority: s.priority,
      reasons: s.reasons,
      publishedAt: newest,
      summary: (grp.find((i) => i.excerpt) ?? lead).excerpt,
    };
  });
}

export function hashId(s: string): string {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) h = Math.imul(h ^ s.charCodeAt(i), 16777619);
  return (h >>> 0).toString(36);
}
