import { createFileRoute } from "@tanstack/react-router";
import { useSuspenseQuery } from "@tanstack/react-query";
import { newsQuery } from "@/lib/news/news.functions";
import { HIGH_PRIORITY_THRESHOLD, WEIGHTS } from "@/lib/news/rank";
import { SOURCES } from "@/lib/news/sources";

export const Route = createFileRoute("/methodology")({
  head: () => ({
    meta: [
      { title: "Methodology & sources — CyberBrief" },
      { name: "description", content: "How CyberBrief collects feeds, clusters reports, scores priority and builds briefings — plus live feed status." },
      { property: "og:title", content: "Methodology & sources — CyberBrief" },
      { property: "og:description", content: "Transparent ranking criteria, sources and automation status." },
    ],
  }),
  loader: ({ context }) => context.queryClient.ensureQueryData(newsQuery),
  component: Methodology,
});

const W: [string, string][] = [
  ["CVE listed in CISA KEV (confirmed exploitation)", `+${WEIGHTS.kevConfirmed}`],
  ["Sources report exploitation / zero-day", `+${WEIGHTS.exploitationReported}`],
  ["Official advisory or vendor publisher", `+${WEIGHTS.officialSource}`],
  ["Ransomware, extortion or breach", `+${WEIGHTS.ransomwareOrBreach}`],
  ["Microsoft / Windows / Entra relevance", `+${WEIGHTS.microsoft}`],
  ["Widely deployed enterprise product", `+${WEIGHTS.enterpriseProduct}`],
  ["Cloud or identity relevance", `+${WEIGHTS.cloudIdentity}`],
  ["CVE identifier referenced", `+${WEIGHTS.cveReferenced}`],
  ["Each additional independent source", `+${WEIGHTS.perExtraSource} (max ${WEIGHTS.maxMultiSource})`],
  ["Published within 24 h / 72 h", `+${WEIGHTS.recency24h} / +${WEIGHTS.recency72h}`],
];

function Methodology() {
  const { data } = useSuspenseQuery(newsQuery);
  return (
    <div className="prose-brief mx-auto max-w-3xl px-4 py-12 sm:px-6">
      <h1 className="text-4xl md:text-5xl">Methodology</h1>
      <p className="mt-4 text-muted-foreground">CyberBrief reads public RSS/Atom feeds only. It never scrapes full articles, bypasses paywalls or evades bot protection.</p>

      <h2>Priority labels</h2>
      <p><strong className="text-critical">Critical</strong> — a referenced CVE appears in CISA's Known Exploited Vulnerabilities catalog, or an official publisher (CISA, Microsoft, Google) itself states the flaw is actively exploited or exploited in the wild.</p>
      <p><strong className="text-high">High Priority</strong> — score of {HIGH_PRIORITY_THRESHOLD} or more. <strong>Standard</strong> — everything else.</p>
      <table className="w-full text-sm">
        <tbody>{W.map(([k, v]) => <tr key={k} className="border-b"><td className="py-2">{k}</td><td className="py-2 text-right font-mono">{v}</td></tr>)}</tbody>
      </table>
      <p className="text-sm text-muted-foreground">Not used: popularity (feeds have no reliable view counts) and CVSS (not verified in feeds; we don't guess).</p>

      <h2>Clustering & deduplication</h2>
      <p>Links are normalized (tracking parameters removed). Reports within four days are grouped when they share a CVE ID or have strongly overlapping headline terms.</p>

      <h2>Briefings</h2>
      <p>Every story page is a structured briefing built without an AI model: source extracts in quotes, derived signals, and defensive steps linked to authoritative references. AI-written drafts are optional and require a free local model (see the repository README); they are saved as drafts, never auto-published.</p>

      <h2>Live feed status</h2>
      <p className="text-sm text-muted-foreground">Last retrieved {new Date(data.fetchedAt).toLocaleString("en-GB")}. CISA KEV catalog: {data.kevLoaded ? "loaded" : "unavailable this run"}.</p>
      <ul className="space-y-1 text-sm">
        {data.sources.map((s) => {
          const src = SOURCES.find((x) => x.id === s.id)!;
          return (
            <li key={s.id} className="flex justify-between border-b py-2">
              <a href={src.site} target="_blank" rel="noopener noreferrer">{s.name}</a>
              <span className={`font-mono ${s.ok ? "text-muted-foreground" : "text-critical"}`}>{s.ok ? `${s.count} items` : `failed: ${s.error}`}</span>
            </li>
          );
        })}
      </ul>

      <h2>Microsoft 365 Change Radar</h2>
      <p>The Change Radar is a separate section backed by Microsoft's public roadmap RSS feed. It is not merged into cybersecurity news, and it does not claim that a planned feature is active in a specific tenant. Microsoft documents roadmap status, cloud instance and rollout information as planning data that can change.</p>
      <p>Tenant-specific Message Center posts and service-health data are not public RSS content. They are available through Microsoft 365 admin experiences and the Microsoft Graph service communications API with tenant authentication and permissions; this build does not connect to Graph.</p>

      <h2>Automation status</h2>
      <p>The website refreshes feeds on demand (cached ~20 minutes), so it works without any scheduler. A morning/evening GitHub Actions workflow for logs and AI drafts is included but is <strong>not active</strong> until the code is pushed to a GitHub repository with Actions enabled. GitHub may delay scheduled runs at busy times.</p>
    </div>
  );
}
