import { createFileRoute, Link } from "@tanstack/react-router";
import { useSuspenseQuery } from "@tanstack/react-query";
import { newsQuery } from "@/lib/news/news.functions";
import { EmptyState, StoryCard } from "@/components/site";
import { CATEGORIES } from "@/lib/news/sources";
import type { CategoryId, Cluster } from "@/lib/news/types";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "CyberBrief — Cybersecurity intelligence, ranked and sourced" },
      { name: "description", content: "Exploited CVEs, ransomware, Microsoft, cloud and AI security news — clustered across publishers and ranked by transparent criteria." },
      { property: "og:title", content: "CyberBrief — Cybersecurity intelligence, ranked and sourced" },
      { property: "og:description", content: "Exploited CVEs, ransomware, Microsoft, cloud and AI security news, ranked by transparent criteria." },
    ],
  }),
  loader: ({ context }) => context.queryClient.ensureQueryData(newsQuery),
  component: Home,
});

function Section({ title, cat, items }: { title: string; cat?: CategoryId; items: Cluster[] }) {
  if (!items.length) return null;
  return (
    <section className="section-rule">
      <div className="mb-6 flex items-baseline justify-between">
        <h2 className="text-2xl">{title}</h2>
        {cat && <Link to="/news" search={{ cat }} className="kicker text-primary">More →</Link>}
      </div>
      <div className="grid gap-8 sm:grid-cols-2 lg:grid-cols-4">
        {items.map((c) => <StoryCard key={c.id} c={c} />)}
      </div>
    </section>
  );
}

function Home() {
  const { data } = useSuspenseQuery(newsQuery);
  const all = data.clusters;
  if (!all.length)
    return (
      <div className="mx-auto max-w-3xl space-y-6 px-4 py-24">
        <EmptyState title="No stories available right now" body="None of the configured feeds could be reached on this attempt. Feed status is listed on the Methodology page; the site retries automatically." />
        <section className="section-rule">
          <p className="kicker text-primary">Separate Microsoft 365 section</p>
          <h2 className="mt-2 text-2xl">Change Radar</h2>
          <p className="mt-2 text-muted-foreground">Browse Microsoft’s public roadmap separately from cybersecurity news.</p>
          <Link to="/change-radar" className="mt-4 inline-block rounded-sm bg-primary px-4 py-2 text-sm font-medium text-primary-foreground">Open Change Radar</Link>
        </section>
      </div>
    );

  const byScore = [...all].sort((a, b) => b.score - a.score);
  const recent = all.filter((c) => c.publishedAt && Date.now() - Date.parse(c.publishedAt) < 72 * 36e5);
  const important = [...(recent.length >= 5 ? recent : all)].sort((a, b) => b.score - a.score);
  const lead = important[0]!; const rest = important.slice(1);
  const used = new Set([lead.id, ...rest.slice(0, 4).map((c) => c.id)]);
  const picks = byScore.filter((c) => !used.has(c.id)).slice(0, 4);
  picks.forEach((c) => used.add(c.id));
  const cat = (id: CategoryId) => all.filter((c) => c.categories.includes(id) && !used.has(c.id)).slice(0, 4);
  const critical = important.filter((c) => c.priority === "Critical");

  return (
    <div className="mx-auto max-w-7xl space-y-16 px-4 py-10 sm:px-6">
      {critical.length > 0 && (
        <div className="flex flex-wrap items-center gap-3 rounded-sm border border-critical/50 px-4 py-3 text-sm">
          <span className="kicker text-critical">Critical · exploitation confirmed</span>
          {critical.slice(0, 3).map((c) => (
            <Link key={c.id} to="/story/$id" params={{ id: c.id }} className="hover:text-primary">{c.title}</Link>
          ))}
        </div>
      )}

      <section className="grid gap-10 lg:grid-cols-[1.6fr_1fr]">
        <div className="border-b pb-10 lg:border-b-0 lg:border-r lg:pb-0 lg:pr-10">
          <p className="kicker mb-4 text-muted-foreground">Top story · ranked by impact</p>
          <StoryCard c={lead} size="lg" />
        </div>
        <div className="space-y-6">
          <p className="kicker text-muted-foreground">Also important</p>
          {rest.slice(0, 4).map((c) => (
            <div key={c.id} className="border-b pb-5 last:border-0"><StoryCard c={c} size="sm" /></div>
          ))}
        </div>
      </section>

      <Section title="Editor's picks · highest impact" items={picks} />

      <section className="section-rule">
        <div className="mb-6 flex items-baseline justify-between">
          <h2 className="text-2xl">Latest</h2>
          <Link to="/news" className="kicker text-primary">All news →</Link>
        </div>
        <div className="grid gap-x-10 md:grid-cols-2">
          {all.filter((c) => !used.has(c.id)).slice(0, 8).map((c) => (
            <div key={c.id} className="border-b py-5"><StoryCard c={c} size="sm" /></div>
          ))}
        </div>
      </section>

      {CATEGORIES.filter((c) => c.id !== "general").map((c) => (
        <Section key={c.id} title={c.label} cat={c.id} items={cat(c.id)} />
      ))}

      <section className="section-rule flex flex-col items-start justify-between gap-4 md:flex-row md:items-center">
        <div>
          <h2 className="text-2xl">Weekly security overview</h2>
          <p className="mt-1 text-muted-foreground">The highest-ranked stories from the past seven days, in one page.</p>
        </div>
        <Link to="/weekly" className="rounded-sm bg-primary px-4 py-2 text-sm font-medium text-primary-foreground">Read this week's overview</Link>
      </section>

      <section className="section-rule flex flex-col items-start justify-between gap-5 md:flex-row md:items-center">
        <div>
          <p className="kicker text-primary">Separate from security news</p>
          <h2 className="mt-2 text-2xl">Microsoft 365 Change Radar</h2>
          <p className="mt-1 max-w-2xl text-muted-foreground">Public roadmap updates for Microsoft 365 services and apps. Tenant-specific Message Center and service-health data are not included.</p>
        </div>
        <Link to="/change-radar" className="shrink-0 rounded-sm border px-4 py-2 text-sm hover:border-primary">Browse roadmap updates →</Link>
      </section>
    </div>
  );
}
