import { createFileRoute, Link } from "@tanstack/react-router";
import { useSuspenseQuery } from "@tanstack/react-query";
import { newsQuery } from "@/lib/news/news.functions";
import { CATEGORIES } from "@/lib/news/sources";
import { EmptyState, PriorityBadge, timeAgo } from "@/components/site";

export const Route = createFileRoute("/weekly")({
  head: () => ({
    meta: [
      { title: "Weekly security overview — CyberBrief" },
      { name: "description", content: "The highest-impact cybersecurity stories of the past seven days, grouped by topic." },
      { property: "og:title", content: "Weekly security overview — CyberBrief" },
      { property: "og:description", content: "The highest-impact cybersecurity stories of the past seven days." },
    ],
  }),
  loader: ({ context }) => context.queryClient.ensureQueryData(newsQuery),
  component: Weekly,
});

function Weekly() {
  const { data } = useSuspenseQuery(newsQuery);
  const week = data.clusters
    .filter((c) => c.publishedAt && Date.now() - Date.parse(c.publishedAt) < 7 * 864e5)
    .sort((a, b) => b.score - a.score);
  const kev = [...new Set(week.flatMap((c) => c.kevCves))];
  const seen = new Set<string>();

  return (
    <div className="mx-auto max-w-4xl px-4 py-12 sm:px-6">
      <p className="kicker text-primary">Past 7 days</p>
      <h1 className="mt-2 text-4xl md:text-5xl">Weekly security overview</h1>
      <p className="mt-4 text-muted-foreground">
        {week.length} story clusters from the configured feeds. {kev.length > 0 && `${kev.length} referenced CVE(s) appear in CISA's KEV catalog: ${kev.join(", ")}.`}
      </p>
      {!week.length && <div className="mt-10"><EmptyState title="Nothing dated in the past week" body="The feeds returned no stories with publication dates in the last seven days." /></div>}
      {CATEGORIES.map((cat) => {
        const items = week.filter((c) => c.categories[0] === cat.id && !seen.has(c.id)).slice(0, 6);
        items.forEach((c) => seen.add(c.id));
        if (!items.length) return null;
        return (
          <section key={cat.id} className="section-rule mt-12">
            <h2 className="text-2xl">{cat.label}</h2>
            <ol className="mt-4 space-y-4">
              {items.map((c) => (
                <li key={c.id} className="flex gap-3">
                  <span className="kicker w-20 shrink-0 pt-1 text-muted-foreground">{timeAgo(c.publishedAt)}</span>
                  <div>
                    <PriorityBadge p={c.priority} />{" "}
                    <Link to="/story/$id" params={{ id: c.id }} className="font-display text-lg hover:text-primary">{c.title}</Link>
                  </div>
                </li>
              ))}
            </ol>
          </section>
        );
      })}
    </div>
  );
}
