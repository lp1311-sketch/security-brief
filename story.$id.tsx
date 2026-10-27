import { createFileRoute, Link, notFound } from "@tanstack/react-router";
import { useSuspenseQuery } from "@tanstack/react-query";
import { newsQuery } from "@/lib/news/news.functions";
import { buildBriefing } from "@/lib/news/briefing";
import { categoryLabel } from "@/lib/news/sources";
import { PriorityBadge, timeAgo } from "@/components/site";

export const Route = createFileRoute("/story/$id")({
  loader: async ({ context, params }) => {
    const data = await context.queryClient.ensureQueryData(newsQuery);
    const c = data.clusters.find((x) => x.id === params.id);
    if (!c) throw notFound();
    return { title: c.title, summary: c.summary };
  },
  head: ({ loaderData }) => ({
    meta: loaderData
      ? [
          { title: `${loaderData.title} — CyberBrief` },
          { name: "description", content: loaderData.summary.slice(0, 160) },
          { property: "og:title", content: loaderData.title },
          { property: "og:description", content: loaderData.summary.slice(0, 160) },
          { property: "og:type", content: "article" },
        ]
      : [{ title: "Story unavailable — CyberBrief" }, { name: "robots", content: "noindex" }],
  }),
  component: Story,
});

function Story() {
  const { id } = Route.useParams();
  const { data } = useSuspenseQuery(newsQuery);
  const c = data.clusters.find((x) => x.id === id)!;
  const b = buildBriefing(c);
  const fmt = (d: string | null) => (d ? new Date(d).toLocaleString("en-GB", { dateStyle: "medium", timeStyle: "short" }) : "date not provided by source");

  return (
    <article className="mx-auto max-w-3xl px-4 py-12 sm:px-6">
      <div className="flex flex-wrap items-center gap-2">
        <PriorityBadge p={c.priority} />
        {c.categories.map((k) => (
          <Link key={k} to="/news" search={{ cat: k }} className="kicker text-primary">{categoryLabel(k)}</Link>
        ))}
      </div>
      <h1 className="mt-4 text-4xl leading-tight md:text-5xl">{b.headline}</h1>
      <p className="kicker mt-4 text-muted-foreground">
        {timeAgo(c.publishedAt)} · {c.items.length} report{c.items.length > 1 && "s"} · retrieved {fmt(c.items[0]?.retrievedAt ?? null)}
      </p>
      <aside className="mt-6 rounded-sm border-l-2 border-primary bg-card px-4 py-3 text-sm text-muted-foreground">
        Automated structured briefing. Assembled from feed metadata and CISA's KEV catalog without a language model. Quoted passages are source extracts; nothing else is inferred.
      </aside>

      <div className="prose-brief mt-8">
        <h2>Executive summary</h2>
        <p>{b.executiveSummary}</p>

        <h2>What is being reported</h2>
        {b.whatHappened.map((w) => (
          <p key={w.url}>
            <strong>{w.source}</strong> <span className="text-muted-foreground">({fmt(w.date)})</span>
            {w.text && <>: “{w.text}”</>} <a href={w.url} target="_blank" rel="noopener noreferrer">Read original</a>
          </p>
        ))}

        <h2>Why it matters</h2>
        <ul className="list-disc space-y-2 pl-5">{b.whyItMatters.map((w) => <li key={w}>{w}</li>)}</ul>

        {b.technical.length > 0 && (
          <>
            <h2>Technical identifiers</h2>
            <ul className="list-disc space-y-2 pl-5 font-mono text-sm">{b.technical.map((t) => <li key={t}>{t}</li>)}</ul>
          </>
        )}

        <h2>Recommended defensive actions</h2>
        <ul className="list-disc space-y-2 pl-5">
          {b.actions.map((a) => (
            <li key={a.text}>{a.url ? <a href={a.url} target="_blank" rel="noopener noreferrer">{a.text}</a> : a.text}</li>
          ))}
        </ul>

        <h2>Unknown or unconfirmed</h2>
        <ul className="list-disc space-y-2 pl-5 text-muted-foreground">{b.unknowns.map((u) => <li key={u}>{u}</li>)}</ul>

        <h2>Why this priority</h2>
        <p className="text-sm text-muted-foreground">Score {c.score}. <Link to="/methodology">How scoring works</Link></p>
        <ul className="space-y-1 font-mono text-sm text-muted-foreground">{c.reasons.map((r) => <li key={r}>{r}</li>)}</ul>

        <h2>Sources</h2>
        <ol className="list-decimal space-y-2 pl-5 text-sm">
          {c.items.map((i) => (
            <li key={i.id}><a href={i.link} target="_blank" rel="noopener noreferrer">{i.title}</a> — {i.sourceName}, {fmt(i.publishedAt)}</li>
          ))}
        </ol>
      </div>
    </article>
  );
}
