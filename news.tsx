import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useSuspenseQuery } from "@tanstack/react-query";
import { z } from "zod";
import { newsQuery } from "@/lib/news/news.functions";
import { CATEGORIES } from "@/lib/news/sources";
import { EmptyState, StoryCard } from "@/components/site";

const PER_PAGE = 12;
const search = z.object({
  q: z.string().optional(),
  cat: z.enum(["microsoft", "vulnerabilities", "threats", "cloud", "ai", "general"]).optional(),
  page: z.number().int().min(1).optional(),
});

export const Route = createFileRoute("/news")({
  validateSearch: search,
  head: () => ({
    meta: [
      { title: "All cybersecurity news — CyberBrief" },
      { name: "description", content: "Search and filter every clustered cybersecurity story by category." },
      { property: "og:title", content: "All cybersecurity news — CyberBrief" },
      { property: "og:description", content: "Search and filter every clustered cybersecurity story by category." },
    ],
  }),
  loader: ({ context }) => context.queryClient.ensureQueryData(newsQuery),
  component: News,
});

function News() {
  const { q = "", cat, page = 1 } = Route.useSearch();
  const navigate = useNavigate({ from: "/news" });
  const { data } = useSuspenseQuery(newsQuery);
  const needle = q.trim().toLowerCase();
  const list = data.clusters.filter(
    (c) =>
      (!cat || c.categories.includes(cat)) &&
      (!needle || `${c.title} ${c.summary} ${c.cves.join(" ")} ${c.items.map((i) => i.sourceName).join(" ")}`.toLowerCase().includes(needle)),
  );
  const pages = Math.max(1, Math.ceil(list.length / PER_PAGE));
  const shown = list.slice((page - 1) * PER_PAGE, page * PER_PAGE);
  const label = CATEGORIES.find((c) => c.id === cat)?.label ?? "All cybersecurity news";

  return (
    <div className="mx-auto max-w-7xl px-4 py-10 sm:px-6">
      <h1 className="text-4xl md:text-5xl">{label}</h1>
      <form
        className="mt-6 flex gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          const v = new FormData(e.currentTarget).get("q")?.toString() || undefined;
          navigate({ search: (s) => ({ ...s, q: v, page: undefined }) });
        }}
      >
        <input name="q" defaultValue={q} key={q} placeholder="Search headlines, CVE IDs, sources…" aria-label="Search stories"
          className="w-full max-w-xl rounded-sm border bg-card px-3 py-2 outline-none focus:border-primary" />
        <button className="rounded-sm bg-primary px-4 text-sm font-medium text-primary-foreground">Search</button>
      </form>
      <div className="mt-5 flex flex-wrap gap-2">
        <Link to="/news" search={{ q: q || undefined }} className={`kicker rounded-sm border px-2.5 py-1 ${!cat ? "border-primary text-primary" : "text-muted-foreground"}`}>All</Link>
        {CATEGORIES.map((c) => (
          <Link key={c.id} to="/news" search={{ q: q || undefined, cat: c.id }}
            className={`kicker rounded-sm border px-2.5 py-1 ${cat === c.id ? "border-primary text-primary" : "text-muted-foreground"}`}>
            {c.short}
          </Link>
        ))}
      </div>
      <p className="kicker mt-6 text-muted-foreground">{list.length} stories</p>
      <div className="mt-6 grid gap-x-8 gap-y-10 sm:grid-cols-2 lg:grid-cols-3">
        {shown.map((c) => <StoryCard key={c.id} c={c} />)}
      </div>
      {!list.length && (
        <EmptyState title="No matching stories" body="Try a different search term or category. Stories are kept for as long as they appear in the source feeds." />
      )}
      {pages > 1 && (
        <nav aria-label="Pagination" className="mt-12 flex items-center justify-center gap-4 text-sm">
          {page > 1 ? <Link to="/news" search={(s) => ({ ...s, page: page - 1 })} className="text-primary">← Newer</Link> : <span className="text-muted-foreground">← Newer</span>}
          <span className="kicker">Page {page} / {pages}</span>
          {page < pages ? <Link to="/news" search={(s) => ({ ...s, page: page + 1 })} className="text-primary">Older →</Link> : <span className="text-muted-foreground">Older →</span>}
        </nav>
      )}
    </div>
  );
}
