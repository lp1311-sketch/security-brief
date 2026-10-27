import { useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { useSuspenseQuery } from "@tanstack/react-query";
import { changeRadarQuery } from "@/lib/news/change-radar.functions";
import {
  CHANGE_PRODUCTS,
  GRAPH_SERVICE_COMMUNICATIONS_DOCS,
  MESSAGE_CENTER_DOCS,
  MICROSOFT_ROADMAP_PAGE,
  type ChangeProduct,
  type ChangeUpdate,
} from "@/lib/news/change-radar";
import { EmptyState } from "@/components/site";

export const Route = createFileRoute("/change-radar")({
  head: () => ({
    meta: [
      { title: "Microsoft 365 Change Radar — CyberBrief" },
      { name: "description", content: "Public Microsoft 365 roadmap updates, clearly separated from tenant-specific Message Center and service health." },
      { property: "og:title", content: "Microsoft 365 Change Radar — CyberBrief" },
      { property: "og:description", content: "Track public roadmap updates for Teams, Exchange, SharePoint, Entra, Intune, Defender and more." },
    ],
  }),
  loader: ({ context }) => context.queryClient.ensureQueryData(changeRadarQuery),
  component: ChangeRadar,
});

function dateLabel(iso: string | null): string | null {
  if (!iso) return null;
  const date = new Date(iso);
  if (!Number.isFinite(date.getTime())) return null;
  return new Intl.DateTimeFormat("en-GB", {
    day: "numeric", month: "short", year: "numeric", timeZone: "UTC",
  }).format(date);
}

function ProductTag({ children }: { children: string }) {
  return <span className="kicker rounded-sm border px-2 py-1 text-muted-foreground">{children}</span>;
}

function UpdateCard({ update }: { update: ChangeUpdate }) {
  const date = dateLabel(update.feedDate);
  return (
    <article className="border-b py-6 first:border-t">
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <span className="kicker text-primary">Public roadmap</span>
        {update.stage && <span className="kicker rounded-sm border border-primary/60 px-2 py-1 text-primary">{update.stage}</span>}
        {update.products.slice(0, 3).map((product) => <ProductTag key={product}>{product}</ProductTag>)}
      </div>
      <h2 className="text-xl leading-tight sm:text-2xl">
        <a href={update.link} target="_blank" rel="noopener noreferrer" className="hover:text-primary focus-visible:outline focus-visible:outline-2 focus-visible:outline-primary">
          {update.title}
        </a>
      </h2>
      {update.summary ? (
        <p className="mt-3 max-w-4xl text-sm leading-6 text-muted-foreground">{update.summary}</p>
      ) : (
        <p className="mt-3 text-sm text-muted-foreground">No summary text was included in this roadmap entry.</p>
      )}
      <p className="kicker mt-4 text-muted-foreground">
        {date ? `Roadmap feed entry · ${date}` : "Roadmap feed entry · date not provided"}
        {update.featureId ? ` · ID ${update.featureId}` : ""}
      </p>
    </article>
  );
}

function ChangeRadar() {
  const { data, refetch } = useSuspenseQuery(changeRadarQuery);
  const [query, setQuery] = useState("");
  const [product, setProduct] = useState<ChangeProduct | "All">("All");
  const search = query.trim().toLowerCase();
  const updates = data.updates.filter((item) =>
    (product === "All" || item.products.includes(product)) &&
    (!search || `${item.title} ${item.summary} ${item.products.join(" ")} ${item.featureId ?? ""}`.toLowerCase().includes(search)),
  );

  return (
    <div className="mx-auto max-w-5xl px-4 py-10 sm:px-6">
      <header className="border-b pb-8">
        <p className="kicker mb-3 text-primary">Microsoft 365 · Change Radar</p>
        <h1 className="text-4xl md:text-5xl">What Microsoft says is changing</h1>
        <p className="mt-4 max-w-3xl text-lg leading-7 text-muted-foreground">
          Public roadmap updates for Microsoft 365 services and apps. This is a product-planning view—not a prediction that a change is already active in your tenant.
        </p>
        <div className="mt-5 flex flex-wrap gap-4 text-sm">
          <a href={MICROSOFT_ROADMAP_PAGE} target="_blank" rel="noopener noreferrer" className="text-primary underline underline-offset-4">Open Microsoft roadmap</a>
          <a href={MESSAGE_CENTER_DOCS} target="_blank" rel="noopener noreferrer" className="text-primary underline underline-offset-4">About Message Center</a>
        </div>
      </header>

      <aside className="my-7 border-l-2 border-primary bg-card px-4 py-4 text-sm leading-6">
        <p className="font-medium">Public roadmap ≠ tenant-specific change notice</p>
        <p className="mt-1 text-muted-foreground">
          Roadmap stages and timing can change, and applicability depends on the product, cloud and rollout. Tenant-specific Message Center posts and service-health incidents are not fetched here; they require authenticated Microsoft Graph access for the relevant tenant.
        </p>
        <a href={GRAPH_SERVICE_COMMUNICATIONS_DOCS} target="_blank" rel="noopener noreferrer" className="mt-2 inline-block text-primary underline underline-offset-4">Microsoft Graph service communications documentation</a>
      </aside>

      {!data.ok ? (
        <div className="space-y-4">
          <EmptyState
            title="The public roadmap feed is unavailable"
            body={`The live feed could not be loaded${data.error ? ` (${data.error})` : ""}. No sample or stale roadmap items are being shown; use Microsoft's roadmap as the source of truth.`}
          />
          <div className="flex flex-wrap gap-4">
            <button type="button" onClick={() => void refetch()} className="rounded-sm border px-3 py-2 text-sm hover:border-primary focus-visible:outline focus-visible:outline-2 focus-visible:outline-primary">Retry feed</button>
            <a href={MICROSOFT_ROADMAP_PAGE} target="_blank" rel="noopener noreferrer" className="self-center text-primary underline underline-offset-4">Open the Microsoft roadmap</a>
          </div>
        </div>
      ) : (
        <>
          <div className="flex flex-col gap-4 border-b pb-5 sm:flex-row sm:items-end sm:justify-between">
            <div>
              <p className="kicker text-muted-foreground" aria-live="polite">{updates.length} of {data.updates.length} public roadmap entries</p>
              <p className="mt-1 text-sm text-muted-foreground">Feed checked {new Intl.DateTimeFormat("en-GB", { day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit", timeZone: "UTC" }).format(new Date(data.fetchedAt))} UTC</p>
            </div>
            <label className="w-full sm:max-w-sm">
              <span className="sr-only">Search roadmap changes</span>
              <input
                type="search"
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Search title, product or ID…"
                className="w-full rounded-sm border bg-card px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/40"
              />
            </label>
          </div>

          <div className="flex flex-wrap gap-2 py-5" aria-label="Filter roadmap entries by product">
            <button type="button" aria-pressed={product === "All"} onClick={() => setProduct("All")}
              className={`kicker rounded-sm border px-2.5 py-1.5 ${product === "All" ? "border-primary text-primary" : "text-muted-foreground hover:border-primary"}`}>All</button>
            {CHANGE_PRODUCTS.filter((p) => p !== "Microsoft 365").map((p) => (
              <button key={p} type="button" aria-pressed={product === p} onClick={() => setProduct(p)}
                className={`kicker rounded-sm border px-2.5 py-1.5 ${product === p ? "border-primary text-primary" : "text-muted-foreground hover:border-primary"}`}>{p}</button>
            ))}
          </div>

          {updates.length ? (
            <div>
              {updates.map((item) => <UpdateCard key={item.id} update={item} />)}
            </div>
          ) : (
            <EmptyState title="No matching roadmap entries" body="Try another product filter or search term. The public roadmap feed may also have no entries for this selection." />
          )}
        </>
      )}
    </div>
  );
}
