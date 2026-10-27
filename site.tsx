import { Link } from "@tanstack/react-router";
import { useState } from "react";
import { Menu, X } from "lucide-react";
import { CATEGORIES, categoryLabel } from "@/lib/news/sources";
import type { Cluster, Priority } from "@/lib/news/types";

export function Logo() {
  return (
    <Link to="/" className="font-display text-2xl font-semibold tracking-tight">
      Cyber<span className="text-primary">Brief</span>
    </Link>
  );
}

export function Header() {
  const [open, setOpen] = useState(false);
  const nav = (
    <>
      {CATEGORIES.filter((c) => c.id !== "general").map((c) => (
        <Link key={c.id} to="/news" search={{ cat: c.id }} onClick={() => setOpen(false)} className="hover:text-primary">
          {c.short}
        </Link>
      ))}
      <Link to="/weekly" onClick={() => setOpen(false)} className="hover:text-primary">Weekly</Link>
      <Link to="/change-radar" onClick={() => setOpen(false)} className="hover:text-primary">Change Radar</Link>
      <Link to="/methodology" onClick={() => setOpen(false)} className="hover:text-primary">Methodology</Link>
    </>
  );
  return (
    <header className="border-b">
      <div className="mx-auto flex max-w-7xl items-center justify-between gap-6 px-4 py-4 sm:px-6">
        <Logo />
        <nav className="hidden items-center gap-5 text-sm text-muted-foreground lg:flex">{nav}</nav>
        <div className="flex items-center gap-3">
          <Link to="/news" className="hidden rounded-sm border px-3 py-1.5 text-sm hover:border-primary sm:inline-block">Search</Link>
          <button aria-label={open ? "Close menu" : "Open menu"} className="lg:hidden" onClick={() => setOpen(!open)}>
            {open ? <X /> : <Menu />}
          </button>
        </div>
      </div>
      {open && (
        <nav className="flex flex-col gap-4 border-t px-4 py-5 text-base lg:hidden">
          <Link to="/news" onClick={() => setOpen(false)}>All news &amp; search</Link>
          {nav}
        </nav>
      )}
    </header>
  );
}

export function Footer() {
  return (
    <footer className="mt-24 border-t">
      <div className="mx-auto grid max-w-7xl gap-8 px-4 py-10 text-sm text-muted-foreground sm:px-6 md:grid-cols-3">
        <div>
          <Logo />
          <p className="mt-3 max-w-xs">Independent, source-attributed cybersecurity briefings built from public feeds.</p>
        </div>
        <p>Headlines and short extracts belong to their original publishers and always link back to the source.</p>
        <div className="flex flex-col gap-2">
          <Link to="/methodology" className="hover:text-foreground">How stories are ranked</Link>
          <Link to="/weekly" className="hover:text-foreground">Weekly overview</Link>
          <Link to="/change-radar" className="hover:text-foreground">Microsoft 365 Change Radar</Link>
        </div>
      </div>
    </footer>
  );
}

export function timeAgo(iso: string | null): string {
  if (!iso) return "Date not provided";
  const m = Math.round((Date.now() - Date.parse(iso)) / 60000);
  if (m < 60) return `${Math.max(m, 1)} min ago`;
  if (m < 1440) return `${Math.round(m / 60)} h ago`;
  return new Date(iso).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric" });
}

export function PriorityBadge({ p }: { p: Priority }) {
  if (p === "Standard") return null;
  return (
    <span className={`kicker rounded-sm px-1.5 py-0.5 ${p === "Critical" ? "bg-critical text-primary-foreground" : "border border-high text-high"}`}>
      {p}
    </span>
  );
}

export function StoryCard({ c, size = "md" }: { c: Cluster; size?: "lg" | "md" | "sm" }) {
  const sources = [...new Set(c.items.map((i) => i.sourceName))];
  return (
    <article className="group">
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <PriorityBadge p={c.priority} />
        <span className="kicker text-primary">{categoryLabel(c.categories[0] ?? "general")}</span>
      </div>
      <Link to="/story/$id" params={{ id: c.id }}>
        <h3 className={`font-display font-medium leading-tight group-hover:text-primary ${size === "lg" ? "text-3xl md:text-4xl" : size === "md" ? "text-xl" : "text-lg"}`}>
          {c.title}
        </h3>
      </Link>
      {size !== "sm" && c.summary && (
        <p className={`mt-2 text-muted-foreground ${size === "lg" ? "text-lg" : "line-clamp-3 text-sm"}`}>{c.summary}</p>
      )}
      <p className="kicker mt-3 text-muted-foreground">
        {timeAgo(c.publishedAt)} · {sources.slice(0, 2).join(", ")}
        {sources.length > 2 && ` +${sources.length - 2}`}
      </p>
    </article>
  );
}

export function EmptyState({ title, body }: { title: string; body: string }) {
  return (
    <div className="rounded-sm border border-dashed p-10 text-center">
      <h3 className="text-xl">{title}</h3>
      <p className="mx-auto mt-2 max-w-md text-sm text-muted-foreground">{body}</p>
    </div>
  );
}
