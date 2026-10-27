import type { CategoryId, Source } from "./types";

// Public RSS/Atom feeds published by each outlet for syndication.
export const SOURCES: Source[] = [
  { id: "bleepingcomputer", name: "BleepingComputer", url: "https://www.bleepingcomputer.com/feed/", site: "https://www.bleepingcomputer.com", official: false },
  { id: "thehackernews", name: "The Hacker News", url: "https://feeds.feedburner.com/TheHackersNews", site: "https://thehackernews.com", official: false },
  { id: "msrc", name: "Microsoft Security Update Guide (MSRC)", url: "https://api.msrc.microsoft.com/update-guide/rss", site: "https://msrc.microsoft.com", official: true },
  { id: "cisa", name: "CISA Cybersecurity Advisories", url: "https://www.cisa.gov/cybersecurity-advisories/all.xml", site: "https://www.cisa.gov", official: true },
  { id: "google-security", name: "Google Security Blog", url: "https://security.googleblog.com/feeds/posts/default", site: "https://security.googleblog.com", official: true },
  { id: "google-cloud", name: "Google Cloud Security", url: "https://cloudblog.withgoogle.com/products/identity-security/rss/", site: "https://cloud.google.com/blog/products/identity-security", official: true },
  { id: "krebs", name: "KrebsOnSecurity", url: "https://krebsonsecurity.com/feed/", site: "https://krebsonsecurity.com", official: false },
  { id: "ars", name: "Ars Technica Security", url: "https://arstechnica.com/security/feed/", site: "https://arstechnica.com/security/", official: false },
];

export const KEV_URL =
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

export const CATEGORIES: { id: CategoryId; label: string; short: string }[] = [
  { id: "vulnerabilities", label: "Vulnerabilities & Exploited CVEs", short: "Vulnerabilities" },
  { id: "microsoft", label: "Microsoft & Enterprise", short: "Microsoft" },
  { id: "threats", label: "Ransomware, Malware & Breaches", short: "Threats" },
  { id: "cloud", label: "Cloud & Identity", short: "Cloud" },
  { id: "ai", label: "AI Security & Emerging Threats", short: "AI Security" },
  { id: "general", label: "Security News", short: "General" },
];

export const categoryLabel = (id: CategoryId) =>
  CATEGORIES.find((c) => c.id === id)?.short ?? id;
