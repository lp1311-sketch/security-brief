import { categoryLabel } from "./sources";
import type { Cluster } from "./types";

export interface Briefing {
  kind: "structured-template";
  headline: string;
  executiveSummary: string;
  whatHappened: { source: string; url: string; date: string | null; text: string }[];
  whyItMatters: string[];
  affected: string[];
  technical: string[];
  actions: { text: string; url?: string }[];
  unknowns: string[];
}

/**
 * Model-free briefing built only from verified metadata (feed fields + CISA KEV).
 * Nothing here is invented: every statement is either a labeled source extract,
 * a derived signal, or a generic defensive step tied to an authoritative reference.
 */
export function buildBriefing(c: Cluster): Briefing {
  const srcCount = new Set(c.items.map((i) => i.sourceId)).size;
  const official = c.items.filter((i) => i.official);
  const why: string[] = [];
  if (c.kevCves.length)
    why.push(`CISA lists ${c.kevCves.join(", ")} in its Known Exploited Vulnerabilities catalog, meaning exploitation has been observed.`);
  if (official.length) why.push(`An official publisher (${[...new Set(official.map((o) => o.sourceName))].join(", ")}) has published on this topic.`);
  if (srcCount > 1) why.push(`${srcCount} independent publications reported on this development.`);
  why.push(`Classified under: ${c.categories.map(categoryLabel).join(", ")}.`);

  const actions: Briefing["actions"] = [];
  if (c.kevCves.length)
    actions.push({ text: "Check exposure against the CISA KEV entry and apply the vendor's remediation by the listed due date.", url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog" });
  if (c.cves.length) {
    c.cves.slice(0, 5).forEach((cve) => actions.push({ text: `Review the authoritative record for ${cve}.`, url: `https://nvd.nist.gov/vuln/detail/${cve}` }));
  }
  if (c.categories.includes("microsoft"))
    actions.push({ text: "Consult the Microsoft Security Update Guide for affected products and updates.", url: "https://msrc.microsoft.com/update-guide" });
  if (c.categories.includes("threats"))
    actions.push({ text: "Review CISA's #StopRansomware guidance for prevention and response steps.", url: "https://www.cisa.gov/stopransomware" });
  if (c.categories.includes("cloud"))
    actions.push({ text: "Audit privileged identities, MFA coverage and token/session policies in affected tenants." });
  actions.push({ text: "Read the original source reports below before acting; vendor advisories take precedence." });

  return {
    kind: "structured-template",
    headline: c.title,
    executiveSummary: c.summary
      ? `${c.items[0]?.sourceName ?? "The source"} reports: “${c.summary}”`
      : "The source feed did not include a summary. See the original reports below.",
    whatHappened: c.items.map((i) => ({ source: i.sourceName, url: i.link, date: i.publishedAt, text: i.excerpt })),
    whyItMatters: why,
    affected: [], // never inferred — only populated from verified structured data
    technical: c.cves.map((cve) => `${cve}${c.kevCves.includes(cve) ? " — listed in CISA KEV (exploited)" : " — referenced by source; exploitation not confirmed by CISA KEV"}`),
    actions,
    unknowns: [
      "Affected versions, CVSS scores and patch availability are not confirmed by CyberBrief unless shown above.",
      ...(c.kevCves.length ? [] : ["Active exploitation is not confirmed by CISA's KEV catalog at the time of retrieval."]),
      "Attribution, scale and indicators of compromise should be taken only from the original sources.",
    ],
  };
}
