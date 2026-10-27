// Scheduled run (GitHub Actions or local): fetch → dedupe → rank → draft → log.
// Usage: bun scripts/run-pipeline.ts
// Optional free local model: set OLLAMA_URL (e.g. http://localhost:11434) and OLLAMA_MODEL.
// Drafts are written to content/drafts and are NEVER auto-published.
import { mkdir, writeFile } from "node:fs/promises";
import { runPipeline } from "../src/lib/news/pipeline";
import { buildBriefing } from "../src/lib/news/briefing";
import type { Cluster } from "../src/lib/news/types";

const MAX_DRAFTS = 8;

function templateMarkdown(c: Cluster): string {
  const b = buildBriefing(c);
  return [
    `# ${b.headline}`, "", `> Automated structured briefing (no language model). Priority: ${c.priority} (score ${c.score}).`, "",
    "## Executive summary", b.executiveSummary, "",
    "## Why it matters", ...b.whyItMatters.map((w) => `- ${w}`), "",
    "## Recommended actions", ...b.actions.map((a) => `- ${a.text}${a.url ? ` (${a.url})` : ""}`), "",
    "## Unknown or unconfirmed", ...b.unknowns.map((u) => `- ${u}`), "",
    "## Sources", ...c.items.map((i) => `- [${i.title}](${i.link}) — ${i.sourceName}, ${i.publishedAt ?? "date not provided"}`),
  ].join("\n");
}

async function llmDraft(c: Cluster): Promise<string | null> {
  const url = process.env.OLLAMA_URL;
  if (!url) return null;
  const facts = c.items.map((i) => `- ${i.sourceName} (${i.publishedAt}): ${i.title}. ${i.excerpt} <${i.link}>`).join("\n");
  const prompt = `Write an original cybersecurity news briefing in English using ONLY these facts. Do not invent CVEs, versions, quotes, IOCs or details. Sections: Headline, Executive summary, What happened, Why it matters, Who may be affected (only if stated), Technical details (only if stated), Recommended defensive actions, What remains unknown, Sources (keep URLs). CISA KEV-confirmed CVEs: ${c.kevCves.join(", ") || "none"}.\n\nFacts:\n${facts}`;
  const res = await fetch(`${url}/api/generate`, {
    method: "POST",
    body: JSON.stringify({ model: process.env.OLLAMA_MODEL ?? "llama3.1:8b", prompt, stream: false }),
  });
  if (!res.ok) throw new Error(`Ollama HTTP ${res.status}`);
  const text = ((await res.json()) as { response: string }).response;
  // basic attribution/quality checks
  const missing = c.items.filter((i) => !text.includes(i.link));
  const strayCves = (text.match(/CVE-\d{4}-\d{4,7}/g) ?? []).filter((x) => !c.cves.includes(x));
  if (strayCves.length) throw new Error(`Model introduced unverified CVEs: ${strayCves.join(", ")}`);
  return text + (missing.length ? `\n\n## Sources\n${missing.map((i) => `- ${i.link}`).join("\n")}` : "");
}

const started = new Date().toISOString();
const snap = await runPipeline();
const failures: string[] = snap.sources.filter((s) => !s.ok).map((s) => `${s.name}: ${s.error}`);
if (!snap.kevLoaded) failures.push("CISA KEV catalog unavailable — Critical labels limited this run");

await mkdir("content/drafts", { recursive: true });
await mkdir("content/runs", { recursive: true });
const top = [...snap.clusters].sort((a, b) => b.score - a.score).slice(0, MAX_DRAFTS);
const drafts: { id: string; method: string }[] = [];
for (const c of top) {
  let body: string | null = null, method = "template";
  try { body = await llmDraft(c); if (body) method = "ollama"; } catch (e) { failures.push(`Draft ${c.id}: ${(e as Error).message}`); }
  await writeFile(`content/drafts/${c.id}.md`, `---\nstatus: draft\nmethod: ${method}\npriority: ${c.priority}\ngenerated: ${started}\n---\n\n${body ?? templateMarkdown(c)}\n`);
  drafts.push({ id: c.id, method });
}
const log = { started, finished: new Date().toISOString(), sources: snap.sources, clusters: snap.clusters.length, drafts, failures };
await writeFile(`content/runs/${started.replace(/[:.]/g, "-")}.json`, JSON.stringify(log, null, 2));
console.log(JSON.stringify({ clusters: log.clusters, drafts: drafts.length, failures }, null, 2));
