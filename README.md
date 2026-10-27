# CyberBrief Intelligence Desk

Project: CyberBrief — An Automated Cybersecurity Intelligence News Platform

Act as a senior full-stack engineer, product designer, cybersecurity journalist, and automation architect.

Build a complete, professional, production-oriented cybersecurity news website called CyberBrief.

The goal is to create an independent cybersecurity publication inspired by the editorial usefulness of BleepingComputer and The Hacker News. Do not copy their branding, layouts, articles, wording, or proprietary content.

The platform should collect publicly available news metadata, identify important developments, organize related stories, and generate original, source-attributed cybersecurity briefings with as little manual work and ongoing cost as possible.

1. Non-negotiable requirements

Target ongoing infrastructure and software costs: €0 per month.

Do not require paid AI APIs.

Do not require a paid automation platform.

Do not require a paid hosting plan.

Do not make any paid subscription necessary for the core website to function.

Prefer free, open-source technologies and free-tier services.

Do not assume that free-tier quotas are unlimited.

Never expose secrets, API keys, service-role keys, or administrative credentials in browser code.

Build a working website, not merely a static mockup.

Avoid unnecessary complexity and paid integrations.

Explain any feature that cannot operate fully automatically under these constraints.

Before implementing integrations, determine which features can actually run without paid services. Never simulate successful automation when it has not been configured.

2. Website design and user experience

Create a distinctive, polished cybersecurity publication with a professional editorial identity.

Visual direction:

Dark navy, white, and restrained electric-blue accents.

Excellent typography and readable article layouts.

Responsive design for desktop, tablet, and mobile.

Professional information hierarchy and generous whitespace.

Fast loading and accessible color contrast.

Avoid generic AI-generated landing-page aesthetics.

Use original branding and a simple text-based CyberBrief logo.

Homepage sections:

Breaking and important security news.

Editor's picks / highest-impact stories.

Latest cybersecurity news.

Microsoft and enterprise security.

Vulnerabilities and actively exploited CVEs.

Ransomware, malware, and data breaches.

Cloud security and identity attacks.

AI security and emerging threats.

Weekly security overview.

Each story card should display its category, headline, short summary, publication time, and source attribution.

Include search, category filtering, pagination, a mobile navigation menu, and a useful empty state when no articles are available.

Do not use fake live statistics, fake reader counts, fake article dates, or fabricated breaking-news labels.

3. Editorial sources

Design the ingestion system around public RSS feeds and other officially permitted public feeds.

Start with these publishers:

BleepingComputer

The Hacker News

Microsoft Security Response Center (MSRC)

CISA cybersecurity advisories

Google Cloud security and security research publications, where suitable feeds are available

Optionally support additional reputable sources such as KrebsOnSecurity, Ars Technica's security coverage, and vendor security advisories.

Store source name, original article URL, source publication date, feed retrieval time, and relevant attribution.

Use RSS metadata and short factual extracts to discover and prioritize stories. Prefer original vendor advisories and official security notices when validating technical details.

Do not bypass paywalls, access controls, or anti-bot restrictions. Do not scrape entire articles when an RSS feed or permitted public source is available.

4. Intelligent story selection

Build a transparent, configurable relevance-ranking system that does not depend on a paid AI API.

Calculate an editorial priority score using available signals such as:

Confirmed active exploitation.

Critical or high CVSS severity, when verified.

Official security advisories.

Ransomware and significant breaches.

Broad enterprise impact.

Microsoft, Windows, Entra ID, cloud, and identity relevance.

Publication recency.

Multiple independent sources reporting the same event.

Deduplicate stories using normalized URLs, source identifiers, similarity checks, and, where possible, CVE identifiers.

Group multiple reports about the same incident into a single story cluster.

Do not equate popularity with importance unless reliable engagement data is actually available. RSS feeds usually do not provide consistent article-view counts.

Display an explainable priority label, such as Critical, High Priority, or Standard. Only use Critical for stories that meet explicit, documented criteria.

5. Original article generation without paid AI APIs

Design a provider-independent article generation system.

Preferred options, in order:

A locally running open-source language model, if a machine with sufficient resources is available.

A genuinely free and currently available hosted model or free API quota, only if its terms permit the intended use.

A high-quality template-based editorial briefing that does not require a language model.

Do not make a paid model API a prerequisite.

If no AI model is configured, the system must still be able to create useful, clearly labeled structured briefings from verified source metadata.

When a model is available, generate original English-language articles containing:

A clear, factual headline.

A concise executive summary.

What happened.

Why the story matters.

Who may be affected, only when verified.

Technical details and indicators, only when supported by sources.

Recommended defensive actions based on authoritative references.

What remains unknown or unconfirmed.

A source list with clickable original URLs.

Do not simply rewrite an existing article sentence by sentence.

Do not fabricate quotes, CVEs, affected versions, patches, attack techniques, indicators of compromise, or incident details.

Distinguish confirmed facts from analysis and uncertainty. Preserve original source attribution.

Generated articles must be stored as drafts until the publication policy has been configured.

6. Automation

Prepare an automation architecture that can run on free infrastructure.

Investigate these options:

GitHub Actions on an eligible public repository.

Scheduled GitHub Actions workflows.

A lightweight Python or JavaScript RSS processing script.

Supabase only if its free tier is sufficient and genuinely necessary.

Git-based static publishing for a low-cost, fast website.

Prefer the simplest architecture that minimizes recurring services.

Target schedule:

Morning run.

Evening run.

Each scheduled run should:

Fetch configured RSS feeds.

Validate feed responses and handle temporary errors.

Normalize and deduplicate stories.

Rank candidate stories.

Validate key facts against available authoritative sources.

Generate original briefings using the configured free generation method.

Run basic quality and attribution checks.

Save eligible articles as drafts or publish according to the configured editorial policy.

Record a timestamped execution log and a summary of failures.

If an automation platform cannot guarantee the schedule, document that limitation.

Do not claim that background automation is working until the repository, workflow, permissions

This project was built with [Lovable](https://lovable.dev).

## Build with Lovable

Continue developing this project in the [Lovable editor](https://lovable.dev/projects/80e159a6-8f8a-561a-b27e-eb30d00d208a).

- **Ship faster**: describe what you want to build and Lovable handles the code.
- **Stay in sync**: every change made in Lovable is committed straight to this repository.
- **Full ownership**: this code is yours. Push to `main` on GitHub and your changes sync back into Lovable, ready for your next prompt.

## Development

Prefer working locally? You need Node.js and npm — [install with nvm](https://github.com/nvm-sh/nvm#installing-and-updating).

```sh
git clone <this-repository-url>
cd <repository-name>
npm i
npm run dev
```
