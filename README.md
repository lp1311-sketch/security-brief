# Security Brief: free automated security news blog

A static blog that reads public RSS/Atom feeds twice a day, ranks and groups the stories,
and publishes short excerpts with links back to the original publishers.
Stdlib Python only. No paid API, no server, no database.

## What it does
- Fetches the feeds in `feeds.json` (BleepingComputer, The Hacker News, MSRC, CISA, Google Security, KrebsOnSecurity, Ars Technica).
- Removes duplicates and groups stories about the same event (shared CVE, or similar titles).
- Scores each story and assigns a priority (rules below).
- Shows a picture: the image from the feed if the publisher provides one, otherwise a generated category cover.
- Writes `docs/` (index, story pages, RSS, sitemap, `status.json`), and the GitHub Action commits it.
- Keeps stories for 7 days (`retention_days`), so the blog builds history.

## Priority rules (documented, not a black box)
| Priority | Rule |
| --- | --- |
| Critical | A CVE is listed in the CISA KEV catalog, **or** exploitation is reported by an official source (MSRC, CISA, Google). |
| High | Score 6 or more. |
| Standard | Everything else. |

Score signals: KEV match +5, exploitation wording +4, ransomware/breach/critical/Microsoft/cloud/AI keywords +1 to +2 each, several sources reporting the same event +1 to +3, published within 24 h +2 (48 h +1), official source +1.
Popularity is not used, because RSS feeds do not provide reliable view counts.

## Setup (about 20 minutes, €0)
1. Create a **public** GitHub repository and upload these files (keep the folder structure, including `.github/`).
   - Public is required for free GitHub Pages and free scheduled Actions on a free account.
2. Edit `feeds.json`: set `site_url` to `https://<your-github-user>.github.io/<repo-name>`.
3. Repo **Settings → Pages → Build and deployment**: Source = *Deploy from a branch*, Branch = `main`, Folder = `/docs`.
4. Repo **Settings → Actions → General**: allow read and write workflow permissions (needed for the bot commit).
5. **Actions → autoblog → Run workflow** to test once. Then check `docs/status.json` for failed sources.

## Domain
- A free `*.github.io` address is free and works. A custom domain (for example `securitybrief.de`) is not free: registration usually costs about €10 to €20 per year. Free domain offers are generally unreliable or abused, so I would not build on one.
- Once you own a domain, add it under Pages → Custom domain, then update `site_url` to match.
- Alternative free hosts: Cloudflare Pages or Netlify (both have free tiers with `*.pages.dev` / `*.netlify.app` subdomains). Their free-tier limits can change, so check before relying on them.

## Images
- Images come from the RSS feed (`media:thumbnail`, `media:content`, enclosure, or the first `<img>` in the feed text), only over HTTPS.
- Images are loaded from the publisher's server and credited in the caption. Copyright stays with the publisher. Check each publisher's terms before publishing more than the excerpt.
- If you want to remove feed images entirely, delete the image lookup in `parse_feed`. The category cover is used then.

## Copyright and terms (please read)
- Stories show only a shortened feed excerpt (max 320 characters) plus a link. The full article is not copied.
- Feed reading is what the feeds are published for, but republishing content can still be restricted by a site's terms. Check the terms of each source you add.
- Do not add sources that forbid automated reading or redistribution, and do not scrape article pages.

## Limits
- GitHub scheduled runs can be delayed or skipped under load. Times are UTC.
- GitHub disables scheduled workflows in public repositories after 60 days without repository activity. Bot commits should count as activity, but I have not verified this for your account. Check the Actions tab after two months.
- The generated text is template-based. There is no AI rewriting, so the "Why it matters" and checks are generic per category, and the page says so.
- Feed URLs were copied from the earlier CyberBrief project config. They were not reachable from my build environment, so verify each one when you first run the workflow (`status.json` shows which ones fail).
- Feeds that block automated access or change format will show up as failed in `status.json`.

## Local test
```sh
python3 -m unittest discover -s tests -v
python3 build.py --fixtures tests/fixtures --out /tmp/site --data /tmp/stories.json   # offline
python3 build.py                                                                        # live (needs internet)
```

## Possible next steps (optional, still free)
- Local AI summaries via Ollama on your own machine (not in GitHub Actions). Store results as drafts before publishing.
- German-language version (translate the fixed category text and the generic checks).
- A `sources` health check that alerts you by email when a feed has failed for three runs in a row.
