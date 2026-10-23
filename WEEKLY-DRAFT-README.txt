SECURITY BRIEF — WEEKLY SIGNAL DRAFT (SAFE OPT-IN)

UPLOADING
Extract this ZIP and upload preserving these paths to the EXISTING repository:
  build.py (root, overwrite existing)
  weekly_draft.py (root, new)
  .github/workflows/weekly-draft.yml (new; do NOT replace autoblog.yml)
No other existing site config, article, newsletter, QR, or docs files are replaced.

ENABLE (optional; no API key needed for website itself)
1. GitHub repository Settings > Secrets and variables > Actions > New repository secret.
   Name: OPENAI_API_KEY. Value: your separately obtained API key. Never put it in site.json or public files.
   The model defaults to gpt-4o-mini; pricing and access are provider-dependent. Set an API usage budget.
2. Commit files. In Actions > Weekly Signal draft (review required), run manually once.
3. New unpublished review draft appears in drafts/weekly/ (repository root). It is NOT shown on the website,
   emailed, or sent to Mailchimp. The scheduled run is Monday 08:37 UTC; scheduled tasks may be delayed/skipped.
4. Read each citation and claim, verify against authoritative sources, correct unsupported content.
5. To publish: copy the reviewed draft to content/briefings/ with the same lowercase slug,
   change the front matter `draft: true` to `draft: false`, add `ai_assisted: true`,
   and remove the draft-only warning/checklist before committing. Do not publish unreviewed text.
6. Run Actions > autoblog manually (or wait for its next feed check). It regenerates the site.

NOTE: GitHub's scheduled workflow cannot guarantee a precise time. Failed or missing API key makes
no article and does not interrupt the regular autoblog. The generator does not send newsletters.
Only public story excerpts (up to 18, max 400 characters each) are sent to the selected model,
not GitHub secrets, site.json or whole articles. News may change after drafts are made.
API provider model pricing/availability should be verified before enabling.
