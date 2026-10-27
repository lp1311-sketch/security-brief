<!-- LOVABLE:BEGIN -->
> [!IMPORTANT]
> This project is connected to [Lovable](https://lovable.dev). Avoid rewriting
> published git history — force pushing, or rebasing/amending/squashing commits
> that are already pushed — as it rewrites history on Lovable's side and the
> user will likely lose their project history.
>
> Commits you push to the connected branch sync back to Lovable and show up in
> the editor, so keep the branch in a working state.
<!-- LOVABLE:END -->

## Architecture rules
- News pipeline lives in src/lib/news (pure, relative-import modules) so both the site's server function and scripts/run-pipeline.ts share it — one source of truth for ranking.
- No database: the site fetches public feeds on demand via a cached server function — keeps running cost at €0.
- Priority label criteria are defined only in rank.ts `priorityFor` and covered by src/test/rank.test.ts — labels must stay explainable.
- AI drafts are optional (local Ollama), written to content/drafts as status: draft, never auto-published.
