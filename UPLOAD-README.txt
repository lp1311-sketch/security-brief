Security Brief editorial shell update

Upload/replace these files in the repository:
- build.py
- .github/workflows/autoblog.yml
- content/briefings/*
- content/patch-tuesday/*
- tests/*

The update is designed to work with the existing site.json and data files.
Do not overwrite site.json unless you intentionally preserve your private publisher settings.

Changes:
- Analysis and Patch Tuesday pages use the same modern editorial shell as the homepage.
- Story detail pages use the same card, surface, typography and image treatment.
- Homepage analysis desk and free field guide remain below the live news feed.
- Feed status no longer exposes a public Details link.
- Header logo/brand is larger and more visible, with responsive mobile behavior.
- Offline regression suite: 42 tests passed.

After uploading:
1. Commit the files to the default branch.
2. Run the autoblog workflow manually.
3. Wait for the Pages deployment to finish.
4. Hard-refresh the site (Ctrl+F5) or use a private browser window.
