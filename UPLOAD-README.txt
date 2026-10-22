Security Brief update - QR restored, homepage sections repositioned, filters refreshed

Upload/replace these files at the repository root:
- build.py
- test_autoblog.py
- buymeacoffee-qr.png

This update:
- Restores the Buy Me a Coffee QR code beside the single donation section.
- Keeps the donation section below the homepage overview, as requested.
- Moves the Free field guide and From the analysis desk below the news feed; From the analysis desk is the last homepage content section before the footer.
- Gives the All stories/category filter panel a more prominent futuristic visual hierarchy. Controls remain visible immediately; no accordion is introduced.
- Adds regression tests for QR presence and homepage section order.

Do not replace site.json. It contains your private site settings and the donation link/text.

Validation: all 44 offline regression tests passed; offline build confirmed one donation section, one Buy Me a Coffee button, the QR image, and the new homepage order.

After upload, commit/push the files, run the GitHub Actions workflow, wait for Pages deployment, then hard-refresh the live site.
