SECURITY BRIEF - CHECKLIST UPDATE

These files belong in the ROOT of your existing GitHub repository (same level as feeds.json and autoblog.yml). The ZIP intentionally has no enclosing folder.

Replace:
- build.py
- site.json
- test_autoblog.py

Add or replace:
- m365-identity-incident-triage-checklist.pdf
- buymeacoffee-qr.png

Then run the repository workflow. The generator copies the PDF and coffee QR into the generated site output, links the PDF from the homepage, and adds the PDF URL to sitemap.xml.

Privacy: site.json contains the postal address and email configured for the public Impressum. Check that you want these details published before committing it.

The PDF is an educational triage aid, not incident-specific advice. Verify current Microsoft portal labels, feature availability and your tenant's procedures before acting.
