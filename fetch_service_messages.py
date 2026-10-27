#!/usr/bin/env python3
"""Read-only export of Microsoft 365 service messages and incidents for the Security Brief.

Writes data/service-messages.json, which build.py reads. Nothing is written to the tenant.

Setup (once, by a Global Admin or Application Admin):
  1. Entra admin center -> App registrations -> New registration (single tenant, no redirect URI).
  2. API permissions -> Microsoft Graph -> Application permissions:
       ServiceHealth.Read.All   (service incidents/issues)
       ServiceMessage.Read.All  (Message center posts)
  3. Grant admin consent for the tenant.
  4. Certificates & secrets -> new client secret (or preferably a certificate). Store it as a
     GitHub Actions secret, never in the repository.

Run (environment variables only, no secrets in files):
  export TENANT_ID=... CLIENT_ID=... CLIENT_SECRET=...
  python3 scripts/fetch_service_messages.py --out data/service-messages.json

Output format:
  {"generated": "...", "messages": [{"id", "title", "body", "type", "category", "severity",
     "isMajorChange", "services", "startDateTime", "lastModifiedDateTime",
     "actionRequiredByDateTime"}]}

Verify endpoint names and fields against learn.microsoft.com (Graph v1.0,
serviceAnnouncement resource) before the first production run.
Exits non-zero on any error and leaves an existing output file untouched.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests

GRAPH = "https://graph.microsoft.com/v1.0"
TOKEN_URL = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
PAGE_LIMIT = 200  # hard cap on pages per endpoint


def token() -> str:
    try:
        tenant, client, secret = os.environ["TENANT_ID"], os.environ["CLIENT_ID"], os.environ["CLIENT_SECRET"]
    except KeyError as e:
        sys.exit(f"Missing environment variable: {e.args[0]}")
    r = requests.post(TOKEN_URL.format(tenant=tenant), timeout=30, data={
        "client_id": client, "client_secret": secret, "grant_type": "client_credentials",
        "scope": "https://graph.microsoft.com/.default"})
    if r.status_code != 200:
        sys.exit(f"Token request failed: HTTP {r.status_code}")  # do not print the response body
    return r.json()["access_token"]


def get_all(session: requests.Session, path: str) -> list[dict]:
    url, out, pages = f"{GRAPH}{path}", [], 0
    while url and pages < PAGE_LIMIT:
        r = session.get(url, timeout=60)  # GET only: this script never writes
        if r.status_code != 200:
            sys.exit(f"Graph GET {path} failed: HTTP {r.status_code}")
        data = r.json()
        out.extend(data.get("value", []))
        url = data.get("@odata.nextLink")
        pages += 1
    return out


def plain(html: str | None) -> str:
    text = re.sub(r"<[^>]+>", " ", html or "")
    return re.sub(r"\s+", " ", text).strip()


def normalise(msgs: list[dict], issues: list[dict]) -> list[dict]:
    rows = []
    for m in msgs:
        rows.append({
            "id": m.get("id"), "title": m.get("title"),
            "body": plain((m.get("body") or {}).get("content")),
            "type": "message", "category": m.get("category"), "severity": m.get("severity"),
            "isMajorChange": m.get("isMajorChange"), "services": m.get("services") or [],
            "startDateTime": m.get("startDateTime"), "lastModifiedDateTime": m.get("lastModifiedDateTime"),
            "actionRequiredByDateTime": m.get("actionRequiredByDateTime"),
        })
    for i in issues:
        if i.get("isResolved"):
            continue  # open incidents only
        rows.append({
            "id": i.get("id"), "title": i.get("title"),
            "body": plain(i.get("impactDescription")),
            "type": "incident" if str(i.get("classification", "")).lower() == "incident" else "advisory",
            "category": i.get("feature") or i.get("origin"), "severity": i.get("severity"),
            "isMajorChange": None, "services": [i["service"]] if i.get("service") else [],
            "startDateTime": i.get("startDateTime"), "lastModifiedDateTime": i.get("lastModifiedDateTime"),
            "actionRequiredByDateTime": None,
        })
    rows.sort(key=lambda r: r.get("lastModifiedDateTime") or "", reverse=True)
    return rows


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, default=Path("data/service-messages.json"))
    args = ap.parse_args()

    s = requests.Session()
    s.headers["Authorization"] = f"Bearer {token()}"
    s.headers["Accept"] = "application/json"
    msgs = get_all(s, "/admin/serviceAnnouncement/messages")
    issues = get_all(s, "/admin/serviceAnnouncement/issues")
    rows = normalise(msgs, issues)

    payload = {"generated": datetime.now(timezone.utc).isoformat(timespec="seconds"), "messages": rows}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    tmp = args.out.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=1), encoding="utf-8")
    tmp.replace(args.out)  # atomic: a failed run never leaves a half-written file
    print(f"Wrote {len(rows)} entries to {args.out}")


if __name__ == "__main__":
    main()
