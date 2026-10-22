---
title: October 2026 Patch Tuesday: what the Microsoft feed shows and what to do
date: 2026-10-20
summary: The Microsoft feed lists few entries, and most of them are updates to October's release rather than new fixes. The one item that needs planning is a .NET remote code execution flaw that Microsoft has not fixed yet. Identity Web and WSL need version checks if you use them.
draft: false
---

## Short answer

Patch Tuesday was on 13 October 2026. The feed entries in this snapshot are dated 16 to 20 October, so most of them are **changes to existing entries**, not new fixes. Only one entry needs planning now: **CVE-2026-70197 (.NET remote code execution)**. Microsoft says it has not been addressed yet, so there is no patch to install. Two other items need a version check if you use the products: **Microsoft Identity Web** and **WSL**. Everything else is informational.

## Why the table looks small

The feed has one "new CVE" and seven revisions. Three things explain that:

1. **Timing.** The feed shows when an entry changed, not when Microsoft released it. The dates here are 16 to 20 October, a week after Patch Tuesday.
2. **Revisions are not new fixes.** Microsoft changes entries to fix links, correct version ranges or add acknowledgements. The feed says so for each item.
3. **Grouped entries.** One Chromium entry names more than twenty CVE IDs. The "1 new CVE" count does not reflect that.

The feed in this snapshot is partial. It cannot be used to check the month's total fix count, so do not compare it with headline numbers. Use the Security Update Guide for the complete picture.

## Triage: what needs action

| Item | What changed | Exploitation | My priority | Action |
| --- | --- | --- | --- | --- |
| **CVE-2026-70197** .NET RCE | Microsoft says it is aware, the issue is not addressed, and a mitigation is being prepared | Not reported | **Plan now** | No fix to install yet. Find .NET applications that accept network input. Apply Microsoft's mitigation as soon as it is published. |
| **CVE-2026-80092** Identity Web EoP | Entry now lists v3 and v4 separately. Fixed versions: 3.16.0 (v3) and 4.16.1 (v4) | Not reported | This week, if you use it | Check your NuGet package versions and update to the fixed version for your line. |
| **CVE-2026-102204** WSL EoP | Entry now says the flaw is in WSL. Install the latest version | Not reported | Routine | Run `wsl --version` and update with `wsl --update` if you are behind. |
| CVE-2026-62913 Exchange RCE | Acknowledgement update only. Lists several other IDs, including the .NET one | Not reported | No action | Stay on your current Exchange cumulative update. |
| CVE-2026-106258 and related Chromium IDs | Edge receives these through Chromium | Not reported | Routine | Keep Edge current. Check `edge://settings/help`. |
| CVE-2026-83782 Windows Shell RCE | Acknowledgement update | Not reported | No action | None, unless you track this product closely. |
| CVE-2026-70074 Windows DNS info disclosure | Acknowledgement update | Not reported | No action | None. |
| CVE-2026-108465 Delivery Optimization EoP | Acknowledgement update | Not reported | No action | None. |
| CVE-2026-103572 Visual Studio Tools / SSMS RCE | Download and KB links added. Fixed builds unchanged | Not reported | No action | None. |

No item in this snapshot is in CISA's Known Exploited Vulnerabilities catalog. No item is marked Critical or High by the feed.

## Why the .NET item matters more than its label

The feed marks CVE-2026-70197 as "Normal cycle", which suggests you can wait for your next maintenance window. That is misleading. A normal-cycle patch needs a fix to deploy, and there is none yet. The useful question is not "when do we patch?" but "what can we do before the fix exists?"

Work through three questions:

1. **Exposure.** Which of your .NET applications receive input from users, partners or the internet? Which of them run with high privileges?
2. **Interim control.** Can you restrict network access to those applications, or put them behind a filter, until the mitigation arrives?
3. **Trigger.** Who checks the Security Update Guide entry each day, and who decides to apply the mitigation? Name that person now.

**Confidence:** Confirmed by the feed: the flaw is listed as not addressed, and a mitigation is in preparation. Unclear: which .NET versions and product areas are affected, and how the flaw is exploited. Read the Security Update Guide entry before you assess exposure.

## Why Identity Web is worth checking this week

Identity Web is a Microsoft library used by .NET applications to sign users in with Microsoft Entra ID. An elevation of privilege flaw means an attacker must already have some access to exploit it, so the urgency is lower than for a remote code execution flaw. But if your applications use it for sign-in, the impact can reach your identity layer.

What to check:

1. Find the packages in your solutions. In a .NET project folder, run `dotnet list package` and look for `Microsoft.Identity.Web` and its sub-packages.
2. Compare the version with the fixed versions: 3.16.0 for the v3 line, 4.16.1 for the v4 line.
3. Update through your normal release process. Do not patch production code without testing sign-in.

Note: `dotnet list package --vulnerable` checks NuGet's advisory data. It may not show this flaw yet, so do the manual version check.

## What I would do this week

1. **Today:** read the Security Update Guide entry for CVE-2026-70197 and write down its current status and the date you last checked.
2. **This week:** inventory .NET applications for network exposure, and check Identity Web versions.
3. **This week:** run `wsl --version` on machines that use WSL, and update where needed.
4. **Ongoing:** keep the .NET entry on a short watch list. Apply the mitigation on the day it is released, not at the next window.

What to leave alone: do not change Exchange, Visual Studio or Windows core components for these entries. The feed shows no new fix for them.

## Confidence and limits

- **Confirmed:** the dates, the revision types and the fix status given in the feed entries.
- **Likely:** most entries in a late-month feed are revisions, not new releases. This is inferred from the feed dates and text.
- **Unclear:** the full list of October fixes, and the exact count. The feed in this snapshot is partial.
- **Speculation:** none in this note.

## Sources

- Microsoft Security Response Center update feed, entries dated 16 to 20 Oct 2026 (snapshot used for this note).
- Microsoft Security Update Guide: <https://msrc.microsoft.com/update-guide/>
