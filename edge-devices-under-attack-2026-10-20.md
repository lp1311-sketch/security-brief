---
title: The edge is where attackers get in: this week's firewall, VPN and remote-access exploits
date: 2026-10-20
summary: Five exploited flaws in firewalls, VPNs, remote-support software and file-sharing servers show one pattern. The systems that sit at the edge of your network, and that administrators manage remotely, are the weakest link. Here is what to check first.
draft: false
---

## Short answer

Between 14 and 19 October 2026, several internet-facing systems were reported as exploited: Palo Alto PAN-OS, Fortinet FortiOS, BeyondTrust Remote Support, Nextcloud with the Collabora CODE app, and AhsayCBS. These are not desktop bugs. They are the systems that let people in from outside your network. The first question to answer is not "did we patch?" but **"can anyone reach these management interfaces from the internet, and would we notice if they had?"**

## What happened

- **Palo Alto Networks PAN-OS (CVE-2026-0322, CVSS 8.6).** A remote code execution flaw in the management interface, patched while under active exploitation. CISA lists it in its Known Exploited Vulnerabilities (KEV) catalog. Source: [Palo Alto Networks Patches PAN-OS Authenticated RCE Flaw Amid Active Exploitation (The Hacker News, 15 Oct 2026)](https://thehackernews.com/2026/10/palo-alto-networks-patches-pan-os.html).
- **Fortinet FortiOS (CVE-2025-61624).** A suspected advanced threat actor used this flaw to deliver a new memory-resident ARM64 malware, PEERSTITCH. The reported actor, CL-STA-0954, removes forensic traces: it stops syslog generation, clears crash logs, disrupts logging telemetry, and deletes rogue administrator accounts after use. CISA added the flaw to KEV on 16 October with a federal deadline of 19 October. Source: [PEERSTITCH Malware Deployed via FortiOS Flaw (The Hacker News, 16 Oct 2026)](https://thehackernews.com/2026/10/attackers-exploit-fortios-flaw-to.html).
- **BeyondTrust Remote Support.** Reporting on 16 October says a China-nexus group, tracked as Armory Castle, exploited a newly disclosed flaw as a zero-day in late August 2026 to take over remote-support servers. Source: The Hacker News and BleepingComputer, 16 Oct 2026. *(Original link to add after review.)*
- **Nextcloud with Collabora CODE (CVE-2026-110447).** Attackers planted web shells on Nextcloud servers through an optional app. Three administrators reported the problem, and the first logged attack was on 10 September. The vendor says that disabling the app does not help: you must upgrade to version 26.4.303 or later, or remove it. Source: [Hackers Backdoor Nextcloud Servers (The Hacker News, 14 Oct 2026)](https://thehackernews.com/2026/10/hackers-backdoor-nextcloud-servers.html).
- **AhsayCBS.** Two flaws were exploited to deploy web shells and cryptominers. The vendor's first fixes were incomplete, and new fixes followed on 15 October. Source: The Hacker News, 15 Oct 2026. *(Original link to add after review.)*

## Why this is a pattern, not a coincidence

Each of these products is designed to be reached from outside: a firewall management interface, a VPN gateway, a remote-support server, a file-sharing server, a backup console. Attackers want exactly these systems because they combine three things: they often run with high privileges, they are hard to monitor with normal endpoint tools, and patching them means a service interruption, so they are often patched late.

The FortiOS case shows why the usual "check for malware on the endpoint" approach is not enough. The reported actor deletes the administrator accounts it creates and clears the logs it leaves behind. If you only look for files, you can miss the compromise.

## Confidence

- **Confirmed by the sources:** the KEV listings for PAN-OS and FortiOS; the Nextcloud advisory that disabling the app is not a fix.
- **Likely:** the BeyondTrust and AhsayCBS campaigns affect more organisations than the reports name. The reports do not give victim counts.
- **Unclear:** how many organisations are compromised. No evidence in these sources says that your organisation is affected.

## What I would check this week

1. **Exposure first.** List every firewall management interface, VPN gateway, remote-support server and file-sharing app that answers from the internet. On PAN-OS, check the permitted IP addresses for the management interface (Device → Setup → Management in the web interface, paths can differ by version). Anything reachable from the internet that does not need to be should be restricted or removed.
2. **FortiOS administrators.** In the FortiOS web interface, go to **System → Administrators** and compare the list with your records. Look for accounts you did not create, and check when each one was last used. Also check whether syslog forwarding to your SIEM has gaps around the dates in the report.
3. **Nextcloud and Collabora.** Confirm the Collabora Online / CODE app version. If it is older than 26.4.303, upgrade it or remove it. Disabling the app is not enough according to the vendor. Look for unknown PHP or script files in the Nextcloud web directories.
4. **Remote-support sessions.** For BeyondTrust or any remote-support tool, review session logs and administrator logins for the last 60 days. Look for logins at unusual hours, from unfamiliar IP addresses, or for sessions you did not schedule.
5. **Patch timing for edge devices.** Agree with your team that KEV-listed edge flaws are patched within days, not in the next maintenance window. Document the exception process if you cannot.

What to leave alone: do not reboot or reconfigure production firewalls during business hours without a rollback plan. Change the exposure rules in a maintenance window, and test them first.

## Lesson from this week

Remove what you do not need on the internet. The fastest protection is to make an edge system unreachable, not to patch it faster. Patching still matters, but a management interface that is not reachable from outside cannot be exploited from outside.

## Sources

- The Hacker News, 15 Oct 2026: [Palo Alto Networks Patches PAN-OS Authenticated RCE Flaw Amid Active Exploitation](https://thehackernews.com/2026/10/palo-alto-networks-patches-pan-os.html)
- The Hacker News, 16 Oct 2026: [Attackers Exploit FortiOS Flaw to Deploy PEERSTITCH](https://thehackernews.com/2026/10/attackers-exploit-fortios-flaw-to.html)
- The Hacker News, 14 Oct 2026: [Hackers Backdoor Nextcloud Servers Through Critical Flaw in Collabora's Built-in CODE App](https://thehackernews.com/2026/10/hackers-backdoor-nextcloud-servers.html)
- The Hacker News and BleepingComputer, 16 Oct 2026: BeyondTrust Remote Support zero-day (original link to add)
- The Hacker News, 15 Oct 2026: AhsayCBS flaws (original link to add)
