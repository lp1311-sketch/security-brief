---
title: Weekly M365 & Entra Briefing: 13 to 19 October 2026
date: 2026-10-20
summary: Exchange sign-in problems after October Windows Server updates, an identity-based incident at ConnectWise that affected Microsoft 365 tenants, and why device-code abuse is still worth a Conditional Access check.
draft: false
---

## What happened

- **Exchange Server after October Windows Server updates.** Microsoft has confirmed that the October Windows Server security updates can break OWA sign-in and mail delivery on some on-premises Exchange Server systems. Microsoft has shared a temporary registry-key workaround while it works on a fix. Source: [Microsoft: October Windows Server updates break Exchange sign-in, mail flow (BleepingComputer, 19 Oct 2026)](https://www.bleepingcomputer.com/news/microsoft/microsoft-october-windows-server-updates-cause-exchange-issues/).
- **ConnectWise and Microsoft 365 tenants.** According to The Hacker News and BleepingComputer (18 Oct 2026), unknown threat actors compromised Microsoft 365 tenants in an incident involving ConnectWise. ConnectWise says it has disabled seven of its application identities while the investigation continues. The full scope is not yet public.
- **Microsoft on AI agents.** On 19 Oct 2026, the Microsoft Security Blog framed agents as "your newest insiders" whose security has to keep pace with how fast they work. The excerpt is high-level, so treat it as direction rather than a control.
- **Device-code phishing remains active as a technique.** Microsoft's September 2026 research on device-code phishing ("EvilTokens") shows how attackers obtain tokens without stealing passwords. Source: [Unmasking EvilTokens: getting to the root of device code phishing (Microsoft Security Blog, 22 Sep 2026)](https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/).

## Impact on Microsoft 365 and Entra

- **Confirmed:** the reports describe on-premises Exchange Server systems that installed the October 2026 Windows security updates. They do not describe Exchange Online.
- **Likely relevant, not yet confirmed for you:** the ConnectWise incident matters if your tenant has third-party applications or service principals from ConnectWise or similar management tools.
- **Unclear:** how the ConnectWise attackers got access, and whether any Microsoft 365 data was accessed. Do not treat either point as known until the vendor or Microsoft confirms it.

## What I would check this week

1. **Exchange on-premises:** send and receive a test message and sign in to OWA with a test account on one server first. Read Microsoft's notice before you apply any registry change. Do not change the registry on every server without a test.
2. **Third-party app identities:** in the Entra admin center, go to **Identity → Applications → Enterprise applications**, filter by the vendor name, and review **Sign-in logs** for the application ID. Check **Monitoring & health → Audit logs** for new credentials or consent grants in the last 30 days.
3. **Device-code flow:** in **Protection → Conditional Access → Policies**, check whether a policy blocks the *Device code flow* authentication flow for users who do not need it. Review the sign-in logs for device-code sign-ins before you block anything, because some legacy tools depend on this flow.
4. **Smart App Control and Outlook Copilot buttons:** only check these if your users are affected. They do not need action on a normal tenant.

What to leave alone: do not revoke all app consents or all sessions unless you have evidence of misuse. Mass revocation breaks business applications.

## Confidence

Confirmed by the source reports: the Exchange issue and the ConnectWise account action. Likely: the ConnectWise incident has wider impact than the excerpt shows. Speculation: none in this briefing.

## Sources

- BleepingComputer, 19 Oct 2026: [Microsoft: October Windows Server updates break Exchange sign-in, mail flow](https://www.bleepingcomputer.com/news/microsoft/microsoft-october-windows-server-updates-cause-exchange-issues/)
- The Hacker News / BleepingComputer, 18 Oct 2026: ConnectWise suspends cloud backup after attackers compromise Microsoft 365 tenants (original link to be added after review)
- Microsoft Security Blog, 19 Oct 2026: Agents are your newest insiders (original link to be added after review)
- Microsoft Security Blog, 22 Sep 2026: [Unmasking EvilTokens](https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/)
