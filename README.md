# Threat Intelligence

Generic, vendor-neutral templates for a cyber threat intelligence (CTI) program, organised by sub-process. All examples are fictional (Contoso Ltd., documentation IP ranges, example domains).

## Find by sub-process

| Sub-process | Folder | What you get | Use it when |
|---|---|---|---|
| Program and requirements | [program-and-requirements](./program-and-requirements) | Charter, PIR/EEI, TLP, sharing agreement | Starting or steering the program |
| Brand abuse | [brand-abuse](./brand-abuse) | Monitoring checklist, dark web procedure, takedown workflow and request | Impersonation of brand, domains, apps, profiles |
| Data breach and leaks | [data-breach-and-leaks](./data-breach-and-leaks) | Data leak triage template | Claims that data is exposed |
| Credential leaks | [credential-leaks](./credential-leaks) | Credential leak response runbook | Exposed usernames, passwords, tokens |
| Phishing and fraud intel | [phishing-and-fraud-intel](./phishing-and-fraud-intel) | Phishing domain investigation template | Suspicious links and fraud campaigns |
| Vulnerability intelligence | [vulnerability-intelligence](./vulnerability-intelligence) | KEV/EPSS-style prioritization and list | Deciding what to patch first |
| Threat actors and campaigns | [threat-actors-and-campaigns](./threat-actors-and-campaigns) | Actor profile, campaign tracking, ATT&CK heatmap | Understanding adversaries |
| Ioc management | [ioc-management](./ioc-management) | Register, lifecycle, feeds, STIX, watchlists, handoff | Operationalizing indicators |
| Threat hunting | [threat-hunting](./threat-hunting) | Hypothesis, playbook, samples | Proactive searching |
| Reporting | [reporting](./reporting) | Landscape report | Communicating intelligence |

## How to use

1. Pick the sub-process you are in and open its folder README.
2. Copy the template you need.
3. Replace every `<PLACEHOLDER>` with your own values.
4. Review with your own legal and security teams before adopting.
5. Never put real indicators or client data in this repository.

## License
Elastic License 2.0: free to use, copy and modify, including inside your own company and for your own clients' projects. You may not provide it to third parties as a hosted or managed service. See [LICENSE](./LICENSE).
