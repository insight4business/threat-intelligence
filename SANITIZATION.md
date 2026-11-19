# Sanitization rules

Nothing in this repository may identify a client, a person or a real system.

## Never include
- Company, client, partner or project names tied to real work
- Hostnames, domains, URLs, IP addresses, e-mail addresses, phone numbers
- Cloud account, subscription, tenant or object IDs, ARNs, resource names
- Secrets, tokens, keys, certificates, KeePass or vault exports
- Screenshots or exports from real environments
- Verbatim text from ISO standards or paid frameworks (use your own wording, cite only the control number)

## Use instead
- `example.com`, `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` (documentation ranges)
- `<TENANT_ID>`, `<ACCOUNT_ID>`, `<RESOURCE_NAME>` placeholders
- Fictional company: **Contoso Ltd.**

## Process
1. Run `python3 tools/sanitize.py` before every commit.
2. Keep a private `tools/denylist.local.txt` (git-ignored) with real client terms; the script reads it when present.
3. Review by a second person before publishing.
