#!/usr/bin/env python3
"""Fail if repository files contain data that could identify a client or real system."""
import re, sys, pathlib
ROOT = pathlib.Path(__file__).resolve().parent.parent
SKIP_DIRS = {".git", "node_modules", ".terraform"}
TEXT_EXT = {".md", ".txt", ".csv", ".json", ".yml", ".yaml", ".tf", ".kql", ".spl", ".py", ".ps1", ".sh", ".toml", ".tfvars", ".hcl", ".xml", ""}
DOC_IPS = ("192.0.2.", "198.51.100.", "203.0.113.", "10.0.0.", "127.0.0.", "0.0.0.0")
OK_DOMAINS = {"example.com", "example.org", "contoso.com", "github.com", "creativecommons.org", "mitre.org", "nist.gov", "attack.mitre.org", "learn.microsoft.com", "docs.splunk.com", "terraform.io", "hashicorp.com", "owasp.org", "cisa.gov", "first.org", "iso.org", "json-schema.org", "elastic.co", "apache.org", "microsoft.com", "microsoftonline.com", "windows.net", "azure.com", "azure.net", "powershellgallery.com", "github.io", "sharepoint.com", "office.com", "office365.com", "windows.com", "visualstudio.com", "dev.azure.com", "aka.ms", "chocolatey.org"}
PATTERNS = {
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "url": re.compile(r"https?://[^\s)>\"']+"),
    "aws_account": re.compile(r"(?<!\d)\d{12}(?!\d)"),
    "arn": re.compile(r"arn:aws:[a-z0-9-]+:[a-z0-9-]*:\d{12}:"),
    "guid": re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"),
    "secret": re.compile(r"(?i)(password|secret|token|apikey|api_key|private_key)\s*[:=]\s*['\"]?(?!Get-)[A-Za-z0-9/+_=-]{12,}"),
    "private_key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
}
def deny_terms():
    p = ROOT / "tools" / "denylist.local.txt"
    return [l.strip().lower() for l in p.read_text().splitlines() if l.strip() and not l.startswith("#")] if p.exists() else []
def main():
    terms, bad = deny_terms(), []
    for f in ROOT.rglob("*"):
        if not f.is_file() or any(s in f.parts for s in SKIP_DIRS) or f.suffix.lower() not in TEXT_EXT or f.name in {"sanitize.py", "SANITIZATION.md", "denylist.local.txt"}:
            continue
        try: text = f.read_text(errors="ignore")
        except Exception: continue
        rel = f.relative_to(ROOT)
        for name, rx in PATTERNS.items():
            for m in rx.finditer(text):
                v = m.group(0)
                if name == "ipv4" and (v.startswith(DOC_IPS) or any(int(x) > 255 for x in v.split("."))): continue
                if name == "url" and any(d in v for d in OK_DOMAINS): continue
                if name == "email" and v.lower().endswith(("@example.com", "@contoso.com")): continue
                if name == "aws_account" and v in ("000000000000", "123456789012"): continue
                if name == "guid" and v.startswith("00000000-"): continue
                bad.append(f"{rel}: {name}: {v[:60]}")
        low = text.lower()
        for t in terms:
            if t in low: bad.append(f"{rel}: denylist: <term hidden>")
    if bad:
        print("SANITIZATION FAILED"); [print(" -", b) for b in sorted(set(bad))[:200]]; sys.exit(1)
    print("sanitize: OK")
if __name__ == "__main__": main()
