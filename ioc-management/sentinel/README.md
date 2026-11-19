# Sentinel

Scripts for the **sentinel-threat-intelligence** technology in this sub-process.

## Scripts adapted from field work

Each script solves one problem. They were adapted from real operations work: replace every `ENTRE_AQUI_COM_SEU_*` marker, review, and test in a non-production tenant first.

| Script | Problem it solves | What it does | Requires | Effect | Notes |
|---|---|---|---|---|---|
| `sentinel-upload-iocs-from-excel.ps1` | IOCs from intel reports must reach Sentinel. | Reads IOC Excel and creates indicators with expirations. | ImportExcel, Az; Sentinel Contributor | changes-state | Variables empty; expiration values like 90d are not valid PowerShell timespans: fix |
