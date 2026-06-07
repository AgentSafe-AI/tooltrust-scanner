# IOC Blacklist Auto-Candidate Pipeline

This workflow adds a daily review loop for OSV-confirmed malicious packages without silently editing the live scanner data.

## What it does

- pulls the per-ecosystem OSV feed for `npm`, `PyPI`, and `Go`
- filters to records published in the last 24 hours
- keeps only `MAL-` records — OSV's namespace for confirmed malicious packages (sourced from OpenSSF malicious-packages, Amazon Inspector, GitHub Advisory, and similar)
- skips package versions already present in `pkg/analyzer/data/blacklist.json`
- opens one review-only digest PR per day with the new confirmed malicious packages

The workflow never auto-merges. A human still decides whether a candidate belongs in the enforced AS-008 blacklist.

## Why this exists

The daily digest surfaces newly confirmed malicious packages (typosquats, hijacked releases, protestware) shortly after OSV indexes them. It separates the intelligence-gathering step from scanner enforcement:

- **Ordinary CVEs** (RCE, SSRF, etc.) are already covered by AS-004 real-time OSV lookup and must not flow through this pipeline.
- **Confirmed malicious packages** (`MAL-` records) are what this pipeline collects; humans pick the high-value ones (e.g. known popular packages) to promote into AS-008.

The old keyword-based approach incorrectly gated on CVSS severity, which `MAL-` records do not carry, so it could never surface a real malicious package.

## Review checklist

When the workflow opens a PR:

1. check the `notes` field for source attribution (amazon-inspector, ossf-package-analysis, etc.)
2. confirm the affected version range is exact and narrow enough
3. decide whether the package is high-value enough to add to AS-008, or whether AS-004 real-time OSV coverage is sufficient
4. rewrite the reason if the current summary is too vague for triage
5. close the PR after triage unless it is being converted into a curated data update

## Local dry run

```bash
go run ./scripts/ioc-candidates \
  -since 720h \
  -ecosystems npm,PyPI,Go \
  -out /tmp/candidates.json \
  -existing pkg/analyzer/data/blacklist.json
```

That gives a 30-day sample so you can inspect candidate quality before relying on the scheduled workflow.

## Failure behavior

- transient OSV fetch failures log a warning and produce an empty candidate set
- the workflow does not fail `main` because an upstream feed had a bad day
- a no-op day simply means no PR is opened

## Scope

This is intentionally narrow:

- it only proposes additions to the blacklist
- it does not auto-remove entries
- it does not cover pre-advisory blog posts or social-media disclosures
- it does not replace the existing threat-intel issue workflow

Those are follow-ups once candidate quality is stable.
