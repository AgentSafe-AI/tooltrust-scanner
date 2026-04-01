# IOC Pipeline

ToolTrust now supports a small, curated IOC feed for supply-chain detection.

This document defines how threat-intel findings move from blog posts or advisories
into scanner-enforced data files such as:

- `pkg/analyzer/data/blacklist.json`
- `pkg/analyzer/data/npm_iocs.json`

## Goals

- Keep IOC updates data-driven instead of editing Go logic for every incident
- Separate low-confidence candidate intel from scanner-enforced detections
- Require human review before promoting new blocking or critical rules

## Current Data Files

### `pkg/analyzer/data/blacklist.json`

Use for:

- confirmed malicious versions
- confirmed compromised releases
- known-bad version ranges with strong public attribution

These entries typically map to `AS-008`.

### `pkg/analyzer/data/npm_iocs.json`

Use for:

- malicious IOC package names
- known dropper/helper package names
- metadata-level indicators that can be detected without tarball scanning

These entries currently map to `AS-016`.

## Candidate Flow

1. Threat-intel monitor opens an issue for a new incident or blog post.
2. Maintainer extracts candidate IOCs into a structured candidate JSON file.
3. Candidate is reviewed and classified:
   - `promote_to: blacklist`
   - `promote_to: npm_iocs`
   - `promote_to: watch_only`
4. Maintainer adds the reviewed entry to the scanner data file.
5. Tests are updated to cover the new signal.
6. A scanner release/tag is cut so ToolTrust Directory can consume the update.

## Candidate Schema

Candidate IOC files should validate against:

- `.github/ioc-candidates.schema.json`

Recommended fields:

- `ecosystem`
- `ioc_type`
- `value`
- `confidence`
- `reason`
- `source`
- `first_seen`
- `suggested_action`
- `promote_to`

Example candidate entry:

```json
{
  "ecosystem": "npm",
  "ioc_type": "package_name",
  "value": "plain-crypto-js",
  "confidence": "high",
  "reason": "Observed in the malicious axios npm publish on March 31, 2026.",
  "source": "https://example.com/incident-writeup",
  "first_seen": "2026-03-31",
  "suggested_action": "flag",
  "promote_to": "npm_iocs"
}
```

## Promotion Rules

Promote to `blacklist.json` when:

- a specific version or version range is confirmed malicious
- public attribution is strong enough to justify blocking
- the action should be immediate and deterministic

Promote to `npm_iocs.json` when:

- the IOC is a suspicious package or metadata indicator
- it can appear across multiple compromised publishes
- it is useful even when the final malicious version is not yet blacklisted

Keep as `watch_only` when:

- attribution is weak
- only one unverified report exists
- the signal is too noisy for scanner enforcement

## What This Does Not Cover Yet

- full tarball signature scanning
- JS source-code fingerprinting
- fuzzy matching over obfuscated payloads
- automatic promotion from issue feed to blocking rules

Those should come later, after the candidate data flow is stable.
