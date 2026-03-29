#!/usr/bin/env python3
"""Check security blog RSS feeds and create GitHub issues for new posts."""

import feedparser
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

STATE_FILE = ".github/threat-intel-state.json"

FEEDS = [
    # Confirmed working RSS feeds
    {"source": "Embrace The Red", "url": "https://embracethered.com/blog/index.xml"},
    {"source": "Trail of Bits",   "url": "https://blog.trailofbits.com/index.xml"},
    # TODO: add proxy RSS URLs for Koi Security, Invariant Labs, Pillar Security
]

state = {}
if Path(STATE_FILE).exists():
    state = json.loads(Path(STATE_FILE).read_text())

new_state = dict(state)
issues_created = 0
repo = os.environ["REPO"]

for feed_info in FEEDS:
    source = feed_info["source"]
    url = feed_info["url"]
    last_seen = state.get(source, "2020-01-01T00:00:00+00:00")
    last_seen_dt = datetime.fromisoformat(last_seen)
    latest_dt = last_seen_dt

    try:
        feed = feedparser.parse(url)
    except Exception as e:
        print(f"[{source}] fetch error: {e}")
        continue

    if feed.bozo and not feed.entries:
        print(f"[{source}] could not parse feed: {url}")
        continue

    for entry in feed.entries:
        pub = entry.get("published_parsed") or entry.get("updated_parsed")
        if not pub:
            continue
        entry_dt = datetime(*pub[:6], tzinfo=timezone.utc)
        if entry_dt <= last_seen_dt:
            continue

        title = entry.get("title", "Untitled")
        link  = entry.get("link", url)
        date  = entry_dt.strftime("%Y-%m-%d")

        body = (
            f"**Source:** {source}\n"
            f"**URL:** {link}\n"
            f"**Date:** {date}\n"
            f"**Attack pattern:** *(fill in after reading)*\n\n"
            f"### ToolTrust coverage\n"
            f"- [ ] Existing rule covers this\n"
            f"- [ ] Rule needs pattern update\n"
            f"- [ ] New rule needed\n"
            f"- [ ] Needs source-code analysis (not coverable today)\n\n"
            f"### Test fixture added?\n"
            f"- [ ] Yes — added to `tests/fixtures/`\n"
        )
        result = subprocess.run(
            ["gh", "issue", "create",
             "--repo", repo,
             "--title", f"[threat-intel] {source}: {title}",
             "--body", body,
             "--label", "threat-intel"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            print(f"[{source}] created issue: {title}")
            issues_created += 1
            if entry_dt > latest_dt:
                latest_dt = entry_dt
        else:
            print(f"[{source}] issue creation failed: {result.stderr.strip()}")

    new_state[source] = latest_dt.isoformat()

Path(STATE_FILE).parent.mkdir(parents=True, exist_ok=True)
Path(STATE_FILE).write_text(json.dumps(new_state, indent=2) + "\n")
print(f"\nDone. {issues_created} new issue(s) created.")
