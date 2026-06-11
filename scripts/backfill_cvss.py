#!/usr/bin/env python3
"""One-time CVSS backfill for historical CVE shards.

Pages the full NVD API 2.0 corpus, extracts CVSS for every CVE that is
missing it in docs/database/CVE-*.jsonl.gz, and rewrites only the shards
that gained data. Fallback order matches cve_processor.py:
cvssMetricV40 -> V31 -> V30 -> V2.

Keyless NVD rate limit is 5 requests / 30s; with NVD_API_KEY it is 50 / 30s.
Progress checkpoints to scripts/.cvss_backfill_checkpoint.json so an
interrupted run resumes at the last completed page.

Usage: python scripts/backfill_cvss.py [--dry-run]
"""

import argparse
import gzip
import json
import os
import sys
import time
from pathlib import Path

import requests

REPO_ROOT = Path(__file__).resolve().parent.parent
SHARD_DIR = REPO_ROOT / "docs" / "database"
CHECKPOINT = Path(__file__).resolve().parent / ".cvss_backfill_checkpoint.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 2000
CVSS_KEYS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")


def extract_cvss(cve: dict) -> dict | None:
    metrics = cve.get("metrics", {})
    for key in CVSS_KEYS:
        metric_list = metrics.get(key) or []
        primary = next(
            (m for m in metric_list if m.get("type") == "Primary"),
            metric_list[0] if metric_list else None,
        )
        if primary:
            data = primary.get("cvssData", {})
            score = data.get("baseScore")
            if score is None:
                continue
            return {
                "score": score,
                "vector": data.get("vectorString", ""),
                "severity": data.get("baseSeverity") or primary.get("baseSeverity", ""),
                "version": data.get("version", ""),
            }
    return None


def load_missing_ids() -> set:
    missing = set()
    for shard in sorted(SHARD_DIR.glob("CVE-*.jsonl.gz")):
        with gzip.open(shard, "rt") as f:
            for line in f:
                cve_id, rec = next(iter(json.loads(line).items()))
                if not rec.get("CVSS"):
                    missing.add(cve_id)
    return missing


def fetch_cvss_map(missing: set, delay: float) -> dict:
    found: dict = {}
    start_index = 0
    if CHECKPOINT.exists():
        state = json.loads(CHECKPOINT.read_text())
        start_index = state["next_index"]
        found = state["found"]
        print(f"Resuming from startIndex={start_index} ({len(found)} already found)")

    headers = {}
    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key

    session = requests.Session()
    total = None
    while total is None or start_index < total:
        for attempt in range(6):
            try:
                resp = session.get(
                    NVD_URL,
                    params={"resultsPerPage": PAGE_SIZE, "startIndex": start_index},
                    headers=headers,
                    timeout=60,
                )
                if resp.status_code == 200:
                    break
                print(f"HTTP {resp.status_code} at index {start_index}, "
                      f"retry {attempt + 1}/6", flush=True)
            except requests.RequestException as e:
                print(f"Request error at index {start_index}: {e}, "
                      f"retry {attempt + 1}/6", flush=True)
            time.sleep(min(delay * (2 ** attempt), 120))
        else:
            raise SystemExit(f"NVD unreachable after 6 retries at index {start_index}")

        payload = resp.json()
        total = payload["totalResults"]
        for item in payload.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id")
            if cve_id in missing:
                cvss = extract_cvss(cve)
                if cvss:
                    found[cve_id] = cvss

        start_index += PAGE_SIZE
        CHECKPOINT.write_text(json.dumps({"next_index": start_index, "found": found}))
        pages_done = start_index // PAGE_SIZE
        pages_total = (total + PAGE_SIZE - 1) // PAGE_SIZE
        print(f"Page {pages_done}/{pages_total} — {len(found)} CVSS found", flush=True)
        time.sleep(delay)
    return found


def apply_to_shards(found: dict, dry_run: bool) -> None:
    for shard in sorted(SHARD_DIR.glob("CVE-*.jsonl.gz")):
        lines, updated = [], 0
        with gzip.open(shard, "rt") as f:
            for line in f:
                obj = json.loads(line)
                cve_id, rec = next(iter(obj.items()))
                if not rec.get("CVSS") and cve_id in found:
                    rec["CVSS"] = found[cve_id]
                    updated += 1
                lines.append(obj)
        if updated == 0:
            continue
        print(f"{shard.name}: +{updated} CVSS")
        if dry_run:
            continue
        tmp = shard.with_suffix(".gz.tmp")
        with gzip.open(tmp, "wt") as f:
            for obj in lines:
                # Default separators match the pipeline's shard format exactly,
                # so untouched records produce zero git diff.
                f.write(json.dumps(obj) + "\n")
        tmp.replace(shard)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    delay = 1.0 if os.environ.get("NVD_API_KEY") else 6.5
    print(f"Rate delay: {delay}s/request ({'keyed' if delay == 1.0 else 'keyless'})")

    missing = load_missing_ids()
    print(f"CVEs missing CVSS across shards: {len(missing)}")
    if not missing:
        return

    found = fetch_cvss_map(missing, delay)
    print(f"NVD provided CVSS for {len(found)}/{len(missing)} missing CVEs "
          f"(the rest were never scored)")
    apply_to_shards(found, args.dry_run)
    if not args.dry_run:
        CHECKPOINT.unlink(missing_ok=True)
    print("Done.")


if __name__ == "__main__":
    main()
