#!/usr/bin/env python3
"""Watchdog for the witness publisher, run OFF the estate by the repository's hourly workflow.

Reads the newest record of every chain under <root>/records and fails when its head time is older
than --max-age-seconds (default two hourly intervals). A publisher that stopped on the gate host is
therefore reported here, where the artifact lives, within one interval of the missed fire.

CONTROL. `--now <ISO>` lets a test present a clock far ahead of the newest record: the watchdog must
then FAIL. The workflow's own control step does that with a planted clock.

Exit 0 when every chain's newest record is young enough; 1 otherwise or when there is no record.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys
from datetime import datetime, timezone


def newest(chain_dir: pathlib.Path) -> tuple[pathlib.Path, dict] | None:
    files = sorted((p for p in chain_dir.glob("*.json") if p.name != "latest.json"), key=lambda p: int(p.stem))
    if not files:
        return None
    return files[-1], json.loads(files[-1].read_text(encoding="utf-8"))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--max-age-seconds", type=int, default=7200)
    ap.add_argument("--now", help="ISO-8601 instant to use as the clock (control only)")
    a = ap.parse_args(argv)
    now = datetime.fromisoformat(a.now.replace("Z", "+00:00")) if a.now else datetime.now(timezone.utc)
    chains = sorted((pathlib.Path(a.root) / "records").glob("*"))
    if not chains:
        print("no chains under records/; nothing is being witnessed")
        return 1
    bad = 0
    for chain_dir in chains:
        n = newest(chain_dir)
        if n is None:
            print(f"{chain_dir.name}: no record"); bad += 1; continue
        path, rec = n
        t = datetime.fromisoformat(str(rec["utc_time"]).replace("Z", "+00:00"))
        age = (now - t).total_seconds()
        ok = age <= a.max_age_seconds
        print(f"{chain_dir.name}: newest {path.name} height {rec['height']} at {rec['utc_time']} age {age:.0f}s {'OK' if ok else 'STALE'}")
        bad += not ok
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
