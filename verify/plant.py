#!/usr/bin/env python3
"""The verifier's control: copy every record to a scratch tree and change ONE character of the newest
record's head_hash. `verify.py --root <scratch>` must then FAIL. Prints the scratch root."""
import json, pathlib, shutil, sys, tempfile

root = pathlib.Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else pathlib.Path(__file__).resolve().parents[1]
scratch = pathlib.Path(tempfile.mkdtemp(prefix="witness-planted-"))
shutil.copytree(root / "records", scratch / "records")
for chain_dir in sorted((scratch / "records").glob("*")):
    files = sorted((p for p in chain_dir.glob("*.json") if p.name != "latest.json"), key=lambda p: int(p.stem))
    if not files:
        continue
    newest = files[-1]
    rec = json.loads(newest.read_text(encoding="utf-8"))
    h = rec["head_hash"]
    rec["head_hash"] = h[:-1] + ("0" if h[-1] != "0" else "1")
    newest.write_text(json.dumps(rec, indent=1) + "\n", encoding="utf-8")
    print(f"planted a one-character change in head_hash of {chain_dir.name}/{newest.name}", file=sys.stderr)
print(scratch)
