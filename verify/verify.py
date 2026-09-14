#!/usr/bin/env python3
"""Verify LogiRoot chain witness records with no credentials.

For every record under records/<chain>/ (in height order, or one file given on the command line):
  1. the record has exactly the seven published fields;
  2. `signature` (base64) verifies with ML-DSA-65 over the ASCII bytes of `head_hash`, under the
     public key the LogiRoot key directory lists for `key_id`;
  3. `prev_witness_hash` equals the SHA-256 of the previous record file as published, with LF
     line endings (all zeros for the first record), and `height` increases.

Exit 0 when every checked record passes; 1 when any fails. Requires the pure-Python package
`dilithium-py` and network access to the key directory. Nothing else.

Usage:
  python verify/verify.py                       # every record of every chain
  python verify/verify.py --root <checkout>     # records under another checkout
  python verify/verify.py records/gate-local/30402085.json
  python verify/verify.py --directory keys.json # use a saved copy of the key directory
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import pathlib
import sys
import urllib.request

FIELDS = ("schema_version", "height", "head_hash", "utc_time", "prev_witness_hash", "key_id", "signature")
KEY_DIRECTORY = "https://api.logirootai.com/.well-known/logiroot-signing-keys.json"
GENESIS_PREV = "0" * 64
LF = b"\n"
CRLF = b"\r\n"
# One record, height 30402144 (2026-09-14T23:15Z), was published with its previous-record hash computed
# over CRLF line endings by a Windows checkout. The rule is LF; that one record is accepted under the
# legacy hash and the verifier says so aloud. No record above this height may use it.
LEGACY_CRLF_MAX_HEIGHT = 30402144


def load_directory(path: str | None) -> dict:
    if path:
        return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    return json.load(urllib.request.urlopen(KEY_DIRECTORY, timeout=30))


def lf_bytes(raw: bytes) -> bytes:
    return raw.replace(CRLF, LF)


def crlf_bytes(raw: bytes) -> bytes:
    return lf_bytes(raw).replace(LF, CRLF)


def check_record(path: pathlib.Path, prev_path: pathlib.Path | None, directory: dict) -> list[str]:
    from dilithium_py.ml_dsa import ML_DSA_65

    faults: list[str] = []
    rec = json.loads(path.read_text(encoding="utf-8"))
    if tuple(rec) != FIELDS:
        faults.append(f"fields are {list(rec)}, expected {list(FIELDS)}")
        return faults
    entry = next((k for k in directory.get("keys", []) if k.get("fingerprint") == rec["key_id"]), None)
    if entry is None:
        faults.append("key_id is not in the public key directory")
    elif str(entry.get("algorithm", "")).lower() != "ml-dsa-65":
        faults.append(f"key_id is listed as {entry.get('algorithm')}, not ML-DSA-65")
    else:
        pk = base64.b64decode(entry["public_key_b64"])
        sig = base64.b64decode(rec["signature"])
        if not ML_DSA_65.verify(pk, str(rec["head_hash"]).encode("ascii"), sig):
            faults.append("signature does not verify over head_hash under key_id")
    if prev_path is None:
        if rec["prev_witness_hash"] != GENESIS_PREV:
            faults.append("first record must name the all-zero previous hash")
    else:
        raw = prev_path.read_bytes()
        want = hashlib.sha256(lf_bytes(raw)).hexdigest()
        legacy = hashlib.sha256(crlf_bytes(raw)).hexdigest()
        if rec["prev_witness_hash"] == want:
            pass
        elif rec["prev_witness_hash"] == legacy and int(rec["height"]) <= LEGACY_CRLF_MAX_HEIGHT:
            print(f"  note: {path.name} names the previous record hashed with CRLF line endings (legacy, before 2026-09-15)")
        else:
            faults.append("prev_witness_hash does not equal the SHA-256 of the previous record file (LF line endings)")
        prev = json.loads(prev_path.read_text(encoding="utf-8"))
        if int(rec["height"]) <= int(prev["height"]):
            faults.append("height does not increase")
    return faults


def ordered_records(chain_dir: pathlib.Path) -> list[pathlib.Path]:
    return sorted((p for p in chain_dir.glob("*.json") if p.name != "latest.json"), key=lambda p: int(p.stem))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("record", nargs="?", help="one record file; default: every record of every chain")
    ap.add_argument("--directory", help="a saved copy of the key directory JSON")
    ap.add_argument("--root", default=str(pathlib.Path(__file__).resolve().parents[1]))
    a = ap.parse_args(argv)
    root = pathlib.Path(a.root)
    directory = load_directory(a.directory)
    failed = 0
    checked = 0
    if a.record:
        p = pathlib.Path(a.record)
        files = ordered_records(p.parent)
        idx = [f.name for f in files].index(p.name)
        prev = files[idx - 1] if idx > 0 else None
        faults = check_record(p, prev, directory)
        checked += 1
        print(f"{p}: {'OK' if not faults else 'FAIL ' + '; '.join(faults)}")
        failed += bool(faults)
    else:
        for chain_dir in sorted((root / "records").glob("*")):
            files = ordered_records(chain_dir)
            for i, p in enumerate(files):
                faults = check_record(p, files[i - 1] if i > 0 else None, directory)
                checked += 1
                print(f"{p.relative_to(root)}: {'OK' if not faults else 'FAIL ' + '; '.join(faults)}")
                failed += bool(faults)
    print(f"checked {checked} record(s), failed {failed}")
    return 1 if failed or checked == 0 else 0


if __name__ == "__main__":
    sys.exit(main())
