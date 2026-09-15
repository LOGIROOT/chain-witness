#!/usr/bin/env python3
"""Verify LogiRoot chain witness records with no credentials.

For every record under records/<chain>/ (in height order, or one file given on the command line):
  1. the record has exactly its schema's published fields;
  2. `signature` (base64) verifies with ML-DSA-65 over the ASCII bytes of `head_hash`, under the
     public key the LogiRoot key directory lists for `key_id`;
  3. `prev_witness_hash` links it to the previous record (all zeros for the first record) and
     `height` increases.

Two record schemas exist and both verify under this one verifier:

  schema_version 1: seven fields; the link is the SHA-256 of the previous record FILE as
      published, with LF line endings. One record, height 30402144, was published with that hash
      computed over CRLF line endings by a Windows checkout; it is accepted under that legacy hash
      and the verifier says so aloud. No later record may use it.
  schema_version 2: the seven fields plus `canonicalization_id`, which names the link rule.
      Rule "c1": the link is the SHA-256 of the previous record's FIELDS serialised canonically
      (JSON, keys sorted, separators "," and ":", ASCII-escaped), so line endings, key order and
      whitespace of the published file are structurally irrelevant. A schema 2 record without
      `canonicalization_id`, or with one this verifier does not know, is REFUSED.

Exit 0 when every checked record passes; 1 when any fails or none was checked. Requires the
pure-Python package `dilithium-py` and network access to the key directory. Nothing else.

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

FIELDS_V1 = ("schema_version", "height", "head_hash", "utc_time", "prev_witness_hash", "key_id", "signature")
FIELDS_V2 = FIELDS_V1 + ("canonicalization_id",)
KNOWN_CANONICALIZATIONS = ("c1",)
KEY_DIRECTORY = "https://api.logirootai.com/.well-known/logiroot-signing-keys.json"
GENESIS_PREV = "0" * 64
LF = b"\n"
CRLF = b"\r\n"
LEGACY_CRLF_MAX_HEIGHT = 30402144


class Refused(ValueError):
    """The document is not a witness record this verifier knows. Never a verdict."""


def load_directory(path: str | None) -> dict:
    if path:
        return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    return json.load(urllib.request.urlopen(KEY_DIRECTORY, timeout=30))


def lf_bytes(raw: bytes) -> bytes:
    return raw.replace(CRLF, LF)


def crlf_bytes(raw: bytes) -> bytes:
    return lf_bytes(raw).replace(LF, CRLF)


def canonical_c1(record: dict) -> bytes:
    """Rule c1: the record's fields, and only its fields, serialised the one way."""
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def link_digest(prev_record: dict, prev_raw: bytes, canonicalization_id: str | None) -> tuple[str, str | None]:
    """The digest a record's prev_witness_hash must equal, and an optional legacy alternative."""
    if canonicalization_id is None:
        return hashlib.sha256(lf_bytes(prev_raw)).hexdigest(), hashlib.sha256(crlf_bytes(prev_raw)).hexdigest()
    if canonicalization_id == "c1":
        return hashlib.sha256(canonical_c1(prev_record)).hexdigest(), None
    raise Refused(f"unknown canonicalization_id {canonicalization_id!r}")


def schema_of(rec: dict) -> int:
    keys = tuple(rec)
    if keys == FIELDS_V1 and rec.get("schema_version") == 1:
        return 1
    if set(keys) == set(FIELDS_V2) and rec.get("schema_version") == 2:
        if rec.get("canonicalization_id") not in KNOWN_CANONICALIZATIONS:
            raise Refused(f"schema 2 record names canonicalization_id {rec.get('canonicalization_id')!r}, which this verifier does not know")
        return 2
    if rec.get("schema_version") == 2:
        raise Refused(f"schema 2 record without its fields: has {list(keys)}, expected {list(FIELDS_V2)}")
    raise Refused(f"fields are {list(keys)} with schema_version {rec.get('schema_version')!r}; expected schema 1 or 2")


def check_record(path: pathlib.Path, prev_path: pathlib.Path | None, directory: dict) -> list[str]:
    from dilithium_py.ml_dsa import ML_DSA_65

    faults: list[str] = []
    rec = json.loads(path.read_text(encoding="utf-8"))
    try:
        schema = schema_of(rec)
    except Refused as e:
        return [f"REFUSED: {e}"]
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
        prev_raw = prev_path.read_bytes()
        prev = json.loads(prev_raw.decode("utf-8"))
        try:
            want, legacy = link_digest(prev, prev_raw, rec.get("canonicalization_id") if schema == 2 else None)
        except Refused as e:
            return [f"REFUSED: {e}"]
        if rec["prev_witness_hash"] == want:
            pass
        elif legacy is not None and rec["prev_witness_hash"] == legacy and int(rec["height"]) <= LEGACY_CRLF_MAX_HEIGHT:
            print(f"  note: {path.name} names the previous record hashed with CRLF line endings (legacy, before 2026-09-15)")
        else:
            faults.append("prev_witness_hash does not link to the previous record under the record's canonicalization")
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
