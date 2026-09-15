"""Controls for the witness verifier's two schemas. Run with `python -m pytest verify -q`.

A-WITNESS-2 acceptance: a record re-serialised with a different key order and different line
endings yields a byte-identical link digest under c1; a schema 2 record without canonicalization_id
is refused; the legacy CRLF acceptance is bounded to one height.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import verify as v  # noqa: E402

REC1 = {"schema_version": 1, "height": 10, "head_hash": "ab" * 32, "utc_time": "2026-09-15T00:00:00+00:00",
        "prev_witness_hash": "0" * 64, "key_id": "cd" * 32, "signature": "AAAA"}


def test_c1_link_digest_ignores_key_order_line_endings_and_whitespace():
    a = json.dumps(REC1, indent=1).encode() + b"\n"
    b = json.dumps(dict(reversed(list(REC1.items()))), indent=4).replace("\n", "\r\n").encode()
    da, _ = v.link_digest(json.loads(a), a, "c1")
    db, _ = v.link_digest(json.loads(b), b, "c1")
    assert da == db == hashlib.sha256(v.canonical_c1(REC1)).hexdigest()
    # control: the byte rule of schema 1 DOES see the difference, which is the class c1 removes
    d1a, _ = v.link_digest(json.loads(a), a, None)
    d1b, _ = v.link_digest(json.loads(b), b, None)
    assert d1a != d1b
    # control: a changed field changes the c1 digest
    changed = dict(REC1, height=11)
    dc, _ = v.link_digest(changed, json.dumps(changed).encode(), "c1")
    assert dc != da


def test_schema_2_requires_canonicalization_id_and_only_known_rules():
    rec2 = dict(REC1, schema_version=2, canonicalization_id="c1")
    assert v.schema_of(rec2) == 2
    with pytest.raises(v.Refused):
        v.schema_of(dict(REC1, schema_version=2))  # claims schema 2, carries no canonicalization_id
    with pytest.raises(v.Refused):
        v.schema_of(dict(rec2, canonicalization_id="c9"))
    with pytest.raises(v.Refused):
        v.schema_of(dict(REC1, canonicalization_id="c1"))  # schema 1 may not carry the field
    with pytest.raises(v.Refused):
        v.link_digest(REC1, b"{}", "c9")


def test_schema_1_is_the_seven_fields_and_nothing_else():
    assert v.schema_of(REC1) == 1
    with pytest.raises(v.Refused):
        v.schema_of(dict(REC1, extra=1))
    missing = dict(REC1); del missing["signature"]
    with pytest.raises(v.Refused):
        v.schema_of(missing)


def test_legacy_crlf_acceptance_is_bounded_to_one_height(tmp_path):
    raw = json.dumps(REC1, indent=1).encode() + b"\n"
    want, legacy = v.link_digest(REC1, raw, None)
    assert want == hashlib.sha256(raw).hexdigest() and legacy == hashlib.sha256(raw.replace(b"\n", b"\r\n")).hexdigest()
    assert want != legacy
    assert v.LEGACY_CRLF_MAX_HEIGHT == 30402144
