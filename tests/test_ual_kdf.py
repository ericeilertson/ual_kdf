import json
from pathlib import Path

import pytest

from ual_kdf import construct_fixed_info, derive_kmac_kdf

VECTOR_PATH = Path("tests/data/ual_kdf_vectors.jsonl")


def _load_vectors():
    with VECTOR_PATH.open("r", encoding="utf-8") as fh:
        for line in fh:
            yield json.loads(line)


def test_construct_fixed_info_layout():
    fixed = construct_fixed_info(epoch=0x01020304, stream_id=2)
    assert fixed == bytes.fromhex("0102030402")


@pytest.mark.parametrize("vector", list(_load_vectors()))
def test_derive_kmac_matches_vectors(vector):
    fixed_info = bytes.fromhex(vector["fixed_info"])
    derived = derive_kmac_kdf(
        b"12345678901234567890123456789012", fixed_info
    )
    assert derived.hex() == vector["derived_key"]

