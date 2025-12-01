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


def test_construct_fixed_info_min_epoch():
    assert construct_fixed_info(0, 0) == bytes.fromhex("0000000000")
    assert construct_fixed_info(0, 1) == bytes.fromhex("0000000001")
    assert construct_fixed_info(0, 2) == bytes.fromhex("0000000002")


def test_construct_fixed_info_max_epoch():
    assert construct_fixed_info(0xFFFFFFFF, 1) == bytes.fromhex("FFFFFFFF01")


@pytest.mark.parametrize("stream_id", [-1, 3])
def test_construct_fixed_info_stream_bounds(stream_id):
    with pytest.raises(ValueError):
        construct_fixed_info(epoch=0, stream_id=stream_id)


@pytest.mark.parametrize("epoch", [-1, 0x1_0000_0000])
def test_construct_fixed_info_epoch_bounds(epoch):
    with pytest.raises(ValueError):
        construct_fixed_info(epoch=epoch, stream_id=0)


@pytest.mark.parametrize("vector", list(_load_vectors()))
def test_derive_kmac_matches_vectors(vector):
    secret = bytes.fromhex(vector["secret"])
    fixed_info = bytes.fromhex(vector["fixed_info"])
    derived = derive_kmac_kdf(secret, fixed_info)
    assert derived.hex() == vector["derived_key"]
