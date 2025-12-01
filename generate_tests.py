import argparse
import json
from pathlib import Path
from typing import Iterable, List

from ual_kdf import construct_fixed_info, derive_kmac_kdf

DEFAULT_SECRET = "12345678901234567890123456789012"
DEFAULT_EPOCHS = [0, 1, 2, 3, 1000000, 1000000000, 0xffffffff]
DEFAULT_STREAMS = (0, 1, 2)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate UAL KDF test vectors as JSON lines"
    )
    parser.add_argument(
        "--secret",
        default=DEFAULT_SECRET,
        help="32-byte secret key in ASCII or hex (prefix with 0x). Stored in each vector entry.",
    )
    parser.add_argument(
        "--epochs",
        nargs="*",
        type=int,
        default=list(DEFAULT_EPOCHS),
        help="Epoch values to include (default 0-4)",
    )
    parser.add_argument(
        "--streams",
        nargs="*",
        type=int,
        default=list(DEFAULT_STREAMS),
        help="Stream IDs to include (default 0 1 2)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("tests/data/ual_kdf_vectors.jsonl"),
        help="Destination JSONL file",
    )
    return parser.parse_args()


def _load_secret(secret_arg: str) -> bytes:
    if secret_arg.startswith("0x"):
        return bytes.fromhex(secret_arg[2:])
    return secret_arg.encode("utf-8")


def _iter_vectors(secret: bytes, epochs: Iterable[int], streams: Iterable[int]):
    secret_hex = secret.hex()
    for epoch in epochs:
        for stream_id in streams:
            fixed_info = construct_fixed_info(epoch, stream_id)
            derived_key = derive_kmac_kdf(secret, fixed_info)
            yield {
                "epoch": epoch,
                "stream_id": stream_id,
                "secret": secret_hex,
                "fixed_info": fixed_info.hex(),
                "derived_key": derived_key.hex(),
            }


def main():
    args = _parse_args()
    secret = _load_secret(args.secret)
    if len(secret) != 32:
        raise ValueError("Secret must be exactly 32 bytes")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    vectors: List[dict] = list(_iter_vectors(secret, args.epochs, args.streams))
    with args.output.open("w", encoding="utf-8") as fh:
        for vector in vectors:
            json.dump(vector, fh)
            fh.write("\n")
    print(f"Wrote {len(vectors)} vectors to {args.output}")


if __name__ == "__main__":
    main()