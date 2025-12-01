A simple Python script to demonstrate the construction of a KMAC-256 based KDF for the Ultra Accelerator Link 1.0 specification.  This is based on the [NIST Special Publication 800-56C rev2](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Cr2.pdf).

This repository is meant to act as a readable reference for hardware teams implementing the KDF: the Python is intentionally straightforward and the included tests/vectors document expected boundary behavior.

## Generating Test Vectors

Run `generate_tests.py` to emit JSON lines containing fixed info and derived keys:

```bash
python generate_tests.py --output tests/data/ual_kdf_vectors.jsonl
```

- `--secret` accepts ASCII or hex (`0x`-prefixed) 32-byte keys.
- `--epochs`/`--streams` allow selecting specific values.
- Each vector now records `secret`, `fixed_info`, and `derived_key` so consumers can replay the derivation without guessing inputs.

## Running Tests

Install dependencies then execute pytest:

```bash
pip install -r requirements.txt
pytest
```

`tests/test_ual_kdf.py` doubles as living documentation: it checks fixed-info layout, boundary conditions on stream IDs and epochs, and validates the published vectors against the reference implementation. Hardware teams can mirror these scenarios to confirm conformity.
