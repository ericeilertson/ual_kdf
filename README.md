A simple Python script to demonstrate the construction of a KMAC-256 based KDF for the Ultra Accelerator Link 1.0 specification.  This is based on the [NIST Special Publication 800-56C rev2](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Cr2.pdf).

## Generating Test Vectors

Run `generate_tests.py` to emit JSON lines containing fixed info and derived keys:

```bash
python generate_tests.py --output tests/data/ual_kdf_vectors.jsonl
```

- `--secret` accepts ASCII or hex (`0x`-prefixed) 32-byte keys.
- `--epochs`/`--streams` allow selecting specific values.

## Running Tests

Install dependencies then execute pytest:

```bash
pip install -r requirements.txt
pytest
```

