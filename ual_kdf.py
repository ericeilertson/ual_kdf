from Crypto.Hash import KMAC256

SALT_LENGTH_BYTES = 132
KDF_OUTPUT_LENGTH_BITS = 256

def construct_fixed_info(epoch: int, stream_id: int) -> bytes:
    """
    Construct UAL-specific FixedInfo (5 bytes: 4 for epoch, 1 for stream index).
    epoch is the 4 byte counter incremented each time a key is rolled for a stream
    stream_id is the stream identifier, selecting one of 3 streams
    """
    if stream_id not in (0, 1, 2):
        raise ValueError(f"stream_id must be 0, 1, or 2")
    fixed_info = epoch.to_bytes(4, byteorder="big")
    fixed_info += stream_id.to_bytes(1, byteorder="big")
    return fixed_info

def derive_kmac_kdf(secret_key: bytes, fixed_info: bytes, output_length_bits: int = KDF_OUTPUT_LENGTH_BITS) -> bytes:
    """
    Derive a key using KMAC256 following NIST.SP.800-56Cr2 spec, Option 3.
    https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Cr2.pdf
    Since the UAL spec requires a 256-bit output this implementation skips the calculation of how many rounds of KMAC
    is needed as it is known to be 1.
    """
    if len(secret_key) != 32:
        raise ValueError("secret_key must be exactly 32 bytes (256 bits)")

    # Prepare counter and input buffer
    counter = 1  # counter for how many rounds of KMAC is needed but UAL parameters require only 1 round
    counter_bytes = counter.to_bytes(4, byteorder="big")
    input_buffer = counter_bytes + secret_key + fixed_info

    # Use 132-byte all-zero salt as per "default salt" recommendation
    salt = bytes(SALT_LENGTH_BYTES)
    kmac = KMAC256.new(key=salt, data=input_buffer, custom=b"KDF", mac_len=output_length_bits // 8)
    return kmac.digest()

if __name__ == "__main__":
    secret_key = b"12345678901234567890123456789012"  # 256 bits / 32 bytes

    for epoch in range(5):
        for stream_id in range(3):
            fixed_info = construct_fixed_info(epoch, stream_id)
            derived_key = derive_kmac_kdf(secret_key, fixed_info)
            print(f"The key for epoch {epoch} and stream_id {stream_id} is {derived_key.hex()}")


