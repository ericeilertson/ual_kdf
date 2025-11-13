from Crypto.Hash import KMAC256
from math import ceil

'''
    This file contains an example of how to construct the context info and pass this to a KMAC based KDF
    
    Page 14: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Cr2.pdf
    
    Process: 
    1. If L > 0, then set reps = ceiling(L / H_outputBits); otherwise, output an error indicator and exit 
    this process without performing the remaining actions (i.e., omit steps 2 through 8). 
    2. If reps > (2^32 −1), then output an error indicator and exit this process without performing
    the remaining actions (i.e., omit steps 3 through 8).
    3. Initialize a big-endian 4-byte unsigned integer counter as 0x00000000, corresponding to
    a 32-bit binary representation of the number zero.
    4. If counter || Z || FixedInfo is more than max_H_inputBits bits long, then output an error
    indicator and exit this process without performing any of the remaining actions (i.e., omit
    steps 5 through 8).
    5. Initialize Result(0) as an empty bit string (i.e., the null string).
    6. For i = 1 to reps, do the following:
        6.1 Increment counter by 1.
        6.2 Compute K(i) = H(counter || Z || FixedInfo).
        6.3 Set Result(i) = Result(i – 1) || K(i).
    7. Set DerivedKeyingMaterial equal to the leftmost L bits of Result(reps).
    8. Output DerivedKeyingMaterial.
'''

# This block is UALink specific to construct the 5-byte fixed_info
secret_key = b"12345678901234567890123456789012"  # a 256-bit secret
epoch = 3 # starts at 0 and increments every epoch
StreamIDX = 1 # this is a 2 bit field identifying which of 3 streams this is for
fixed_info = epoch.to_bytes(4, byteorder="big")
fixed_info += StreamIDX.to_bytes(1, byteorder="big")  # expand the 2-bit field into a full byte


# This rest of the code is KMAC-KDF specific based on the NIST spec

# The next few lines of code follow the NIST process defined in the comment block above
# but for the UAL case can be treated as constants
L = 256  # the length of the key material to derive
H_outputBits = L
#  If Option 3 is chosen, then H_outputBits
# shall either be set equal to the length (in bits) of the secret keying material to be derived (see
# input L below) or selected from the set {160, 224, 256, 384, 512}.
reps = ceil(L / H_outputBits)
if reps != 1:
    print(f"Error: expected reps to be 1, calculated reps={reps}")
    exit(1)
# initialized to 0 and then incremented as step 6.1 above
counter = 1

# pack the KDF values into the format specified by the spec
input_buffer = counter.to_bytes(4, byteorder="big")
input_buffer += secret_key # this is Z in the nist spec
input_buffer += fixed_info

salt = bytes(132)  # "...the default salt shall be an all-zero string of 132 bytes"

# Finally call the standard KMAC256 function
kmac = KMAC256.new(key=salt, data=input_buffer, custom=b"KDF", mac_len=32)
as_bytes = kmac.digest()
as_hex = kmac.hexdigest()
print(f"The derived key has length {len(as_bytes)} bytes and is {as_hex}")

