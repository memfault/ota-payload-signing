#!/usr/bin/env python3

import hashlib
import sys
from binascii import hexlify

try:
    from ecdsa import SigningKey
    from ecdsa.util import sigencode_string
except ImportError:
    print("Please install ecdsa package")
    sys.exit(1)


def gen_binary_signature(data, key_filename):
    with open(key_filename, "r") as f:
        key_pem = f.read()
    key = SigningKey.from_pem(key_pem)
    sig = key.sign_deterministic(
        # Note: "sigencode_string" means generate just the r + s values, each 32
        # bytes long, NOT the DER encoded format, which is variable length,
        # 71-73 bytes total depending on r + s values.
        data,
        hashfunc=hashlib.sha256,
        sigencode=sigencode_string,
    )
    return sig


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <private-key> <file-to-sign> <output-file>")
        sys.exit(1)

    private_key = sys.argv[1]
    with open(sys.argv[2], "rb") as f:
        data = f.read()

    sig = gen_binary_signature(data, private_key)
    print(f"Signature: {hexlify(sig).decode()}", file=sys.stderr)
    print(f"Signature length: {len(sig)}", file=sys.stderr)
    with open(sys.argv[3], "wb") as f:
        f.write(data)
        f.write(sig)
