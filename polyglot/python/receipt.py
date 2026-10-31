"""Konaet commitment frame v1. ISC; Copyright 2026 Adilson Oliveira / 7dsol3."""
import hashlib
import hmac
import json
import re
import sys

LIMIT = 32900


def process(frame: bytes):
    if len(frame) > LIMIT:
        raise ValueError("INPUT_LIMIT")
    lines = frame.decode("ascii").split("\n")
    if len(lines) != 4 or lines[-1] != "":
        raise ValueError("FRAME_INVALID")
    salt, document, expected, _ = lines
    if not re.fullmatch(r"[0-9a-f]{64}", salt):
        raise ValueError("SALT_INVALID")
    if not 4 <= len(document) <= 32768 or len(document) % 2 or not re.fullmatch(r"[0-9a-f]+", document):
        raise ValueError("DOCUMENT_INVALID")
    if expected != "-" and not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise ValueError("EXPECTED_INVALID")
    value = hashlib.sha256(b"KONAET/SOCIAL-RECEIPT/v1\0" + bytes.fromhex(salt) + bytes.fromhex(document)).hexdigest()
    matches = None if expected == "-" else hmac.compare_digest(value, expected)
    return {"commitment": value, "args": [str(int(value[:32], 16)), str(int(value[32:], 16))], "matches": matches}


if __name__ == "__main__":
    try:
        result = process(sys.stdin.buffer.read(LIMIT + 1))
        print(json.dumps(result, separators=(",", ":")))
        sys.exit(1 if result["matches"] is False else 0)
    except (ValueError, UnicodeError):
        print("KONAET_INPUT_INVALID", file=sys.stderr)
        sys.exit(2)
