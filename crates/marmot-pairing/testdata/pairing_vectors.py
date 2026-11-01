#!/usr/bin/env python3
"""Independent implementation of the pairing derivations, for known-answer vectors.

Writes pairing-v1.json next to this file. The Rust tests in tests/vectors.rs
check every value against marmot-pairing. This script shares no code with the
crate: it uses Python's `cryptography` package for X25519 and HKDF-SHA256 and
the standard library for SHA-256 and HMAC-SHA256.

Run: python3 -I crates/marmot-pairing/testdata/pairing_vectors.py <sas-emoji.json>

The argument is Matrix's emoji table, data-definitions/sas-emoji.json from
https://github.com/matrix-org/matrix-spec; the vectors pin a digest of it.
"""

import hashlib
import hmac
import json
import pathlib

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def h(label: str) -> bytes:
    return hashlib.sha256(label.encode()).digest()


def varint(n: int) -> bytes:
    if n < 64:
        return bytes([n])
    if n < 16384:
        return (0x4000 | n).to_bytes(2, "big")
    raise ValueError("vector inputs stay under 16384 bytes")


def var(b: bytes) -> bytes:
    return varint(len(b)) + b


def hkdf(ikm: bytes, info: bytes, length: int) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info).derive(ikm)


def public(secret: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(secret).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def emoji_numbers(sas: bytes) -> list:
    bits = int.from_bytes(sas[:6], "big")
    return [(bits >> (42 - 6 * i)) & 0x3F for i in range(7)]


def vector(name: str, kp_ref_len: int, group_id_len: int, signature_key_len: int) -> dict:
    session = h(name + " session")
    account = h(name + " account")
    kp_event = h(name + " key package event")
    kp_ref = h(name + " key package ref")[:kp_ref_len] if kp_ref_len <= 32 else (
        h(name + " key package ref") + h(name + " key package ref 2")
    )[:kp_ref_len]
    slot = h(name + " existing device slot")
    group = (h(name + " device group") * 8)[:group_id_len]
    signature_key = (h(name + " existing device signature key") * 5)[:signature_key_len]
    new_secret = h(name + " new device secret")
    existing_secret = h(name + " existing device secret")
    new_key = public(new_secret)
    existing_key = public(existing_secret)

    commitment = hashlib.sha256(
        var(b"marmot-pairing-v1-commitment") + new_key + session + account + kp_event + var(kp_ref)
    ).digest()

    shared_new = X25519PrivateKey.from_private_bytes(new_secret).exchange(
        X25519PublicKey.from_public_bytes(existing_key)
    )
    shared_existing = X25519PrivateKey.from_private_bytes(existing_secret).exchange(
        X25519PublicKey.from_public_bytes(new_key)
    )
    assert shared_new == shared_existing

    sas_info = (
        var(b"marmot-pairing-v1-sas") + session + account + var(kp_ref) + new_key + slot + existing_key
    )
    sas = hkdf(shared_new, sas_info, 6)

    def mac_info(sender: int, item: int) -> bytes:
        return var(b"marmot-pairing-v1-mac") + bytes([sender]) + session + account + var(kp_ref) + slot + bytes([item])

    new_mac_info = mac_info(1, 1)
    new_mac = hmac.new(hkdf(shared_new, new_mac_info, 32), var(kp_ref), hashlib.sha256).digest()
    existing_mac_info = mac_info(2, 2)
    device_group = var(group) + var(signature_key)
    existing_mac = hmac.new(
        hkdf(shared_new, existing_mac_info, 32), var(device_group), hashlib.sha256
    ).digest()

    def content(obj: dict) -> str:
        return json.dumps(obj, separators=(",", ":"))

    return {
        "name": name,
        "session_id": session.hex(),
        "account": account.hex(),
        "key_package_event_id": kp_event.hex(),
        "key_package_ref": kp_ref.hex(),
        "existing_device_slot": slot.hex(),
        "device_group_id": group.hex(),
        "signature_key": signature_key.hex(),
        "new_device_secret": new_secret.hex(),
        "existing_device_secret": existing_secret.hex(),
        "new_device_key": new_key.hex(),
        "existing_device_key": existing_key.hex(),
        "commitment": commitment.hex(),
        "shared_secret": shared_new.hex(),
        "sas_info": sas_info.hex(),
        "sas_bytes": sas.hex(),
        "emoji_numbers": emoji_numbers(sas),
        "new_device_mac_info": new_mac_info.hex(),
        "new_device_mac": new_mac.hex(),
        "existing_device_mac_info": existing_mac_info.hex(),
        "existing_device_mac_value": device_group.hex(),
        "existing_device_mac": existing_mac.hex(),
        "content": {
            "request": content({
                "v": 1,
                "session": session.hex(),
                "key_package_event": kp_event.hex(),
                "key_package_ref": kp_ref.hex(),
                "commitment": commitment.hex(),
            }),
            "answer": content({"v": 1, "session": session.hex(), "slot": slot.hex(), "key": existing_key.hex()}),
            "reveal": content({"v": 1, "session": session.hex(), "answer_slot": slot.hex(), "key": new_key.hex()}),
            "new_device_confirm": content({
                "v": 1, "session": session.hex(), "from": "new_device", "mac": new_mac.hex(),
            }),
            "existing_device_confirm": content({
                "v": 1,
                "session": session.hex(),
                "from": "existing_device",
                "device_group": group.hex(),
                "signature_key": signature_key.hex(),
                "mac": existing_mac.hex(),
            }),
        },
    }


def emoji_table_sha256(matrix_json: pathlib.Path) -> str:
    """SHA-256 over one `number TAB emoji TAB description TAB unicode LF` line per entry."""
    table = json.loads(matrix_json.read_text(encoding="utf-8"))
    lines = "".join(
        f"{e['number']}\t{e['emoji']}\t{e['description']}\t{e['unicode']}\n" for e in table
    )
    return hashlib.sha256(lines.encode("utf-8")).hexdigest()


def main() -> None:
    import sys

    if len(sys.argv) != 2:
        sys.exit("usage: pairing_vectors.py <matrix-spec data-definitions/sas-emoji.json>")
    vectors = {
        "description": "marmot-pairing v1 known-answer vectors, generated by pairing_vectors.py",
        "emoji_table_source": "matrix-org/matrix-spec data-definitions/sas-emoji.json "
        "at 7aaeac07608f97942eff88634a56b630a745ce56",
        "emoji_table_sha256": emoji_table_sha256(pathlib.Path(sys.argv[1])),
        "vectors": [
            vector("pairing-v1 basic", 32, 16, 32),
            vector("pairing-v1 short ref", 20, 32, 32),
            vector("pairing-v1 long ref and group", 64, 255, 133),
        ],
    }
    out = pathlib.Path(__file__).with_name("pairing-v1.json")
    out.write_text(json.dumps(vectors, indent=2) + "\n")


if __name__ == "__main__":
    main()
