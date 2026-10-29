"""
Demo Asset Generator for Secure Examination-Paper Exchange Workshop
===================================================================
Prepares the initial demonstration fixtures:
1. Receiver RSA-3072 key pair (keys/receiver_private.pem, keys/receiver_public.pem)
2. Sender RSA-3072 public key (sender_public_keys/sender_public.pem)
3. Encrypted sample exam package (incoming/exam_package.json)
"""

from __future__ import annotations

from pathlib import Path
from secure_exam_receiver import (
    canonical_json_bytes,
    generate_receiver_keypair,
    get_public_key_fingerprint,
    save_receiver_keys,
)
from tests.test_helpers import create_sender_test_package

def setup_demo():
    root = Path("secure_exam_exchange")
    keys_dir = root / "keys"
    sender_pub_dir = root / "sender_public_keys"
    incoming_dir = root / "incoming"
    sample_file = root / "sample_data" / "sample_exam.txt"

    keys_dir.mkdir(parents=True, exist_ok=True)
    sender_pub_dir.mkdir(parents=True, exist_ok=True)
    incoming_dir.mkdir(parents=True, exist_ok=True)

    recv_priv_file = keys_dir / "receiver_private.pem"
    recv_pub_file = keys_dir / "receiver_public.pem"
    sender_pub_file = sender_pub_dir / "sender_public.pem"
    package_file = incoming_dir / "exam_package.json"

    # 1. Generate Receiver Key Pair
    demo_passphrase = "WorkshopPassphrase2026!"
    if not recv_priv_file.exists():
        recv_priv, recv_pub = generate_receiver_keypair(key_size=3072)
        save_receiver_keys(
            recv_priv,
            recv_pub,
            recv_priv_file,
            recv_pub_file,
            passphrase=demo_passphrase,
            overwrite=True,
        )
        print(f"Generated receiver keypair. Public key fingerprint: {get_public_key_fingerprint(recv_pub)}")
    else:
        from secure_exam_receiver import load_public_key, load_receiver_private_key
        recv_priv = load_receiver_private_key(recv_priv_file, passphrase=demo_passphrase)
        recv_pub = load_public_key(recv_pub_file)
        print(f"Existing receiver keypair loaded.")

    # 2. Generate Sender Key Pair (Simulating Sender faculty member)
    sender_priv, sender_pub = generate_receiver_keypair(key_size=3072)
    if not sender_pub_file.exists():
        sender_pub_dir.mkdir(parents=True, exist_ok=True)
        from cryptography.hazmat.primitives import serialization
        sender_pub_file.write_bytes(
            sender_pub.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        print(f"Saved trusted sender public key. Fingerprint: {get_public_key_fingerprint(sender_pub)}")

    # 3. Create Incoming Examination Package
    if not package_file.exists() and sample_file.exists():
        plaintext = sample_file.read_bytes()
        pkg = create_sender_test_package(
            plaintext=plaintext,
            filename="sample_exam.txt",
            sender_id="faculty01",
            recipient_id="coordinator01",
            sender_private_key=sender_priv,
            receiver_public_key=recv_pub,
        )
        package_file.write_bytes(canonical_json_bytes(pkg))
        print(f"Created sample incoming package: {package_file} ({len(plaintext)} bytes of plaintext).")

if __name__ == "__main__":
    setup_demo()
