"""
Automated Security and Cryptographic Test Suite for SecureExamExchange Receiver
================================================================================
Implements Tests A through I required for the workshop validation:
- Test A: RSA Key Management & Storage
- Test B: Successful End-to-End Recovery & Verification
- Test C: Rejection of Untrusted / Wrong Sender Public Key
- Test D: Rejection of Incorrect Receiver Private Key
- Test E: Tampering Resistance (Ciphertext, Metadata, Nonce, Tag, Key, Signature, Version)
- Test F: Malformed & Invalid Input Handling (Duplicate keys, invalid UTF-8, malformed JSON, etc.)
- Test G: Zero-Length and Binary File Recovery (with Null bytes)
- Test H: Path Traversal Defense and Safe File Persistence
- Test I: Replay Attack Analysis and Documentation
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Generator

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from secure_exam_receiver import (
    FileSafetyError,
    KeyManagementError,
    ProtocolValidationError,
    SecurityVerificationError,
    canonical_json_bytes,
    decrypt_and_verify_package,
    export_receiver_public_key,
    generate_receiver_keypair,
    get_public_key_fingerprint,
    import_sender_public_key,
    load_public_key,
    load_receiver_private_key,
    parse_strict_json,
    save_plaintext_safely,
    save_receiver_keys,
    verify_package_signature,
)
from tests.test_helpers import create_sender_test_package


# ------------------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------------------
@pytest.fixture(scope="module")
def sender_keys() -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    priv, pub = generate_receiver_keypair(key_size=3072)
    return priv, pub


@pytest.fixture(scope="module")
def receiver_keys() -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    priv, pub = generate_receiver_keypair(key_size=3072)
    return priv, pub


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    d = Path(tempfile.mkdtemp(prefix="secure_exam_test_"))
    try:
        yield d
    finally:
        shutil.rmtree(d, ignore_errors=True)


# ------------------------------------------------------------------------------
# Test A — Key Management & Storage
# ------------------------------------------------------------------------------
def test_a_key_management(temp_dir: Path):
    """Test A: Key generation, PKCS#8 encrypted persistence, passphrase checks, fingerprints, and size checks."""
    priv_path = temp_dir / "keys" / "receiver_private.pem"
    pub_path = temp_dir / "keys" / "receiver_public.pem"
    passphrase = "CorrectReceiverPassphrase123!"

    # 1. Generate RSA-3072 key pair
    priv, pub = generate_receiver_keypair(key_size=3072)
    assert priv.key_size == 3072
    assert pub.key_size == 3072

    # 2. Serialize and save keys
    save_receiver_keys(priv, pub, priv_path, pub_path, passphrase=passphrase)
    assert priv_path.exists()
    assert pub_path.exists()

    # 3. Reload private key with correct passphrase
    loaded_priv = load_receiver_private_key(priv_path, passphrase=passphrase)
    assert loaded_priv.key_size == 3072

    # 4. Reject incorrect passphrase
    with pytest.raises(KeyManagementError, match="Incorrect passphrase or corrupt PEM"):
        load_receiver_private_key(priv_path, passphrase="WrongPassword999!")

    # 5. Export and import public keys
    exported_pub_path = temp_dir / "exported_receiver_public.pem"
    export_receiver_public_key(pub, exported_pub_path)
    assert exported_pub_path.exists()

    imported_path = temp_dir / "trusted_sender" / "sender_public.pem"
    imported_key, fp = import_sender_public_key(exported_pub_path, imported_path)
    assert imported_key.key_size == 3072

    # 6. Fingerprint verification
    orig_fp = get_public_key_fingerprint(pub)
    assert fp == orig_fp
    assert len(fp.split(":")) == 32  # SHA-256 has 32 bytes -> 32 hex pairs
    assert all(len(pair) == 2 for pair in fp.split(":"))

    # 7. Reject keys smaller than 3072 bits
    small_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    small_priv_path = temp_dir / "small_priv.pem"
    small_pub_path = temp_dir / "small_pub.pem"
    save_receiver_keys(small_priv, small_priv.public_key(), small_priv_path, small_pub_path, "pass", overwrite=True)

    with pytest.raises(KeyManagementError, match="below required minimum"):
        load_receiver_private_key(small_priv_path, "pass")
    with pytest.raises(KeyManagementError, match="below required minimum"):
        load_public_key(small_pub_path)

    # 8. Prevent silent overwrite of existing keys
    with pytest.raises(FileSafetyError, match="Private key file already exists"):
        save_receiver_keys(priv, pub, priv_path, pub_path, passphrase=passphrase, overwrite=False)


# ------------------------------------------------------------------------------
# Test B — Successful End-to-End Recovery
# ------------------------------------------------------------------------------
def test_b_successful_recovery(temp_dir: Path, sender_keys, receiver_keys):
    """Test B: End-to-end signature verification, RSA-OAEP recovery, AES-GCM decryption, and SHA-256 match."""
    sender_priv, sender_pub = sender_keys
    recv_priv, recv_pub = receiver_keys

    original_content = (
        b"CONFIDENTIAL EXAM QUESTIONS\n"
        b"1. Prove that AES-GCM provides authenticated encryption.\n"
        b"2. What is the impact of nonces reuse in GCM mode?\n"
    )
    filename = "midterm_exam.txt"

    pkg = create_sender_test_package(
        plaintext=original_content,
        filename=filename,
        sender_id="faculty_prof_alice",
        recipient_id="coordinator_bob",
        sender_private_key=sender_priv,
        receiver_public_key=recv_pub,
    )

    pkg_file = temp_dir / "exam_package.json"
    pkg_file.write_bytes(canonical_json_bytes(pkg))

    out_dir = temp_dir / "received"
    result = decrypt_and_verify_package(
        package_path=pkg_file,
        receiver_private_key=recv_priv,
        sender_public_key=sender_pub,
        output_dir=out_dir,
        expected_recipient_id="coordinator_bob",
    )

    assert result["verified"] is True
    assert result["sender_id"] == "faculty_prof_alice"
    assert result["recipient_id"] == "coordinator_bob"
    assert result["file_size"] == len(original_content)
    assert result["sha256"] == hashlib.sha256(original_content).hexdigest()

    saved_file = Path(result["output_path"])
    assert saved_file.is_file()
    assert saved_file.read_bytes() == original_content


# ------------------------------------------------------------------------------
# Test C — Wrong Sender Public Key
# ------------------------------------------------------------------------------
def test_c_wrong_sender_key(temp_dir: Path, sender_keys, receiver_keys):
    """Test C: Package signed by Sender A fails verification against Sender B's public key."""
    sender_priv, _ = sender_keys
    _, recv_pub = receiver_keys
    recv_priv, _ = receiver_keys

    wrong_sender_priv, wrong_sender_pub = generate_receiver_keypair(key_size=3072)

    pkg = create_sender_test_package(
        plaintext=b"Secret Exam",
        filename="exam.txt",
        sender_id="faculty01",
        recipient_id="coord01",
        sender_private_key=sender_priv,
        receiver_public_key=recv_pub,
    )

    pkg_file = temp_dir / "pkg.json"
    pkg_file.write_bytes(canonical_json_bytes(pkg))
    out_dir = temp_dir / "received"

    with pytest.raises(SecurityVerificationError, match="Sender digital signature verification failed"):
        decrypt_and_verify_package(
            package_path=pkg_file,
            receiver_private_key=recv_priv,
            sender_public_key=wrong_sender_pub,  # Using wrong sender public key
            output_dir=out_dir,
        )

    # Ensure no file was created
    assert len(list(out_dir.glob("*"))) == 0


# ------------------------------------------------------------------------------
# Test D — Wrong Receiver Key
# ------------------------------------------------------------------------------
def test_d_wrong_receiver_key(temp_dir: Path, sender_keys, receiver_keys):
    """Test D: Encrypted key cannot be decrypted by an unauthorized receiver private key."""
    sender_priv, sender_pub = sender_keys
    _, recv_pub = receiver_keys

    wrong_recv_priv, _ = generate_receiver_keypair(key_size=3072)

    pkg = create_sender_test_package(
        plaintext=b"Confidential Questions",
        filename="exam.txt",
        sender_id="faculty01",
        recipient_id="coord01",
        sender_private_key=sender_priv,
        receiver_public_key=recv_pub,  # Encrypted for intended receiver
    )

    pkg_file = temp_dir / "pkg.json"
    pkg_file.write_bytes(canonical_json_bytes(pkg))
    out_dir = temp_dir / "received"

    # Signature passes, but RSA-OAEP recovery fails with wrong receiver private key
    with pytest.raises(SecurityVerificationError, match="Failed to recover AES session key"):
        decrypt_and_verify_package(
            package_path=pkg_file,
            receiver_private_key=wrong_recv_priv,
            sender_public_key=sender_pub,
            output_dir=out_dir,
        )

    assert len(list(out_dir.glob("*"))) == 0


# ------------------------------------------------------------------------------
# Test E — Tampering Resistance
# ------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "field_to_modify",
    [
        "ciphertext",
        "metadata",
        "nonce",
        "tag",
        "encrypted_key",
        "signature",
        "protocol",
        "version",
    ],
)
def test_e_tampering(temp_dir: Path, sender_keys, receiver_keys, field_to_modify: str):
    """Test E: Any modification to signed fields or cryptographic artifacts causes rejection."""
    sender_priv, sender_pub = sender_keys
    recv_priv, recv_pub = receiver_keys

    pkg = create_sender_test_package(
        plaintext=b"Original Exam Text",
        filename="tamper_exam.txt",
        sender_id="faculty01",
        recipient_id="coord01",
        sender_private_key=sender_priv,
        receiver_public_key=recv_pub,
    )

    tampered_pkg = copy.deepcopy(pkg)

    if field_to_modify == "ciphertext":
        raw = base64.b64decode(tampered_pkg["ciphertext"])
        # Bit-flip first byte
        flipped = bytes([raw[0] ^ 0xFF]) + raw[1:]
        tampered_pkg["ciphertext"] = base64.b64encode(flipped).decode("ascii")
    elif field_to_modify == "metadata":
        tampered_pkg["metadata"]["filename"] = "hacked_exam.txt"
    elif field_to_modify == "nonce":
        raw = base64.b64decode(tampered_pkg["nonce"])
        flipped = bytes([raw[0] ^ 0x01]) + raw[1:]
        tampered_pkg["nonce"] = base64.b64encode(flipped).decode("ascii")
    elif field_to_modify == "tag":
        raw = base64.b64decode(tampered_pkg["tag"])
        flipped = bytes([raw[0] ^ 0x01]) + raw[1:]
        tampered_pkg["tag"] = base64.b64encode(flipped).decode("ascii")
    elif field_to_modify == "encrypted_key":
        raw = base64.b64decode(tampered_pkg["encrypted_key"])
        flipped = bytes([raw[0] ^ 0x01]) + raw[1:]
        tampered_pkg["encrypted_key"] = base64.b64encode(flipped).decode("ascii")
    elif field_to_modify == "signature":
        raw = base64.b64decode(tampered_pkg["signature"])
        flipped = bytes([raw[0] ^ 0x01]) + raw[1:]
        tampered_pkg["signature"] = base64.b64encode(flipped).decode("ascii")
    elif field_to_modify == "protocol":
        tampered_pkg["protocol"] = "MaliciousProtocol"
    elif field_to_modify == "version":
        tampered_pkg["version"] = 2

    pkg_file = temp_dir / f"tampered_{field_to_modify}.json"
    pkg_file.write_bytes(canonical_json_bytes(tampered_pkg))
    out_dir = temp_dir / "received"

    with pytest.raises((SecurityVerificationError, ProtocolValidationError)):
        decrypt_and_verify_package(
            package_path=pkg_file,
            receiver_private_key=recv_priv,
            sender_public_key=sender_pub,
            output_dir=out_dir,
        )

    assert not (out_dir / "tamper_exam.txt").exists()
    assert not (out_dir / "hacked_exam.txt").exists()


# ------------------------------------------------------------------------------
# Test F — Malformed & Invalid Input Handling
# ------------------------------------------------------------------------------
def test_f_malformed_input(temp_dir: Path, sender_keys, receiver_keys):
    """Test F: Handling duplicate keys, invalid UTF-8, malformed JSON, and bad Base64."""
    _, sender_pub = sender_keys
    recv_priv, _ = receiver_keys
    out_dir = temp_dir / "received"

    # 1. Malformed JSON
    f1 = temp_dir / "f1.json"
    f1.write_bytes(b"{ incomplete json: ")
    with pytest.raises(ProtocolValidationError, match="Malformed JSON syntax"):
        decrypt_and_verify_package(f1, recv_priv, sender_pub, out_dir)

    # 2. Duplicate keys
    f2 = temp_dir / "f2.json"
    f2.write_bytes(b'{"protocol": "SecureExamExchange", "protocol": "DuplicateKey"}')
    with pytest.raises(ProtocolValidationError, match="Duplicate key detected"):
        decrypt_and_verify_package(f2, recv_priv, sender_pub, out_dir)

    # 3. Invalid UTF-8
    f3 = temp_dir / "f3.json"
    f3.write_bytes(b'{"protocol": "SecureExamExchange", "bad": \xff\xfe}')
    with pytest.raises(ProtocolValidationError, match="Invalid UTF-8"):
        decrypt_and_verify_package(f3, recv_priv, sender_pub, out_dir)

    # 4. Invalid Base64 in tag
    valid_pkg = create_sender_test_package(
        b"data", "exam.txt", "s1", "r1", sender_keys[0], receiver_keys[1]
    )
    bad_b64_pkg = copy.deepcopy(valid_pkg)
    bad_b64_pkg["tag"] = "NotBase64!!!"
    f4 = temp_dir / "f4.json"
    f4.write_bytes(canonical_json_bytes(bad_b64_pkg))
    with pytest.raises(ProtocolValidationError, match="Invalid Base64"):
        decrypt_and_verify_package(f4, recv_priv, sender_pub, out_dir)

    # 5. Wrong nonce length (e.g. 10 bytes instead of 12)
    bad_nonce_pkg = copy.deepcopy(valid_pkg)
    bad_nonce_pkg["nonce"] = base64.b64encode(b"0123456789").decode("ascii")
    f5 = temp_dir / "f5.json"
    f5.write_bytes(canonical_json_bytes(bad_nonce_pkg))
    with pytest.raises(ProtocolValidationError, match="nonce size"):
        decrypt_and_verify_package(f5, recv_priv, sender_pub, out_dir)

    # 6. Recipient ID mismatch
    f6 = temp_dir / "f6.json"
    f6.write_bytes(canonical_json_bytes(valid_pkg))
    with pytest.raises(SecurityVerificationError, match="Recipient mismatch"):
        decrypt_and_verify_package(
            f6, recv_priv, sender_pub, out_dir, expected_recipient_id="different_recipient"
        )

    # 7. Oversized package
    f7 = temp_dir / "f7.json"
    f7.write_bytes(b"x" * 2000)
    with pytest.raises(ProtocolValidationError, match="exceeds maximum limit"):
        decrypt_and_verify_package(f7, recv_priv, sender_pub, out_dir, max_package_size=1000)


# ------------------------------------------------------------------------------
# Test G — Empty and Binary Files (with Null bytes)
# ------------------------------------------------------------------------------
def test_g_empty_and_binary_files(temp_dir: Path, sender_keys, receiver_keys):
    """Test G: Exact byte recovery for 0-byte file and binary file containing null bytes."""
    sender_priv, sender_pub = sender_keys
    recv_priv, recv_pub = receiver_keys
    out_dir = temp_dir / "received"

    # 1. Empty file (0 bytes)
    empty_pkg = create_sender_test_package(
        plaintext=b"",
        filename="empty.dat",
        sender_id="sender1",
        recipient_id="receiver1",
        sender_private_key=sender_priv,
        receiver_public_key=recv_pub,
    )
    p1 = temp_dir / "empty.json"
    p1.write_bytes(canonical_json_bytes(empty_pkg))

    res1 = decrypt_and_verify_package(p1, recv_priv, sender_pub, out_dir)
    assert res1["file_size"] == 0
    assert (out_dir / "empty.dat").read_bytes() == b""

    # 2. Binary file with null bytes and all byte values 0..255
    all_bytes = bytes(range(256)) * 4 + b"\x00\x00\x00\xff\xfe\x00"
    bin_pkg = create_sender_test_package(
        plaintext=all_bytes,
        filename="binary_exam.bin",
        sender_id="sender1",
        recipient_id="receiver1",
        sender_private_key=sender_priv,
        receiver_public_key=recv_pub,
    )
    p2 = temp_dir / "binary.json"
    p2.write_bytes(canonical_json_bytes(bin_pkg))

    res2 = decrypt_and_verify_package(p2, recv_priv, sender_pub, out_dir)
    assert res2["file_size"] == len(all_bytes)
    assert (out_dir / "binary_exam.bin").read_bytes() == all_bytes


# ------------------------------------------------------------------------------
# Test H — Output Safety & Path Traversal Defense
# ------------------------------------------------------------------------------
def test_h_output_safety(temp_dir: Path, sender_keys, receiver_keys):
    """Test H: Path traversal attempt is thwarted, existing files are protected from silent overwrite."""
    sender_priv, sender_pub = sender_keys
    recv_priv, recv_pub = receiver_keys
    out_dir = temp_dir / "received"
    out_dir.mkdir(parents=True, exist_ok=True)

    # 1. Attempt path traversal in filename
    pkg = create_sender_test_package(
        plaintext=b"Malicious",
        filename="../../escaped.txt",
        sender_id="attacker",
        recipient_id="target",
        sender_private_key=sender_priv,
        receiver_public_key=recv_pub,
    )
    p = temp_dir / "traversal.json"
    p.write_bytes(canonical_json_bytes(pkg))

    # Path traversal characters in metadata are caught in stage 1
    with pytest.raises(ProtocolValidationError, match="path traversal"):
        decrypt_and_verify_package(p, recv_priv, sender_pub, out_dir)

    assert not (temp_dir / "escaped.txt").exists()

    # 2. Existing file overwrite protection
    existing_file = out_dir / "final_exam.txt"
    existing_file.write_text("DO NOT OVERWRITE THIS")

    pkg_normal = create_sender_test_package(
        plaintext=b"New Exam Text",
        filename="final_exam.txt",
        sender_id="prof",
        recipient_id="coord",
        sender_private_key=sender_priv,
        receiver_public_key=recv_pub,
    )
    p_normal = temp_dir / "normal.json"
    p_normal.write_bytes(canonical_json_bytes(pkg_normal))

    with pytest.raises(FileSafetyError, match="Output file already exists"):
        decrypt_and_verify_package(
            p_normal, recv_priv, sender_pub, out_dir, overwrite=False
        )

    # Ensure existing content remains unchanged
    assert existing_file.read_text() == "DO NOT OVERWRITE THIS"

    # Overwrite confirmed
    res = decrypt_and_verify_package(
        p_normal, recv_priv, sender_pub, out_dir, overwrite=True
    )
    assert res["verified"] is True
    assert existing_file.read_text() == "New Exam Text"


# ------------------------------------------------------------------------------
# Test I — Replay Attack Consideration
# ------------------------------------------------------------------------------
def test_i_replay_consideration(temp_dir: Path, sender_keys, receiver_keys):
    """
    Test I: Demonstrates that while cryptographic signature and GCM tag remain valid,
    re-sending the same package is accepted unless an authenticated replay registry
    or message ID tracking is implemented.
    """
    sender_priv, sender_pub = sender_keys
    recv_priv, recv_pub = receiver_keys
    out_dir = temp_dir / "received"

    pkg = create_sender_test_package(
        plaintext=b"Old Exam Paper From Last Year",
        filename="replay_exam.txt",
        sender_id="prof1",
        recipient_id="coord1",
        sender_private_key=sender_priv,
        receiver_public_key=recv_pub,
    )
    p = temp_dir / "replay.json"
    p.write_bytes(canonical_json_bytes(pkg))

    # First receive succeeds
    res1 = decrypt_and_verify_package(p, recv_priv, sender_pub, out_dir)
    assert res1["verified"] is True

    # Resending the exact same valid package mathematically passes verification again!
    # (Without overwrite=True, it detects existing file)
    with pytest.raises(FileSafetyError, match="Output file already exists"):
        decrypt_and_verify_package(p, recv_priv, sender_pub, out_dir, overwrite=False)

    # With overwrite, crypto succeeds because signature & GCM tag are self-contained.
    res2 = decrypt_and_verify_package(p, recv_priv, sender_pub, out_dir, overwrite=True)
    assert res2["verified"] is True
    # Documented: Real-world production requires monotonic counter / replay cache.
