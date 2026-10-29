"""
Test Helper: Sender Protocol Simulator for Receiver Security Testing
====================================================================
This module provides synthetic package generation strictly following the
SecureExamExchange v1 protocol specification. Used SOLELY for automated
security testing and verification of the receiver application.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import os
from typing import Any, Dict, Optional, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from secure_exam_receiver import (
    AES_KEY_BYTES,
    GCM_NONCE_BYTES,
    GCM_TAG_BYTES,
    PROTOCOL_NAME,
    PROTOCOL_VERSION,
    canonical_json_bytes,
)


def create_sender_test_package(
    plaintext: bytes,
    filename: str,
    sender_id: str,
    recipient_id: str,
    sender_private_key: rsa.RSAPrivateKey,
    receiver_public_key: rsa.RSAPublicKey,
    override_metadata: Optional[Dict[str, Any]] = None,
    override_nonce: Optional[bytes] = None,
    override_aes_key: Optional[bytes] = None,
    timestamp_str: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Creates a compliant SecureExamExchange v1 encrypted package for testing.
    """
    if timestamp_str is None:
        timestamp_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

    file_size = len(plaintext)
    plaintext_sha256 = hashlib.sha256(plaintext).hexdigest()

    metadata: Dict[str, Any] = {
        "sender_id": sender_id,
        "recipient_id": recipient_id,
        "filename": filename,
        "file_size": file_size,
        "created_at": timestamp_str,
        "encryption": "AES-256-GCM",
        "key_wrap": "RSA-OAEP-SHA256",
        "signature": "RSA-PSS-SHA256",
        "plaintext_sha256": plaintext_sha256,
    }

    if override_metadata:
        metadata.update(override_metadata)

    # 1. Fresh AES-256 session key
    aes_key = override_aes_key if override_aes_key is not None else os.urandom(AES_KEY_BYTES)

    # 2. RSA-OAEP Key Encapsulation using receiver's public key
    encrypted_key_bytes = receiver_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # 3. Fresh Nonce (12 bytes)
    nonce = override_nonce if override_nonce is not None else os.urandom(GCM_NONCE_BYTES)

    # 4. Associated Data = Canonical JSON bytes of complete metadata
    aad = canonical_json_bytes(metadata)

    # 5. AES-256-GCM Encryption
    aesgcm = AESGCM(aes_key)
    # aesgcm.encrypt returns ciphertext + 16-byte tag
    ct_with_tag = aesgcm.encrypt(nonce, plaintext, aad)
    ciphertext_bytes = ct_with_tag[:-GCM_TAG_BYTES]
    tag_bytes = ct_with_tag[-GCM_TAG_BYTES:]

    # Construct the package prior to signing
    package_unsigned: Dict[str, Any] = {
        "protocol": PROTOCOL_NAME,
        "version": PROTOCOL_VERSION,
        "metadata": metadata,
        "encrypted_key": base64.b64encode(encrypted_key_bytes).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext_bytes).decode("ascii"),
        "tag": base64.b64encode(tag_bytes).decode("ascii"),
    }

    # 6. RSA-PSS Digital Signature over canonical JSON of package without top-level signature
    canonical_bytes_to_sign = canonical_json_bytes(package_unsigned)
    signature_bytes = sender_private_key.sign(
        canonical_bytes_to_sign,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    package = dict(package_unsigned)
    package["signature"] = base64.b64encode(signature_bytes).decode("ascii")

    return package
