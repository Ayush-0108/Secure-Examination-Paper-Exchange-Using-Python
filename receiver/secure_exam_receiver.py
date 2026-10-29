"""
Secure Examination-Paper Exchange Using Python — Receiver Application Core Module
==================================================================================
This module implements the receiver-side cryptographic functions, key management,
protocol parsing, digital signature verification, RSA-OAEP session-key recovery,
AES-256-GCM authenticated decryption, and safe atomic file persistence.

Protocol: SecureExamExchange (Version 1)
Designed for high-integrity, confidential exchange of academic examination papers.
"""

from __future__ import annotations

import base64
import binascii
import datetime
import hashlib
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ------------------------------------------------------------------------------
# Protocol Constants and Safety Limits
# ------------------------------------------------------------------------------
PROTOCOL_NAME: str = "SecureExamExchange"
PROTOCOL_VERSION: int = 1

EXPECTED_ENCRYPTION: str = "AES-256-GCM"
EXPECTED_KEY_WRAP: str = "RSA-OAEP-SHA256"
EXPECTED_SIGNATURE_ALGO: str = "RSA-PSS-SHA256"

MIN_RSA_KEY_SIZE: int = 3072
RSA_PUBLIC_EXPONENT: int = 65537

AES_KEY_BYTES: int = 32
GCM_NONCE_BYTES: int = 12
GCM_TAG_BYTES: int = 16
RSA_3072_MODULUS_BYTES: int = 384

# Default safety limits to prevent denial-of-service / memory exhaustion
MAX_PACKAGE_SIZE_BYTES: int = 50 * 1024 * 1024   # 50 MB
MAX_PLAINTEXT_SIZE_BYTES: int = 100 * 1024 * 1024 # 100 MB

SHA256_HEX_REGEX = re.compile(r"^[0-9a-fA-F]{64}$")

REQUIRED_TOP_LEVEL_KEYS = {
    "protocol",
    "version",
    "metadata",
    "encrypted_key",
    "nonce",
    "ciphertext",
    "tag",
    "signature",
}

REQUIRED_METADATA_KEYS = {
    "sender_id",
    "recipient_id",
    "filename",
    "file_size",
    "created_at",
    "encryption",
    "key_wrap",
    "signature",
    "plaintext_sha256",
}


# ------------------------------------------------------------------------------
# Custom Exceptions for Granular Security & Protocol Diagnosis
# ------------------------------------------------------------------------------
class SecureExchangeError(Exception):
    """Base exception for all secure exchange errors."""
    pass


class ProtocolValidationError(SecureExchangeError):
    """Raised when JSON structure, protocol header, or metadata is invalid."""
    pass


class SecurityVerificationError(SecureExchangeError):
    """Raised when cryptographic signature, key recovery, or GCM tag fails."""
    pass


class KeyManagementError(SecureExchangeError):
    """Raised when key loading, generation, or storage encounters an error."""
    pass


class FileSafetyError(SecureExchangeError):
    """Raised when file path, overwrite policy, or disk safety is violated."""
    pass


# ------------------------------------------------------------------------------
# 1. Canonical JSON Serialization & Strict Parsing
# ------------------------------------------------------------------------------
def canonical_json_bytes(value: Any) -> bytes:
    """
    Serializes a Python object into canonical UTF-8 JSON bytes according to protocol:
    - UTF-8 encoding
    - Sorted dictionary keys
    - Compact separators (',', ':')
    - No NaN, Infinity, or -Infinity constants
    - ensure_ascii=False
    """
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def parse_strict_json(json_bytes_or_str: Union[bytes, str]) -> Dict[str, Any]:
    """
    Parses UTF-8 JSON strictly:
    - Rejects duplicate object keys
    - Rejects nonstandard constants (NaN, Infinity, -Infinity)
    - Validates UTF-8 encoding if bytes are provided
    """
    if isinstance(json_bytes_or_str, bytes):
        try:
            text = json_bytes_or_str.decode("utf-8")
        except UnicodeDecodeError as e:
            raise ProtocolValidationError(f"Invalid UTF-8 encoding in JSON input: {e}") from e
    else:
        text = json_bytes_or_str

    def _reject_duplicate_keys(ordered_pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
        result_dict: Dict[str, Any] = {}
        for key, val in ordered_pairs:
            if key in result_dict:
                raise ProtocolValidationError(f"Duplicate key detected in JSON: '{key}'")
            result_dict[key] = val
        return result_dict

    def _reject_constants(constant_str: str) -> None:
        raise ProtocolValidationError(f"Non-standard JSON constant rejected: '{constant_str}'")

    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constants,
        )
    except json.JSONDecodeError as e:
        raise ProtocolValidationError(f"Malformed JSON syntax: {e}") from e

    if not isinstance(parsed, dict):
        raise ProtocolValidationError("Root JSON value must be an object/dictionary.")

    return parsed


# ------------------------------------------------------------------------------
# 2. Strict Base64 Validation & Decoding
# ------------------------------------------------------------------------------
def strict_b64decode(b64_string: Any, field_name: str) -> bytes:
    """
    Strictly decodes a Base64 string, rejecting invalid characters or corrupted padding.
    """
    if not isinstance(b64_string, str):
        raise ProtocolValidationError(f"Field '{field_name}' must be a string containing Base64 data.")
    try:
        return base64.b64decode(b64_string, validate=True)
    except (binascii.Error, ValueError) as e:
        raise ProtocolValidationError(f"Invalid Base64 encoding in field '{field_name}': {e}") from e


# ------------------------------------------------------------------------------
# 3. RSA Key Management & Fingerprints
# ------------------------------------------------------------------------------
def generate_receiver_keypair(
    key_size: int = MIN_RSA_KEY_SIZE,
    public_exponent: int = RSA_PUBLIC_EXPONENT,
) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """
    Generates a cryptographically strong RSA key pair (default: 3072-bit, e=65537).
    """
    if key_size < MIN_RSA_KEY_SIZE:
        raise KeyManagementError(f"Requested RSA key size ({key_size}) is below the required {MIN_RSA_KEY_SIZE} bits.")
    private_key = rsa.generate_private_key(
        public_exponent=public_exponent,
        key_size=key_size,
    )
    return private_key, private_key.public_key()


def save_receiver_keys(
    private_key: rsa.RSAPrivateKey,
    public_key: rsa.RSAPublicKey,
    private_key_path: Union[str, Path],
    public_key_path: Union[str, Path],
    passphrase: str,
    overwrite: bool = False,
) -> None:
    """
    Safely saves receiver private and public keys:
    - Never silently overwrites existing keys.
    - Encrypts the private key with PKCS#8 BestAvailableEncryption using the passphrase.
    - Writes atomically using temporary files to avoid partial or corrupted key files.
    - Applies restrictive file permissions (0600) where supported.
    """
    priv_path = Path(private_key_path).resolve()
    pub_path = Path(public_key_path).resolve()

    if priv_path.exists() and not overwrite:
        raise FileSafetyError(f"Private key file already exists at '{priv_path}'. Explicit confirmation required.")
    if pub_path.exists() and not overwrite:
        raise FileSafetyError(f"Public key file already exists at '{pub_path}'. Explicit confirmation required.")

    if not passphrase:
        raise KeyManagementError("Private key passphrase cannot be empty.")

    # Serialize in memory before touching the filesystem
    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode("utf-8")),
    )
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    priv_path.parent.mkdir(parents=True, exist_ok=True)
    pub_path.parent.mkdir(parents=True, exist_ok=True)

    # Atomic write for private key
    tmp_priv = None
    tmp_pub = None
    try:
        with tempfile.NamedTemporaryFile("wb", dir=priv_path.parent, delete=False) as f:
            tmp_priv = Path(f.name)
            f.write(priv_bytes)
            f.flush()
            os.fsync(f.fileno())

        # Attempt to restrict permissions on POSIX systems (0600: read/write owner only)
        if hasattr(os, "chmod"):
            try:
                os.chmod(tmp_priv, 0o600)
            except OSError:
                pass

        with tempfile.NamedTemporaryFile("wb", dir=pub_path.parent, delete=False) as f:
            tmp_pub = Path(f.name)
            f.write(pub_bytes)
            f.flush()
            os.fsync(f.fileno())

        os.replace(tmp_priv, priv_path)
        tmp_priv = None

        os.replace(tmp_pub, pub_path)
        tmp_pub = None

    finally:
        # Clean up temporary files on failure
        if tmp_priv and tmp_priv.exists():
            try:
                tmp_priv.unlink()
            except OSError:
                pass
        if tmp_pub and tmp_pub.exists():
            try:
                tmp_pub.unlink()
            except OSError:
                pass


def load_receiver_private_key(
    private_key_path: Union[str, Path],
    passphrase: str,
) -> rsa.RSAPrivateKey:
    """
    Loads and decrypts the receiver's RSA private key.
    Validates that:
    - The file exists and is accessible.
    - The passphrase is correct.
    - The key is an RSA private key with at least 3072 bits.
    Never automatically generates a replacement key on failure.
    """
    path = Path(private_key_path).resolve()
    if not path.is_file():
        raise KeyManagementError(f"Private key file not found: '{path}'")

    try:
        key_data = path.read_bytes()
    except OSError as e:
        raise KeyManagementError(f"Failed to read private key file '{path}': {e}") from e

    try:
        private_key = serialization.load_pem_private_key(
            key_data,
            password=passphrase.encode("utf-8") if passphrase else None,
        )
    except (ValueError, TypeError) as e:
        raise KeyManagementError(f"Failed to decrypt private key. Incorrect passphrase or corrupt PEM: {e}") from e

    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise KeyManagementError("Loaded key is not an RSA private key.")

    if private_key.key_size < MIN_RSA_KEY_SIZE:
        raise KeyManagementError(
            f"Receiver RSA key size ({private_key.key_size} bits) is below required minimum of {MIN_RSA_KEY_SIZE} bits."
        )

    return private_key


def load_public_key(public_key_path: Union[str, Path]) -> rsa.RSAPublicKey:
    """
    Loads an RSA public key from a PEM SubjectPublicKeyInfo file.
    Validates that key size is at least 3072 bits.
    """
    path = Path(public_key_path).resolve()
    if not path.is_file():
        raise KeyManagementError(f"Public key file not found: '{path}'")

    try:
        key_data = path.read_bytes()
    except OSError as e:
        raise KeyManagementError(f"Failed to read public key file '{path}': {e}") from e

    try:
        public_key = serialization.load_pem_public_key(key_data)
    except (ValueError, TypeError) as e:
        raise KeyManagementError(f"Failed to parse public key PEM from '{path}': {e}") from e

    if not isinstance(public_key, rsa.RSAPublicKey):
        raise KeyManagementError("Loaded key is not an RSA public key.")

    if public_key.key_size < MIN_RSA_KEY_SIZE:
        raise KeyManagementError(
            f"Public key size ({public_key.key_size} bits) is below required minimum of {MIN_RSA_KEY_SIZE} bits."
        )

    return public_key


def get_public_key_fingerprint(public_key: rsa.RSAPublicKey) -> str:
    """
    Computes the SHA-256 fingerprint of the public key's DER SubjectPublicKeyInfo serialization.
    Returns uppercase hexadecimal with colon separators (e.g., 'AA:BB:CC:...').
    """
    der_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashlib.sha256(der_bytes).hexdigest().upper()
    return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))


def export_receiver_public_key(
    public_key: rsa.RSAPublicKey,
    destination_path: Union[str, Path],
    overwrite: bool = False,
) -> Path:
    """
    Exports the receiver's public key in PEM SubjectPublicKeyInfo format to the user's destination.
    Never exports private keys.
    """
    dest = Path(destination_path).resolve()
    if dest.exists() and not overwrite:
        raise FileSafetyError(f"Destination public key path already exists: '{dest}'. Overwrite not confirmed.")

    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(pub_bytes)
    return dest


def import_sender_public_key(
    source_path: Union[str, Path],
    destination_path: Union[str, Path],
    overwrite: bool = False,
) -> Tuple[rsa.RSAPublicKey, str]:
    """
    Validates and imports a sender's public key:
    - Validates RSA key size >= 3072 bits.
    - Computes and returns the fingerprint.
    - Safely stores the key into the destination path.
    - Never silently overwrites an existing trusted sender key.
    """
    src = Path(source_path).resolve()
    dest = Path(destination_path).resolve()

    if not src.is_file():
        raise KeyManagementError(f"Sender public key source file not found: '{src}'")

    if dest.exists() and not overwrite:
        raise FileSafetyError(
            f"A trusted sender public key already exists at '{dest}'. Explicit confirmation required to replace it."
        )

    loaded_key = load_public_key(src)
    fingerprint = get_public_key_fingerprint(loaded_key)

    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(src.read_bytes())

    return loaded_key, fingerprint


# ------------------------------------------------------------------------------
# 4. Package Schema & Semantic Validation
# ------------------------------------------------------------------------------
def validate_package_structure(package: Dict[str, Any], receiver_modulus_bytes: int = RSA_3072_MODULUS_BYTES) -> None:
    """
    Validates all top-level keys, metadata fields, algorithm parameters,
    and Base64 encodings against the SecureExamExchange protocol v1 specification.
    """
    # 1. Top-level keys check
    actual_top_keys = set(package.keys())
    missing_top_keys = REQUIRED_TOP_LEVEL_KEYS - actual_top_keys
    unexpected_top_keys = actual_top_keys - REQUIRED_TOP_LEVEL_KEYS
    if missing_top_keys:
        raise ProtocolValidationError(f"Missing required top-level package keys: {sorted(missing_top_keys)}")
    if unexpected_top_keys:
        raise ProtocolValidationError(f"Unexpected top-level package keys: {sorted(unexpected_top_keys)}")

    # 2. Protocol & Version check
    if package["protocol"] != PROTOCOL_NAME:
        raise ProtocolValidationError(f"Unsupported protocol name '{package['protocol']}', expected '{PROTOCOL_NAME}'.")
    if package["version"] != PROTOCOL_VERSION or not isinstance(package["version"], int):
        raise ProtocolValidationError(f"Unsupported protocol version '{package['version']}', expected {PROTOCOL_VERSION}.")

    # 3. Metadata check
    metadata = package["metadata"]
    if not isinstance(metadata, dict):
        raise ProtocolValidationError("The 'metadata' field must be a JSON object.")

    actual_meta_keys = set(metadata.keys())
    missing_meta_keys = REQUIRED_METADATA_KEYS - actual_meta_keys
    unexpected_meta_keys = actual_meta_keys - REQUIRED_METADATA_KEYS
    if missing_meta_keys:
        raise ProtocolValidationError(f"Missing required metadata keys: {sorted(missing_meta_keys)}")
    if unexpected_meta_keys:
        raise ProtocolValidationError(f"Unexpected metadata keys: {sorted(unexpected_meta_keys)}")

    # Validate metadata types and values
    sender_id = metadata["sender_id"]
    recipient_id = metadata["recipient_id"]
    filename = metadata["filename"]
    file_size = metadata["file_size"]
    created_at = metadata["created_at"]
    enc_algo = metadata["encryption"]
    wrap_algo = metadata["key_wrap"]
    sig_algo = metadata["signature"]
    sha256_digest = metadata["plaintext_sha256"]

    if not isinstance(sender_id, str) or not sender_id.strip():
        raise ProtocolValidationError("Metadata 'sender_id' must be a non-empty string.")
    if not isinstance(recipient_id, str) or not recipient_id.strip():
        raise ProtocolValidationError("Metadata 'recipient_id' must be a non-empty string.")

    if not isinstance(filename, str) or not filename.strip():
        raise ProtocolValidationError("Metadata 'filename' must be a non-empty string.")
    # Ensure filename has no directory components
    if os.path.basename(filename) != filename or filename in {".", ".."}:
        raise ProtocolValidationError(f"Metadata 'filename' contains invalid or path traversal characters: '{filename}'.")

    if not isinstance(file_size, int) or file_size < 0:
        raise ProtocolValidationError(f"Metadata 'file_size' must be a non-negative integer, got {file_size}.")
    if file_size > MAX_PLAINTEXT_SIZE_BYTES:
        raise ProtocolValidationError(
            f"Metadata 'file_size' ({file_size} bytes) exceeds maximum permitted limit ({MAX_PLAINTEXT_SIZE_BYTES} bytes)."
        )

    if not isinstance(created_at, str) or not created_at.strip():
        raise ProtocolValidationError("Metadata 'created_at' must be a valid ISO-8601 timestamp string.")
    # Validate timestamp format
    try:
        # ISO-8601 parsing check (handles 'Z' and offsets)
        datetime.datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    except ValueError as e:
        raise ProtocolValidationError(f"Invalid ISO-8601 format in metadata 'created_at' ('{created_at}'): {e}") from e

    if enc_algo != EXPECTED_ENCRYPTION:
        raise ProtocolValidationError(f"Unsupported encryption algorithm '{enc_algo}', expected '{EXPECTED_ENCRYPTION}'.")
    if wrap_algo != EXPECTED_KEY_WRAP:
        raise ProtocolValidationError(f"Unsupported key wrap algorithm '{wrap_algo}', expected '{EXPECTED_KEY_WRAP}'.")
    if sig_algo != EXPECTED_SIGNATURE_ALGO:
        raise ProtocolValidationError(f"Unsupported signature algorithm '{sig_algo}', expected '{EXPECTED_SIGNATURE_ALGO}'.")

    if not isinstance(sha256_digest, str) or not SHA256_HEX_REGEX.match(sha256_digest):
        raise ProtocolValidationError(f"Metadata 'plaintext_sha256' must be a 64-character hexadecimal SHA-256 digest.")

    # 4. Strict Base64 and length validation
    enc_key_bytes = strict_b64decode(package["encrypted_key"], "encrypted_key")
    if len(enc_key_bytes) != receiver_modulus_bytes:
        raise ProtocolValidationError(
            f"Decoded 'encrypted_key' length ({len(enc_key_bytes)} bytes) does not match expected RSA modulus ({receiver_modulus_bytes} bytes)."
        )

    nonce_bytes = strict_b64decode(package["nonce"], "nonce")
    if len(nonce_bytes) != GCM_NONCE_BYTES:
        raise ProtocolValidationError(
            f"Decoded 'nonce' length ({len(nonce_bytes)} bytes) does not match required AES-GCM nonce size ({GCM_NONCE_BYTES} bytes)."
        )

    # Ciphertext must be valid Base64
    strict_b64decode(package["ciphertext"], "ciphertext")

    tag_bytes = strict_b64decode(package["tag"], "tag")
    if len(tag_bytes) != GCM_TAG_BYTES:
        raise ProtocolValidationError(
            f"Decoded 'tag' length ({len(tag_bytes)} bytes) does not match required GCM tag size ({GCM_TAG_BYTES} bytes)."
        )

    sig_bytes = strict_b64decode(package["signature"], "signature")
    if len(sig_bytes) != receiver_modulus_bytes:
        raise ProtocolValidationError(
            f"Decoded 'signature' length ({len(sig_bytes)} bytes) does not match expected RSA modulus ({receiver_modulus_bytes} bytes)."
        )


# ------------------------------------------------------------------------------
# 5. Digital Signature Verification
# ------------------------------------------------------------------------------
def verify_package_signature(package: Dict[str, Any], sender_public_key: rsa.RSAPublicKey) -> bool:
    """
    Verifies the sender's RSA-PSS digital signature over the canonical JSON package:
    1. Reads top-level signature and decodes Base64.
    2. Creates a shallow copy of package omitting ONLY the top-level 'signature' key.
       (The metadata['signature'] algorithm identifier remains untouched).
    3. Serializes the remaining structure using canonical_json_bytes().
    4. Verifies using RSA-PSS with SHA-256, MGF1-SHA-256, and maximum PSS salt length.
    5. Returns True or raises SecurityVerificationError.
    """
    if "signature" not in package:
        raise ProtocolValidationError("Package is missing the top-level 'signature' field.")

    sig_bytes = strict_b64decode(package["signature"], "signature")

    # Omit only the top-level 'signature' field
    package_to_verify = {k: v for k, v in package.items() if k != "signature"}
    signed_canonical_bytes = canonical_json_bytes(package_to_verify)

    try:
        sender_public_key.verify(
            sig_bytes,
            signed_canonical_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature as e:
        raise SecurityVerificationError(
            "Sender digital signature verification failed. The package may have been altered or signed with an untrusted key."
        ) from e


# ------------------------------------------------------------------------------
# 6. RSA Session-Key Recovery (RSA-OAEP)
# ------------------------------------------------------------------------------
def recover_aes_session_key(encrypted_key_b64: str, receiver_private_key: rsa.RSAPrivateKey) -> bytes:
    """
    Recovers the 32-byte AES session key using the receiver's private RSA key:
    - RSA-OAEP with SHA-256 and MGF1-SHA-256, empty label (None).
    - Rejects any recovered key whose length is not exactly 32 bytes (256 bits).
    - Never leaks or displays the session key.
    """
    enc_key_bytes = strict_b64decode(encrypted_key_b64, "encrypted_key")

    try:
        session_key = receiver_private_key.decrypt(
            enc_key_bytes,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except Exception as e:
        raise SecurityVerificationError(
            f"Failed to recover AES session key using receiver private key (RSA-OAEP decryption failed): {e}"
        ) from e

    if len(session_key) != AES_KEY_BYTES:
        raise SecurityVerificationError(
            f"Recovered session key length is {len(session_key)} bytes; expected exactly {AES_KEY_BYTES} bytes."
        )

    return session_key


# ------------------------------------------------------------------------------
# 7. AES-256-GCM Decryption & Authenticated Plaintext Validation
# ------------------------------------------------------------------------------
def decrypt_and_authenticate_file(
    session_key: bytes,
    nonce_b64: str,
    ciphertext_b64: str,
    tag_b64: str,
    metadata: Dict[str, Any],
) -> bytes:
    """
    Performs AES-256-GCM authenticated decryption:
    - Nonce: 12 bytes
    - Ciphertext + Tag: Combined for the AESGCM API
    - Associated Data (AAD): canonical UTF-8 bytes of the metadata object
    - Validates recovered plaintext size against metadata['file_size']
    - Validates recovered plaintext SHA-256 against metadata['plaintext_sha256']
    """
    nonce = strict_b64decode(nonce_b64, "nonce")
    ciphertext = strict_b64decode(ciphertext_b64, "ciphertext")
    tag = strict_b64decode(tag_b64, "tag")

    # Associated Authenticated Data is the canonical JSON bytes of the entire metadata object
    associated_data = canonical_json_bytes(metadata)

    # In cryptography library, AESGCM.decrypt expects ciphertext with the tag appended
    combined_ciphertext_tag = ciphertext + tag

    aesgcm = AESGCM(session_key)
    try:
        plaintext = aesgcm.decrypt(nonce, combined_ciphertext_tag, associated_data)
    except InvalidTag as e:
        raise SecurityVerificationError(
            "AES-GCM authentication failed (InvalidTag). Ciphertext, authentication tag, or metadata was tampered with."
        ) from e

    # Stage 6: Plaintext verification against metadata
    actual_length = len(plaintext)
    expected_length = metadata["file_size"]
    if actual_length != expected_length:
        raise SecurityVerificationError(
            f"Decrypted plaintext size mismatch: recovered {actual_length} bytes, metadata claimed {expected_length} bytes."
        )

    actual_sha256 = hashlib.sha256(plaintext).hexdigest().lower()
    expected_sha256 = metadata["plaintext_sha256"].lower()
    if actual_sha256 != expected_sha256:
        raise SecurityVerificationError(
            f"Decrypted plaintext SHA-256 digest mismatch:\n  Calculated: {actual_sha256}\n  Expected:   {expected_sha256}"
        )

    return plaintext


# ------------------------------------------------------------------------------
# 8. Safe File Persistence (Atomicity & Path Traversal Defense)
# ------------------------------------------------------------------------------
def save_plaintext_safely(
    plaintext: bytes,
    raw_filename: str,
    output_dir: Union[str, Path],
    overwrite: bool = False,
) -> Path:
    """
    Safely writes recovered plaintext to disk:
    - Strips all directory components to prevent path traversal attacks.
    - Rejects empty, root, or reserved names.
    - Prevents unintended overwrite unless explicitly authorized.
    - Writes to a temporary file in the destination folder, flushes, syncs,
      and performs an atomic rename.
    - Cleans up temporary files on any failure.
    """
    out_dir = Path(output_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    # Path traversal protection: isolate basename only
    safe_filename = Path(raw_filename).name
    if not safe_filename or safe_filename in {".", ".."}:
        raise FileSafetyError(f"Invalid or unsafe output filename: '{raw_filename}'")

    target_path = (out_dir / safe_filename).resolve()

    # Verify target path is strictly within output_dir
    try:
        target_path.relative_to(out_dir)
    except ValueError as e:
        raise FileSafetyError(f"Path traversal detected: target '{target_path}' is outside '{out_dir}'.") from e

    if target_path.exists() and not overwrite:
        raise FileSafetyError(
            f"Output file already exists: '{target_path}'. Explicit user confirmation required to overwrite."
        )

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile("wb", dir=out_dir, delete=False, prefix=".exam_tmp_") as tmp_file:
            tmp_path = Path(tmp_file.name)
            tmp_file.write(plaintext)
            tmp_file.flush()
            os.fsync(tmp_file.fileno())

        os.replace(tmp_path, target_path)
        tmp_path = None
        return target_path
    finally:
        if tmp_path and tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass


# ------------------------------------------------------------------------------
# 9. Complete Receiver Decryption Workflow
# ------------------------------------------------------------------------------
def decrypt_and_verify_package(
    package_path: Union[str, Path],
    receiver_private_key: rsa.RSAPrivateKey,
    sender_public_key: rsa.RSAPublicKey,
    output_dir: Union[str, Path],
    expected_recipient_id: Optional[str] = None,
    overwrite: bool = False,
    max_package_size: int = MAX_PACKAGE_SIZE_BYTES,
) -> Dict[str, Any]:
    """
    Executes the strict 7-stage receiver verification and decryption pipeline:

    Stage 1: Read & strictly validate the incoming JSON package.
    Stage 2: Verify the sender's RSA-PSS digital signature.
             (Do NOT attempt RSA decryption if this fails!)
    Stage 3: Validate the intended recipient ID against expected_recipient_id.
    Stage 4: Recover the AES-256 session key using RSA-OAEP.
    Stage 5: Authenticate & decrypt the ciphertext using AES-256-GCM.
    Stage 6: Validate the recovered plaintext byte size and SHA-256 hash.
    Stage 7: Safely persist the plaintext file to the output directory.

    Returns a comprehensive result dictionary with verification details.
    """
    pkg_file = Path(package_path).resolve()
    if not pkg_file.is_file():
        raise FileSafetyError(f"Incoming examination package file not found: '{pkg_file}'")

    # Enforce file size limit before loading into memory
    file_size_on_disk = pkg_file.stat().st_size
    if file_size_on_disk > max_package_size:
        raise ProtocolValidationError(
            f"Package file size ({file_size_on_disk} bytes) exceeds maximum limit ({max_package_size} bytes)."
        )

    # ---------------- Stage 1: Read and Parse Package ----------------
    raw_content = pkg_file.read_bytes()
    package = parse_strict_json(raw_content)

    modulus_bytes = (receiver_private_key.key_size + 7) // 8
    validate_package_structure(package, receiver_modulus_bytes=modulus_bytes)

    metadata = package["metadata"]

    # ---------------- Stage 2: Verify Sender Signature ----------------
    # MUST be completed before attempting RSA decryption
    verify_package_signature(package, sender_public_key)

    # ---------------- Stage 3: Validate Intended Recipient -----------
    actual_recipient = metadata["recipient_id"]
    if expected_recipient_id is not None:
        if actual_recipient != expected_recipient_id:
            raise SecurityVerificationError(
                f"Recipient mismatch: package is intended for '{actual_recipient}', but this receiver expects '{expected_recipient_id}'."
            )

    # ---------------- Stage 4: Recover AES Session Key ---------------
    session_key = recover_aes_session_key(package["encrypted_key"], receiver_private_key)

    try:
        # ------------ Stage 5 & 6: AES-GCM Decrypt & Plaintext Validation ---
        plaintext = decrypt_and_authenticate_file(
            session_key=session_key,
            nonce_b64=package["nonce"],
            ciphertext_b64=package["ciphertext"],
            tag_b64=package["tag"],
            metadata=metadata,
        )

        # ------------ Stage 7: Safely Persist Plaintext -----------------
        saved_file_path = save_plaintext_safely(
            plaintext=plaintext,
            raw_filename=metadata["filename"],
            output_dir=output_dir,
            overwrite=overwrite,
        )

    finally:
        # Secure hygiene: zeroize session key reference
        del session_key

    return {
        "status": "SUCCESS",
        "verified": True,
        "sender_id": metadata["sender_id"],
        "recipient_id": metadata["recipient_id"],
        "created_at": metadata["created_at"],
        "original_filename": metadata["filename"],
        "output_path": str(saved_file_path),
        "file_size": len(plaintext),
        "sha256": metadata["plaintext_sha256"],
        "sender_fingerprint": get_public_key_fingerprint(sender_public_key),
        "receiver_fingerprint": get_public_key_fingerprint(receiver_private_key.public_key()),
    }
