"""
Generator for receiver_secure_exam_exchange.ipynb
=================================================
Generates the comprehensive, beautifully styled Jupyter Notebook following the
exact 17-section structure and pedagogical requirements of the workshop.
"""

from __future__ import annotations

import json
from pathlib import Path


def create_markdown_cell(source: str) -> dict:
    return {
        "cell_type": "markdown",
        "metadata": {},
        "source": [line + "\n" for line in source.strip().split("\n")],
    }


def create_code_cell(source: str) -> dict:
    return {
        "cell_type": "code",
        "execution_count": None,
        "metadata": {},
        "outputs": [],
        "source": [line + "\n" for line in source.strip().split("\n")],
    }


def build_notebook():
    cells = []

    # =========================================================================
    # Section 1: Project Overview and Security Objectives
    # =========================================================================
    sec1 = """# Secure Examination-Paper Exchange Using Python
## Receiver Application & Verification Suite (Protocol `SecureExamExchange` v1)

---

### 1. Project Overview & Security Objectives

In an academic examination environment, question papers prepared by faculty members must be securely delivered to the university examination coordinator over untrusted public networks or file exchanges.

The primary objective of this **Receiver Application** is to guarantee:
1. **Confidentiality:** Only the designated coordinator possessing the authorized private key can decrypt the AES session key and recover the paper.
2. **Sender Authentication:** Every paper package is signed with the faculty member's RSA private key. The receiver authenticates the sender's identity prior to decryption.
3. **Integrity & Authenticity:** AES-256-GCM combined with RSA-PSS signature verification detects any unauthorized tampering, bit-flipping, or data truncation.
4. **Metadata Binding:** Examination parameters (filename, file size, sender/recipient IDs, and SHA-256 digest) are authenticated as AES-GCM Associated Data (AAD).
5. **Fail-Closed Security:** Under NO circumstances is partial plaintext released or saved if any signature, key recovery, or authentication tag check fails.
6. **Path Traversal & Overwrite Protection:** Output files are sanitized and saved atomically; pre-existing examination papers cannot be overwritten without explicit authorization."""
    cells.append(create_markdown_cell(sec1))

    # =========================================================================
    # Section 2: Sequence-of-Events Mermaid Architecture Diagram
    # =========================================================================
    sec_diag = """### Protocol Architecture & End-to-End Sequence of Events

The diagram below outlines the exact hybrid cryptographic handshake and fail-closed validation pipeline:

```mermaid
sequenceDiagram
    autonumber
    actor Sender as Faculty Member (Sender)
    participant Channel as Untrusted Transport / Filesystem
    actor Receiver as Examination Coordinator (Receiver)

    Note over Sender: Prepare Examination Paper Plaintext
    Sender->>Sender: Generate 32-byte AES Session Key (AES-256-GCM)
    Sender->>Sender: Encrypt Paper & Authenticate Metadata as AAD
    Sender->>Sender: Encapsulate AES Key with Receiver RSA-3072 Public Key (RSA-OAEP)
    Sender->>Sender: Sign Canonical Package with Sender RSA-3072 Private Key (RSA-PSS)
    Sender->>Channel: Transmit exam_package.json

    Channel->>Receiver: Receive exam_package.json
    Note over Receiver: Stage 1: Parse Strict JSON (Reject Duplicates & Oversized)
    
    Receiver->>Receiver: Stage 2: Verify Sender RSA-PSS Signature
    alt Invalid Signature or Untrusted Sender Public Key
        Receiver-->>Receiver: REJECT: Abort immediately. Zero decryption attempted.
    end

    Receiver->>Receiver: Stage 3: Validate Expected Recipient ID
    alt Recipient ID Mismatch
        Receiver-->>Receiver: REJECT: Mismatched intended recipient. Abort.
    end

    Receiver->>Receiver: Stage 4: Recover AES-256 Key via RSA-OAEP
    alt Incorrect Receiver Private Key
        Receiver-->>Receiver: REJECT: RSA-OAEP Decryption Failed. Abort.
    end

    Receiver->>Receiver: Stage 5: Decrypt & Authenticate via AES-256-GCM (AAD = Metadata)
    alt GCM Authentication Tag Invalid / Tampered Ciphertext
        Receiver-->>Receiver: REJECT: InvalidTag. Abort with zero plaintext output.
    end

    Receiver->>Receiver: Stage 6: Verify Plaintext Size & SHA-256 Digest
    alt File Size or Hash Mismatch
        Receiver-->>Receiver: REJECT: Hash mismatch. Abort.
    end

    Receiver->>Receiver: Stage 7: Path Traversal Check & Atomic File Write
    Receiver-->>Receiver: SUCCESS: Examination Paper Saved Safely!
```"""
    cells.append(create_markdown_cell(sec_diag))

    # =========================================================================
    # Section 2: Installation of Dependencies
    # =========================================================================
    sec2 = """### 2. Installation of Dependencies

This project requires standard cryptographic primitives provided by the vetted `cryptography` Python library. Manual cryptographic implementations (e.g., custom AES or RSA) are strictly prohibited.

Run the cell below to verify or install required packages in your current environment."""
    cells.append(create_markdown_cell(sec2))

    code2 = """# Install required dependencies if running in a fresh environment
import sys
!{sys.executable} -m pip install --quiet "cryptography>=41.0.0" "pytest>=7.0.0" ipykernel"""
    cells.append(create_code_cell(code2))

    # =========================================================================
    # Section 3: Imports and Directory Setup
    # =========================================================================
    sec3 = """### 3. Imports and Directory Setup

We establish a clean, sandboxed directory layout for the receiver:
```
secure_exam_exchange/
    keys/                  # Receiver private and public keys
    sender_public_keys/    # Trusted sender public keys
    incoming/              # Transferred encrypted JSON packages
    received/              # Safely recovered plaintext examination papers
    test_results/          # Audit logs and automated test reports
    sample_data/           # Synthetic examination papers for demonstration
```"""
    cells.append(create_markdown_cell(sec3))

    code3 = """from __future__ import annotations

import base64
import binascii
import datetime
import getpass
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import cryptography
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

print(f"Python Version: {sys.version.split()[0]}")
print(f"Cryptography Library Version: {cryptography.__version__}")

# Workspace directories
BASE_DIR = Path("secure_exam_exchange")
KEYS_DIR = BASE_DIR / "keys"
SENDER_KEYS_DIR = BASE_DIR / "sender_public_keys"
INCOMING_DIR = BASE_DIR / "incoming"
RECEIVED_DIR = BASE_DIR / "received"
TEST_RESULTS_DIR = BASE_DIR / "test_results"
SAMPLE_DATA_DIR = BASE_DIR / "sample_data"

for folder in [KEYS_DIR, SENDER_KEYS_DIR, INCOMING_DIR, RECEIVED_DIR, TEST_RESULTS_DIR, SAMPLE_DATA_DIR]:
    folder.mkdir(parents=True, exist_ok=True)

print("Project directory structure initialized successfully.")"""
    cells.append(create_code_cell(code3))

    # =========================================================================
    # Section 4: Canonical JSON and Strict Parsing Utilities
    # =========================================================================
    sec4 = """### 4. Canonical JSON & Strict Parsing Utilities

#### Why Canonical Serialization is Mandatory
Digital signatures verify raw byte arrays. In JSON, key ordering is non-deterministic and whitespace formatting varies across operating systems. 

To ensure exact cryptographic agreement between the sender and receiver:
- Keys are sorted lexicographically (`sort_keys=True`).
- Separators are compact `(',', ':')` with no redundant whitespace.
- UTF-8 encoding is strictly enforced.
- Duplicate keys and non-standard constants (`NaN`, `Infinity`) are rejected."""
    cells.append(create_markdown_cell(sec4))

    code4 = """# Custom Protocol Exceptions
class SecureExchangeError(Exception): pass
class ProtocolValidationError(SecureExchangeError): pass
class SecurityVerificationError(SecureExchangeError): pass
class KeyManagementError(SecureExchangeError): pass
class FileSafetyError(SecureExchangeError): pass

def canonical_json_bytes(value: Any) -> bytes:
    \"\"\"
    Serializes a Python dictionary/value to protocol canonical UTF-8 JSON bytes:
    - Sorted dictionary keys
    - Compact separators (',', ':')
    - No NaN/Infinity constants
    - UTF-8 byte output
    \"\"\"
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")

def parse_strict_json(json_bytes_or_str: Union[bytes, str]) -> Dict[str, Any]:
    \"\"\"
    Parses UTF-8 JSON strictly:
    - Rejects duplicate keys
    - Rejects nonstandard constants (NaN, Infinity)
    - Validates UTF-8 encoding
    \"\"\"
    if isinstance(json_bytes_or_str, bytes):
        try:
            text = json_bytes_or_str.decode("utf-8")
        except UnicodeDecodeError as e:
            raise ProtocolValidationError(f"Invalid UTF-8 encoding in JSON: {e}") from e
    else:
        text = json_bytes_or_str

    def _reject_duplicates(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
        d: Dict[str, Any] = {}
        for k, v in pairs:
            if k in d:
                raise ProtocolValidationError(f"Duplicate key detected in JSON: '{k}'")
            d[k] = v
        return d

    def _reject_constants(val: str) -> None:
        raise ProtocolValidationError(f"Non-standard JSON constant rejected: '{val}'")

    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_constants,
        )
    except json.JSONDecodeError as e:
        raise ProtocolValidationError(f"Malformed JSON syntax: {e}") from e

    if not isinstance(parsed, dict):
        raise ProtocolValidationError("Root JSON value must be an object.")
    return parsed

def strict_b64decode(b64_string: Any, field_name: str) -> bytes:
    \"\"\"Strictly decodes Base64 data with character and padding validation.\"\"\"
    if not isinstance(b64_string, str):
        raise ProtocolValidationError(f"Field '{field_name}' must be a string containing Base64 data.")
    try:
        return base64.b64decode(b64_string, validate=True)
    except (binascii.Error, ValueError) as e:
        raise ProtocolValidationError(f"Invalid Base64 in field '{field_name}': {e}") from e

print("Canonical JSON and parsing utilities defined.")"""
    cells.append(create_code_cell(code4))

    # =========================================================================
    # Section 5: RSA Key Generation and Storage
    # =========================================================================
    sec5 = """### 5. Receiver RSA Key Generation and Secure Storage

- **RSA Key Size:** 3072 bits ($e = 65537$)
- **Private Key Encryption:** PKCS#8 format encrypted with `BestAvailableEncryption` (AES-256-CBC with PBKDF2/scrypt derivation).
- **Passphrase:** Prompted securely using `getpass.getpass()`.
- **Atomic File Writing:** Keys are written via temporary files and atomically published to prevent partial or corrupted key files."""
    cells.append(create_markdown_cell(sec5))

    code5 = """MIN_RSA_KEY_SIZE = 3072
RSA_PUBLIC_EXPONENT = 65537

def generate_receiver_keypair(key_size: int = MIN_RSA_KEY_SIZE) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    if key_size < MIN_RSA_KEY_SIZE:
        raise KeyManagementError(f"RSA key size must be at least {MIN_RSA_KEY_SIZE} bits.")
    private_key = rsa.generate_private_key(
        public_exponent=RSA_PUBLIC_EXPONENT,
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
    priv_path = Path(private_key_path).resolve()
    pub_path = Path(public_key_path).resolve()

    if priv_path.exists() and not overwrite:
        raise FileSafetyError(f"Private key already exists at '{priv_path}'. Explicit confirmation required.")
    if pub_path.exists() and not overwrite:
        raise FileSafetyError(f"Public key already exists at '{pub_path}'. Explicit confirmation required.")

    if not passphrase:
        raise KeyManagementError("Passphrase cannot be empty.")

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

    tmp_priv, tmp_pub = None, None
    try:
        with tempfile.NamedTemporaryFile("wb", dir=priv_path.parent, delete=False) as f:
            tmp_priv = Path(f.name)
            f.write(priv_bytes)
            f.flush()
            os.fsync(f.fileno())

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
        if tmp_priv and tmp_priv.exists():
            tmp_priv.unlink()
        if tmp_pub and tmp_pub.exists():
            tmp_pub.unlink()

def load_receiver_private_key(private_key_path: Union[str, Path], passphrase: str) -> rsa.RSAPrivateKey:
    path = Path(private_key_path).resolve()
    if not path.is_file():
        raise KeyManagementError(f"Private key file not found: '{path}'")
    try:
        data = path.read_bytes()
        key = serialization.load_pem_private_key(data, password=passphrase.encode("utf-8") if passphrase else None)
    except Exception as e:
        raise KeyManagementError(f"Failed to load/decrypt private key (bad passphrase or corrupt PEM): {e}") from e

    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < MIN_RSA_KEY_SIZE:
        raise KeyManagementError(f"Key is not a valid RSA private key of at least {MIN_RSA_KEY_SIZE} bits.")
    return key

def load_public_key(public_key_path: Union[str, Path]) -> rsa.RSAPublicKey:
    path = Path(public_key_path).resolve()
    if not path.is_file():
        raise KeyManagementError(f"Public key file not found: '{path}'")
    try:
        data = path.read_bytes()
        key = serialization.load_pem_public_key(data)
    except Exception as e:
        raise KeyManagementError(f"Failed to parse public key PEM: {e}") from e
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size < MIN_RSA_KEY_SIZE:
        raise KeyManagementError(f"Key is not a valid RSA public key of at least {MIN_RSA_KEY_SIZE} bits.")
    return key

print("RSA Key management functions loaded.")"""
    cells.append(create_code_cell(code5))

    # Interactive key creation cell (safeguarded)
    sec5_interactive = """#### 5.1 Interactive Receiver Key Pair Creation
Run the code cell below to generate or verify your receiver key pair. If keys already exist, the cell preserves them safely."""
    cells.append(create_markdown_cell(sec5_interactive))

    code5_interactive = """recv_priv_path = KEYS_DIR / "receiver_private.pem"
recv_pub_path = KEYS_DIR / "receiver_public.pem"

if recv_priv_path.exists():
    print(f"Existing receiver private key found at: {recv_priv_path}")
    print("Skipping automatic overwrite to preserve existing coordinator identity.")
else:
    print("Creating new RSA-3072 receiver keypair...")
    # For interactive use in notebook:
    passphrase = getpass.getpass("Enter a secure passphrase to protect your receiver private key: ")
    confirm_passphrase = getpass.getpass("Confirm passphrase: ")
    if passphrase != confirm_passphrase:
        raise ValueError("Passphrases do not match!")
    
    priv_key, pub_key = generate_receiver_keypair(key_size=3072)
    save_receiver_keys(priv_key, pub_key, recv_priv_path, recv_pub_path, passphrase=passphrase, overwrite=False)
    print("Receiver RSA-3072 key pair successfully generated and saved!")"""
    cells.append(create_code_cell(code5_interactive))

    # =========================================================================
    # Section 6 & 7 & 8: Public-Key Export, Import, and Fingerprints
    # =========================================================================
    sec678 = """### 6, 7 & 8. Public Key Export, Import, & SHA-256 Fingerprints

#### The Public-Key Distribution Dilemma
Public keys are not secret, but they **must be authentic**. If an adversary substitutes the sender's public key with their own, they could sign counterfeit examination papers.

To resolve this without requiring a full X.509 Public Key Infrastructure (PKI), participants compute a cryptographic **SHA-256 Fingerprint** over the canonical DER `SubjectPublicKeyInfo` bytes and compare it out-of-band (e.g., via authenticated institutional directory or telephone confirmation)."""
    cells.append(create_markdown_cell(sec678))

    code678 = """def get_public_key_fingerprint(public_key: rsa.RSAPublicKey) -> str:
    \"\"\"
    Serializes public key to DER SubjectPublicKeyInfo, calculates SHA-256 digest,
    and formats as uppercase hex separated by colons (e.g., 'AA:BB:CC:...').
    \"\"\"
    der_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashlib.sha256(der_bytes).hexdigest().upper()
    return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))

def export_receiver_public_key(public_key: rsa.RSAPublicKey, dest_path: Union[str, Path], overwrite: bool = False) -> Path:
    dest = Path(dest_path).resolve()
    if dest.exists() and not overwrite:
        raise FileSafetyError(f"Destination public key path already exists: '{dest}'")
    pem_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(pem_bytes)
    return dest

def import_sender_public_key(source_path: Union[str, Path], dest_path: Union[str, Path], overwrite: bool = False) -> Tuple[rsa.RSAPublicKey, str]:
    src = Path(source_path).resolve()
    dest = Path(dest_path).resolve()
    if not src.is_file():
        raise KeyManagementError(f"Sender public key not found: '{src}'")
    if dest.exists() and not overwrite:
        raise FileSafetyError(f"Sender public key already exists at '{dest}'. Confirmation needed to replace.")
    key = load_public_key(src)
    fp = get_public_key_fingerprint(key)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(src.read_bytes())
    return key, fp

# Display fingerprints for our current workshop keys
if (KEYS_DIR / "receiver_public.pem").exists():
    r_pub = load_public_key(KEYS_DIR / "receiver_public.pem")
    print("=" * 70)
    print("RECEIVER PUBLIC KEY FINGERPRINT (Share with Sender):")
    print(get_public_key_fingerprint(r_pub))
    print("=" * 70)

if (SENDER_KEYS_DIR / "sender_public.pem").exists():
    s_pub = load_public_key(SENDER_KEYS_DIR / "sender_public.pem")
    print("TRUSTED SENDER PUBLIC KEY FINGERPRINT (Verify with Faculty):")
    print(get_public_key_fingerprint(s_pub))
    print("=" * 70)"""
    cells.append(create_code_cell(code678))

    # =========================================================================
    # Section 9: Package Validation
    # =========================================================================
    sec9 = """### 9. Protocol Schema & Package Validation

The receiver strictly validates the incoming JSON package against the `SecureExamExchange` v1 protocol specification:
- Exactly 8 top-level keys
- Exactly 9 metadata keys
- Valid algorithms: `AES-256-GCM`, `RSA-OAEP-SHA256`, `RSA-PSS-SHA256`
- Exact decoded byte lengths: `nonce` (12 bytes), `tag` (16 bytes), `encrypted_key` (384 bytes for RSA-3072), `signature` (384 bytes)."""
    cells.append(create_markdown_cell(sec9))

    code9 = """PROTOCOL_NAME = "SecureExamExchange"
PROTOCOL_VERSION = 1
EXPECTED_ENCRYPTION = "AES-256-GCM"
EXPECTED_KEY_WRAP = "RSA-OAEP-SHA256"
EXPECTED_SIGNATURE_ALGO = "RSA-PSS-SHA256"

AES_KEY_BYTES = 32
GCM_NONCE_BYTES = 12
GCM_TAG_BYTES = 16
RSA_3072_MODULUS_BYTES = 384
MAX_PLAINTEXT_SIZE_BYTES = 100 * 1024 * 1024
SHA256_HEX_REGEX = re.compile(r"^[0-9a-fA-F]{64}$")

REQUIRED_TOP_LEVEL_KEYS = {"protocol", "version", "metadata", "encrypted_key", "nonce", "ciphertext", "tag", "signature"}
REQUIRED_METADATA_KEYS = {"sender_id", "recipient_id", "filename", "file_size", "created_at", "encryption", "key_wrap", "signature", "plaintext_sha256"}

def validate_package_structure(package: Dict[str, Any], receiver_modulus_bytes: int = RSA_3072_MODULUS_BYTES) -> None:
    # 1. Top-level keys
    actual_top = set(package.keys())
    if REQUIRED_TOP_LEVEL_KEYS - actual_top:
        raise ProtocolValidationError(f"Missing required top-level keys: {sorted(REQUIRED_TOP_LEVEL_KEYS - actual_top)}")
    if actual_top - REQUIRED_TOP_LEVEL_KEYS:
        raise ProtocolValidationError(f"Unexpected top-level keys: {sorted(actual_top - REQUIRED_TOP_LEVEL_KEYS)}")

    # 2. Protocol Header
    if package["protocol"] != PROTOCOL_NAME:
        raise ProtocolValidationError(f"Unsupported protocol: '{package['protocol']}' (expected '{PROTOCOL_NAME}')")
    if package["version"] != PROTOCOL_VERSION or not isinstance(package["version"], int):
        raise ProtocolValidationError(f"Unsupported version: '{package['version']}' (expected {PROTOCOL_VERSION})")

    # 3. Metadata
    metadata = package["metadata"]
    if not isinstance(metadata, dict):
        raise ProtocolValidationError("'metadata' must be a JSON dictionary.")
    actual_meta = set(metadata.keys())
    if REQUIRED_METADATA_KEYS - actual_meta:
        raise ProtocolValidationError(f"Missing metadata keys: {sorted(REQUIRED_METADATA_KEYS - actual_meta)}")
    if actual_meta - REQUIRED_METADATA_KEYS:
        raise ProtocolValidationError(f"Unexpected metadata keys: {sorted(actual_meta - REQUIRED_METADATA_KEYS)}")

    # Check metadata fields
    if not isinstance(metadata["sender_id"], str) or not metadata["sender_id"].strip():
        raise ProtocolValidationError("metadata 'sender_id' must be a non-empty string.")
    if not isinstance(metadata["recipient_id"], str) or not metadata["recipient_id"].strip():
        raise ProtocolValidationError("metadata 'recipient_id' must be a non-empty string.")
    if not isinstance(metadata["filename"], str) or os.path.basename(metadata["filename"]) != metadata["filename"] or metadata["filename"] in {".", ".."}:
        raise ProtocolValidationError(f"Invalid or unsafe metadata filename: '{metadata['filename']}'")
    if not isinstance(metadata["file_size"], int) or metadata["file_size"] < 0 or metadata["file_size"] > MAX_PLAINTEXT_SIZE_BYTES:
        raise ProtocolValidationError(f"Invalid file_size in metadata: {metadata['file_size']}")

    try:
        datetime.datetime.fromisoformat(metadata["created_at"].replace("Z", "+00:00"))
    except ValueError as e:
        raise ProtocolValidationError(f"Invalid ISO-8601 created_at timestamp: {e}") from e

    if metadata["encryption"] != EXPECTED_ENCRYPTION:
        raise ProtocolValidationError(f"Unsupported encryption: {metadata['encryption']}")
    if metadata["key_wrap"] != EXPECTED_KEY_WRAP:
        raise ProtocolValidationError(f"Unsupported key_wrap: {metadata['key_wrap']}")
    if metadata["signature"] != EXPECTED_SIGNATURE_ALGO:
        raise ProtocolValidationError(f"Unsupported signature algo: {metadata['signature']}")
    if not isinstance(metadata["plaintext_sha256"], str) or not SHA256_HEX_REGEX.match(metadata["plaintext_sha256"]):
        raise ProtocolValidationError("metadata 'plaintext_sha256' must be 64-char hexadecimal SHA-256 digest.")

    # 4. Decoded field lengths
    if len(strict_b64decode(package["encrypted_key"], "encrypted_key")) != receiver_modulus_bytes:
        raise ProtocolValidationError("Decoded 'encrypted_key' length mismatch with RSA modulus.")
    if len(strict_b64decode(package["nonce"], "nonce")) != GCM_NONCE_BYTES:
        raise ProtocolValidationError("Decoded 'nonce' length must be 12 bytes.")
    strict_b64decode(package["ciphertext"], "ciphertext")
    if len(strict_b64decode(package["tag"], "tag")) != GCM_TAG_BYTES:
        raise ProtocolValidationError("Decoded 'tag' length must be 16 bytes.")
    if len(strict_b64decode(package["signature"], "signature")) != receiver_modulus_bytes:
        raise ProtocolValidationError("Decoded 'signature' length mismatch with RSA modulus.")

print("Package validation engine loaded.")"""
    cells.append(create_code_cell(code9))

    # =========================================================================
    # Section 10: Digital Signature Verification
    # =========================================================================
    sec10 = """### 10. Digital Signature Verification (RSA-PSS)

**Crucial Security Rule:** The sender's digital signature MUST be verified before attempting any RSA private-key decryption. This prevents chosen-ciphertext or padding-oracle attempts against the receiver's private key.

- **Signature Scheme:** RSA-PSS (Probabilistic Signature Scheme)
- **Hash Algorithm:** SHA-256
- **Mask Generation Function:** MGF1 with SHA-256
- **Salt Length:** `padding.PSS.MAX_LENGTH`
- **Signed Data:** The canonical JSON bytes of the package omitting *only* the top-level `signature` property (the metadata `signature` field identifying the algorithm remains in place)."""
    cells.append(create_markdown_cell(sec10))

    code10 = """def verify_package_signature(package: Dict[str, Any], sender_public_key: rsa.RSAPublicKey) -> bool:
    \"\"\"
    Verifies sender RSA-PSS signature over canonical JSON of the package
    excluding only the top-level 'signature' key.
    \"\"\"
    if "signature" not in package:
        raise ProtocolValidationError("Package missing top-level 'signature'.")

    sig_bytes = strict_b64decode(package["signature"], "signature")

    # Copy package omitting only top-level signature
    package_to_verify = {k: v for k, v in package.items() if k != "signature"}
    canonical_bytes = canonical_json_bytes(package_to_verify)

    try:
        sender_public_key.verify(
            sig_bytes,
            canonical_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature as e:
        raise SecurityVerificationError(
            "Sender digital signature verification failed. The package may have been altered or signed by an unauthenticated key."
        ) from e

print("RSA-PSS Signature verification loaded.")"""
    cells.append(create_code_cell(code10))

    # =========================================================================
    # Section 11: AES Key Recovery (RSA-OAEP)
    # =========================================================================
    sec11 = """### 11. RSA-OAEP Session-Key Recovery

Once the signature is verified, the receiver recovers the 32-byte AES symmetric session key using their RSA private key:
- **Padding Scheme:** RSA-OAEP (Optimal Asymmetric Encryption Padding)
- **Hash & MGF:** SHA-256
- **Label:** `None` (empty label)
- **Check:** Rejects recovered keys unless length is exactly 32 bytes (256 bits)."""
    cells.append(create_markdown_cell(sec11))

    code11 = """def recover_aes_session_key(encrypted_key_b64: str, receiver_private_key: rsa.RSAPrivateKey) -> bytes:
    \"\"\"Recovers the 32-byte AES session key using RSA-OAEP-SHA256.\"\"\"
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
        raise SecurityVerificationError(f"Failed to recover AES session key via RSA-OAEP: {e}") from e

    if len(session_key) != AES_KEY_BYTES:
        raise SecurityVerificationError(f"Recovered session key is {len(session_key)} bytes; expected 32 bytes.")
    return session_key

print("RSA-OAEP Session key recovery loaded.")"""
    cells.append(create_code_cell(code11))

    # =========================================================================
    # Section 12: AES-GCM Decryption and Plaintext Validation
    # =========================================================================
    sec12 = """### 12. AES-256-GCM Decryption & Authenticated Plaintext Validation

- **Cipher:** AES-256 in Galois/Counter Mode (GCM)
- **Associated Data (AAD):** Canonical UTF-8 JSON bytes of the entire `metadata` object.
- **Fail-Closed:** If the GCM authentication tag does not match, `InvalidTag` is raised and NO partial plaintext is ever released or saved.
- **Post-Decryption Integrity Check:** The decrypted plaintext byte length and SHA-256 digest are compared against `metadata.file_size` and `metadata.plaintext_sha256`."""
    cells.append(create_markdown_cell(sec12))

    code12 = """def decrypt_and_authenticate_file(
    session_key: bytes,
    nonce_b64: str,
    ciphertext_b64: str,
    tag_b64: str,
    metadata: Dict[str, Any],
) -> bytes:
    \"\"\"Decrypts AES-256-GCM ciphertext and validates size and SHA-256 digest.\"\"\"
    nonce = strict_b64decode(nonce_b64, "nonce")
    ciphertext = strict_b64decode(ciphertext_b64, "ciphertext")
    tag = strict_b64decode(tag_b64, "tag")

    # Associated Data is the canonical JSON bytes of the metadata object
    associated_data = canonical_json_bytes(metadata)
    combined = ciphertext + tag

    aesgcm = AESGCM(session_key)
    try:
        plaintext = aesgcm.decrypt(nonce, combined, associated_data)
    except InvalidTag as e:
        raise SecurityVerificationError("AES-GCM authentication failed (InvalidTag). Ciphertext or metadata altered.") from e

    # Stage 6: Plaintext verification against signed metadata
    if len(plaintext) != metadata["file_size"]:
        raise SecurityVerificationError(
            f"Plaintext size mismatch: recovered {len(plaintext)} bytes, expected {metadata['file_size']} bytes."
        )

    calc_hash = hashlib.sha256(plaintext).hexdigest().lower()
    if calc_hash != metadata["plaintext_sha256"].lower():
        raise SecurityVerificationError(
            f"Plaintext SHA-256 mismatch: calculated {calc_hash}, expected {metadata['plaintext_sha256']}."
        )

    return plaintext

print("AES-GCM Decryption and plaintext validation loaded.")"""
    cells.append(create_code_cell(code12))

    # =========================================================================
    # Section 13: Secure Output-File Creation
    # =========================================================================
    sec13 = """### 13. Secure Output-File Creation (Atomicity & Path Traversal Immunity)

- **Path Traversal Defense:** Only `Path(filename).name` is used. Parent directory components (`../`, `/etc/`) are rejected or stripped.
- **Overwrite Protection:** If the file already exists, it is rejected unless explicit confirmation is provided.
- **Atomic Writing:** Plaintext is written to a temporary file in the destination folder and renamed atomically, preventing partial/corrupted files if interrupted."""
    cells.append(create_markdown_cell(sec13))

    code13 = """def save_plaintext_safely(plaintext: bytes, raw_filename: str, output_dir: Union[str, Path], overwrite: bool = False) -> Path:
    out_dir = Path(output_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    safe_name = Path(raw_filename).name
    if not safe_name or safe_name in {".", ".."}:
        raise FileSafetyError(f"Invalid or unsafe output filename: '{raw_filename}'")

    target_path = (out_dir / safe_name).resolve()
    try:
        target_path.relative_to(out_dir)
    except ValueError as e:
        raise FileSafetyError("Path traversal attack detected!") from e

    if target_path.exists() and not overwrite:
        raise FileSafetyError(f"Output file already exists: '{target_path}'. Overwrite confirmation required.")

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
            tmp_path.unlink()

print("Secure file persistence loaded.")"""
    cells.append(create_code_cell(code13))

    # =========================================================================
    # Section 14: Receive-Package Demonstration
    # =========================================================================
    sec14 = """### 14. Live Demonstration: Receiving and Decrypting an Examination Paper

We assemble the 7-stage pipeline into `decrypt_and_verify_package()` and execute a live demonstration on `secure_exam_exchange/incoming/exam_package.json`."""
    cells.append(create_markdown_cell(sec14))

    code14_func = """def decrypt_and_verify_package(
    package_path: Union[str, Path],
    receiver_private_key: rsa.RSAPrivateKey,
    sender_public_key: rsa.RSAPublicKey,
    output_dir: Union[str, Path],
    expected_recipient_id: Optional[str] = None,
    overwrite: bool = False,
    max_package_size: int = 50 * 1024 * 1024,
) -> Dict[str, Any]:
    pkg_file = Path(package_path).resolve()
    if not pkg_file.is_file():
        raise FileSafetyError(f"Package file not found: '{pkg_file}'")

    if pkg_file.stat().st_size > max_package_size:
        raise ProtocolValidationError("Package exceeds maximum permitted size.")

    # Stage 1: Read & Parse Strict JSON
    package = parse_strict_json(pkg_file.read_bytes())
    validate_package_structure(package, receiver_modulus_bytes=(receiver_private_key.key_size + 7) // 8)
    metadata = package["metadata"]

    # Stage 2: Verify Sender Digital Signature (BEFORE RSA Decryption)
    verify_package_signature(package, sender_public_key)

    # Stage 3: Validate Expected Recipient ID
    if expected_recipient_id is not None and metadata["recipient_id"] != expected_recipient_id:
        raise SecurityVerificationError(
            f"Recipient ID mismatch: package meant for '{metadata['recipient_id']}', but expected '{expected_recipient_id}'."
        )

    # Stage 4: Recover AES Session Key
    session_key = recover_aes_session_key(package["encrypted_key"], receiver_private_key)

    try:
        # Stage 5 & 6: AES-GCM Decryption & Plaintext Verification
        plaintext = decrypt_and_authenticate_file(
            session_key=session_key,
            nonce_b64=package["nonce"],
            ciphertext_b64=package["ciphertext"],
            tag_b64=package["tag"],
            metadata=metadata,
        )

        # Stage 7: Safe Atomic Persistence
        saved_path = save_plaintext_safely(
            plaintext=plaintext,
            raw_filename=metadata["filename"],
            output_dir=output_dir,
            overwrite=overwrite,
        )
    finally:
        del session_key

    return {
        "status": "SUCCESS",
        "verified": True,
        "sender_id": metadata["sender_id"],
        "recipient_id": metadata["recipient_id"],
        "created_at": metadata["created_at"],
        "original_filename": metadata["filename"],
        "output_path": str(saved_path),
        "file_size": len(plaintext),
        "sha256": metadata["plaintext_sha256"],
        "sender_fingerprint": get_public_key_fingerprint(sender_public_key),
        "receiver_fingerprint": get_public_key_fingerprint(receiver_private_key.public_key()),
    }

print("decrypt_and_verify_package pipeline fully loaded.")"""
    cells.append(create_code_cell(code14_func))

    code14_run = """# Demonstration Execution: Decrypt & Verify Incoming Examination Package
# Automatically detects the latest JSON package transferred into the incoming/ directory
incoming_pkgs = sorted(INCOMING_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
priv_key_path = KEYS_DIR / "receiver_private.pem"
trusted_sender_pub_path = SENDER_KEYS_DIR / "sender_public.pem"

if incoming_pkgs and priv_key_path.exists() and trusted_sender_pub_path.exists():
    pkg_path = incoming_pkgs[0]
    print(f"Reading incoming examination package: {pkg_path.name}")
    
    # Prompt for receiver private key passphrase
    # (Demo passphrase used in setup: 'WorkshopPassphrase2026!')
    demo_pass = os.environ.get("EXAM_PASS", "WorkshopPassphrase2026!")
    recv_priv = load_receiver_private_key(priv_key_path, passphrase=demo_pass)
    sender_pub = load_public_key(trusted_sender_pub_path)
    
    result = decrypt_and_verify_package(
        package_path=pkg_path,
        receiver_private_key=recv_priv,
        sender_public_key=sender_pub,
        output_dir=RECEIVED_DIR,
        expected_recipient_id=None,  # Accepts intended recipient from authenticated metadata
        overwrite=True,
    )
    
    print()
    print("=" * 65)
    print("PACKAGE VERIFICATION & DECRYPTION REPORT")
    print("=" * 65)
    print(f"Status:             {result['status']}")
    print(f"Sender ID:          {result['sender_id']}")
    print(f"Recipient ID:       {result['recipient_id']}")
    print(f"Created At:         {result['created_at']}")
    print(f"Filename:           {result['original_filename']}")
    print(f"Saved To:           {result['output_path']}")
    print(f"Plaintext Size:     {result['file_size']} bytes")
    print(f"Plaintext SHA-256:  {result['sha256']}")
    print(f"Sender Fingerprint: {result['sender_fingerprint']}")
    print("=" * 65)
    
    # Display preview of the recovered examination paper
    recovered_text = Path(result["output_path"]).read_text(encoding="utf-8", errors="replace")
    print()
    print("RECOVERED EXAMINATION PAPER PREVIEW (First 15 lines):")
    print("-" * 65)
    for line in recovered_text.splitlines()[:15]:
        print(line)
    print("-" * 65)
else:
    print("Demo files not yet found. Please run the setup script or place incoming files.")"""
    cells.append(create_code_cell(code14_run))

    # =========================================================================
    # Section 15: Automated Security Tests
    # =========================================================================
    sec15 = """### 15. Automated Security Tests (Tests A through I)

We now run the complete automated security test suite covering:
- **Test A:** RSA Key Management (Generation, PKCS#8, Passphrase rejection, Fingerprints, Overwrite guard)
- **Test B:** Successful Recovery (Valid Package end-to-end)
- **Test C:** Wrong Sender Public Key (Signature rejection)
- **Test D:** Wrong Receiver Private Key (RSA-OAEP failure)
- **Test E:** Tampering Resistance (Bit-flipping in ciphertext, tag, nonce, key, signature, metadata, version)
- **Test F:** Malformed Input (Bad JSON, duplicate keys, invalid UTF-8, wrong types, bad Base64)
- **Test G:** Edge Cases (0-byte file and arbitrary binary file with null bytes)
- **Test H:** Output Safety (Path traversal defense and existing file overwrite protection)
- **Test I:** Replay Consideration Analysis

Results are automatically saved to `secure_exam_exchange/test_results/receiver_test_results.txt`."""
    cells.append(create_markdown_cell(sec15))

    code15_tests = """from run_tests_and_report import run_all_security_tests

report_target = TEST_RESULTS_DIR / "receiver_test_results.txt"
print(f"Running automated security test suite and writing audit report to {report_target}...")

test_results = run_all_security_tests(report_target)
passed = sum(1 for r in test_results if r.passed)
total = len(test_results)

print()
print("=" * 70)
print(f"TEST EXECUTION SUMMARY: {passed} / {total} TESTS PASSED ({passed/total*100:.1f}%)")
print("=" * 70)
for idx, r in enumerate(test_results, start=1):
    tag = "PASS" if r.passed else "FAIL"
    print(f"[{tag}] Test {idx:02d}: {r.name}")
    print(f"       Result: {r.actual}")
print("=" * 70)"""
    cells.append(create_code_cell(code15_tests))

    # =========================================================================
    # Section 16: Security Explanation for Workshop Report
    # =========================================================================
    sec16 = """### 16. Security Explanations for the Workshop Report

#### 16.1 Confidentiality
The confidentiality of the examination paper is protected by **AES-256-GCM**, a state-of-the-art symmetric cipher with 256-bit security. Because symmetric keys cannot be safely pre-shared across an open network, **RSA-OAEP-SHA256** encapsulates the 32-byte AES key using the receiver's public key. Only the entity possessing the receiver's matching 3072-bit private key can mathematically invert the trapdoor one-way permutation to recover the AES key.

#### 16.2 Integrity & Authenticity
AES-GCM computes a 16-byte polynomial authentication tag over the ciphertext and Associated Authenticated Data (AAD). If an adversary modifies even a single bit of the ciphertext or changes the metadata (such as renaming the file or changing the file size), the GCM authentication check fails immediately with `InvalidTag`, and no plaintext is ever released.

#### 16.3 Sender Authentication & Non-Repudiation
The **RSA-PSS** digital signature over the canonical JSON package guarantees that the package originated specifically from the authorized faculty member holding the sender private key. Because PSS incorporates randomized salt padding, every signature is distinct and immune to chosen-message forgeability.

#### 16.4 Key Separation
We maintain strict separation between key purposes:
| Key | Owner | Algorithm | Function |
| :--- | :--- | :--- | :--- |
| **Sender Private Key** | Faculty | RSA-PSS (Sign) | Digitally signs the examination package |
| **Sender Public Key** | Trusted Store | RSA-PSS (Verify) | Authenticates faculty signature at receiver |
| **Receiver Public Key** | Coordinator | RSA-OAEP (Encrypt) | Encapsulates AES-256 session key |
| **Receiver Private Key** | Coordinator | RSA-OAEP (Decrypt) | Decapsulates AES-256 session key |

#### 16.5 Why Hybrid Encryption?
Asymmetric encryption (RSA) involves modular exponentiation of multi-thousand-bit numbers, which is computationally expensive ($O(k^3)$) and restricted to messages smaller than the RSA modulus minus padding overhead. Symmetric encryption (AES-GCM) processes bulk data at gigabytes per second with hardware acceleration (AES-NI). Hybrid encryption gives the best of both worlds: the key distribution advantages of asymmetric cryptography combined with the speed and message capacity of symmetric ciphers.

#### 16.6 Replay Limitations & Production Mitigations
A valid digital signature verifies that the sender authorized the package at some point in time. It does NOT automatically prove that the package has not been resent. In our workshop implementation, replaying an old package is blocked from silent overwriting by filesystem checks, but a true production system requires:
1. **Monotonically Increasing Sequence IDs** or UUID message nonces maintained in a database.
2. **Short UTC Expiry Windows** checked against authenticated NTP time servers.
3. **Nonce Cache** that records and rejects duplicate message hashes."""
    cells.append(create_markdown_cell(sec16))

    # =========================================================================
    # Section 17: Troubleshooting and Workshop Submission Instructions
    # =========================================================================
    sec17 = """### 17. Troubleshooting & Workshop Demonstration Instructions

#### How to Demonstrate in the Workshop:
1. **Select Python Environment:** In VS Code, click the Python environment selector in the top-right corner of the notebook and choose the project `.venv` (`Python 3.11`).
2. **Public Key Exchange:**
   - Run Section 5 & 6 to export `secure_exam_exchange/keys/receiver_public.pem`.
   - Provide this public key to the sender student.
   - Verify fingerprints verbally: Compare the 32-byte colon-separated SHA-256 fingerprint displayed in Section 8.
3. **Receiving Package:**
   - Place the sender's encrypted package into `secure_exam_exchange/incoming/exam_package.json`.
   - Ensure the sender's public key is placed in `secure_exam_exchange/sender_public_keys/sender_public.pem`.
   - Execute Section 14 to decrypt, authenticate, and safely save the recovered examination paper into `secure_exam_exchange/received/`.
4. **Audit & Testing:**
   - Execute Section 15 to demonstrate all 20 automated security tests passing live.

#### Common Troubleshooting Issues:
- **`SecurityVerificationError: Sender digital signature verification failed`:**
  - Verify that the sender public key in `sender_public_keys/sender_public.pem` matches the sender's actual private key.
  - Verify that the sender serialized the package using exact canonical JSON (compact separators `(',', ':')`, sorted keys, UTF-8).
- **`SecurityVerificationError: Failed to recover AES session key`:**
  - Verify that the sender encrypted the session key using the receiver's public key, NOT their own public key.
- **`FileSafetyError: Output file already exists`:**
  - The receiver refuses to silently overwrite existing files. To overwrite, set `overwrite=True` in `decrypt_and_verify_package()`.
- **`KeyManagementError: Incorrect passphrase`:**
  - Enter the exact passphrase used when generating `receiver_private.pem`."""
    cells.append(create_markdown_cell(sec17))

    nb = {
        "cells": cells,
        "metadata": {
            "kernelspec": {
                "display_name": "Python 3 (ipykernel)",
                "language": "python",
                "name": "python3",
            },
            "language_info": {
                "codemirror_mode": {"name": "ipython", "version": 3},
                "file_extension": ".py",
                "mimetype": "text/x-python",
                "name": "python",
                "nbconvert_exporter": "python",
                "pygments_lexer": "ipython3",
                "version": "3.11.9",
            },
        },
        "nbformat": 4,
        "nbformat_minor": 2,
    }

    nb_path = Path("receiver_secure_exam_exchange.ipynb")
    nb_path.write_text(json.dumps(nb, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Jupyter Notebook successfully written to {nb_path.resolve()}")


if __name__ == "__main__":
    build_notebook()
