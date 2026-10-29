"""
Generate sender_secure_exam_exchange.ipynb according to all workshop specifications.
"""
import json
import uuid
from pathlib import Path

def generate_notebook():
    cells = []

    def add_cell(cell_type: str, source: str):
        cell_id = f"cell_{len(cells)+1:02d}_{uuid.uuid4().hex[:8]}"
        c = {
            "cell_type": cell_type,
            "id": cell_id,
            "metadata": {},
            "source": [line + "\n" for line in source.strip().split("\n")]
        }
        if cell_type == "code":
            c["execution_count"] = None
            c["outputs"] = []
        cells.append(c)

    # -------------------------------------------------------------------------
    # 1. Project overview and security objectives (Markdown)
    # -------------------------------------------------------------------------
    add_cell("markdown", """# Secure Examination-Paper Exchange Using Python
## Sender Application Notebook (`sender_secure_exam_exchange.ipynb`)

### 1. Project Overview & Operational Context
This notebook implements the complete **Sender-Side Application** for the **Secure Examination-Paper Exchange** cryptosystem. In academic institutions, final examination papers must be transferred from faculty authors (**Sender**) to examination coordinators or evaluation centers (**Receiver**) across untrusted networks (campus LAN, email, cloud storage, USB drives) without risking leakage, undetectable tampering, or identity spoofing.

This system implements a state-of-the-art **hybrid public-key cryptosystem** combining asymmetric cryptography (**RSA-3072**) and authenticated symmetric cryptography (**AES-256-GCM**).

```
 +---------------------------------------------------------------------------------------+
 |                                  SENDER WORKFLOW                                      |
 |                                                                                       |
 |  [Plaintext Exam Paper]                                                               |
 |           |                                                                           |
 |           v                                                                           |
 |  Compute SHA-256 & Metadata                                                           |
 |           |                                                                           |
 |           +---------------------------------------+                                   |
 |           |                                       |                                   |
 |           v                                       v                                   |
 |  Generate Fresh AES Key (32B) & Nonce (12B)     Canonical Metadata (AAD)              |
 |           |                                       |                                   |
 |           +-------------------> [ AES-256-GCM ] <--+                                   |
 |           |                             |                                             |
 |           v                             v                                             |
 |  [ Encrypt AES Key with ]      [ Ciphertext & Tag (16B) ]                             |
 |  [ Receiver Public Key  ]               |                                             |
 |  [  (RSA-OAEP-SHA256)   ]               |                                             |
 |           |                             |                                             |
 |           +--------------+--------------+                                             |
 |                          |                                                            |
 |                          v                                                            |
 |             Construct Unsigned Package                                                |
 |                          |                                                            |
 |                          v                                                            |
 |                Canonical JSON (UTF-8)                                                 |
 |                          |                                                            |
 |                          v                                                            |
 |           [ Sign with Sender Private Key ]                                            |
 |           [      (RSA-PSS-SHA256)        ]                                            |
 |                          |                                                            |
 |                          v                                                            |
 |              Complete Signed Package JSON                                             |
 |          (Export for USB or POST to Receiver)                                         |
 +---------------------------------------------------------------------------------------+
```

### 2. Core Security Objectives
* **Confidentiality:** Examination papers are encrypted with a fresh, cryptographically random AES-256 session key. The session key is encapsulated exclusively for the intended recipient using the Receiver's RSA-3072 public key and RSA-OAEP padding. Eavesdroppers cannot view examination questions.
* **Integrity & Authenticity:** AES-256-GCM generates a 16-byte authentication tag over the ciphertext and canonical metadata (Associated Authenticated Data). Any manipulation of the encrypted text or metadata (such as timestamps, recipient ID, or file length) causes immediate decryption failure.
* **Non-Repudiation & Sender Identity Binding:** The entire package is digitally signed by the faculty author using their RSA-3072 private key and RSA-PSS with maximum salt length. The receiver uses the sender's authenticated public key to verify that the exam paper was originated by the authorized faculty member.
* **Key Separation Principle:** Sender keys are strictly used for digital signatures (`sign`/`verify`), while Receiver keys are strictly used for key encapsulation (`encrypt`/`decrypt`).
* **Replay Attack Resistance:** Time-stamped metadata (`created_at`), unique file digests, and distinct session nonces ensure that every package is unique.
""")

    # -------------------------------------------------------------------------
    # 2. Install and import dependencies (Markdown + Code)
    # -------------------------------------------------------------------------
    add_cell("markdown", """---
## 2. Install and Import Dependencies

All cryptographic algorithms are provided by the Python `cryptography` library (`cryptography.hazmat`), ensuring robust, constant-time, and side-channel resistant implementations. **Cryptographic algorithms are never implemented manually.** Network operations utilize the `requests` library.

Run the cell below to verify and import all necessary modules.
""")

    add_cell("code", """# Dependency Installation (Run if packages are missing)
# %pip install cryptography requests pytest

import os
import sys
import json
import base64
import hashlib
import shutil
import getpass
import tempfile
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Tuple, Dict, Any, Union, Optional

# Standard cryptography primitives from cryptography.hazmat
import cryptography
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature, InvalidTag

# HTTP network client
import requests

print("=" * 70)
print(f"Python Environment    : {sys.version.split()[0]} on {sys.platform}")
print(f"Cryptography Library  : v{cryptography.__version__}")
print(f"Requests Library      : v{requests.__version__}")
print(f"Host Machine          : {socket.gethostname()}")
print("All required dependencies loaded successfully.")
print("=" * 70)
""")

    # -------------------------------------------------------------------------
    # Exact Sender/Receiver Package Protocol & Canonical JSON Engine
    # -------------------------------------------------------------------------
    add_cell("markdown", """### Exact Protocol Specification (`SecureExamExchange` v1)

To allow your colleague to implement a 100% compatible receiver on another computer without accessing your source code, the protocol is strictly defined below:

#### Package JSON Structure
```json
{
  "protocol": "SecureExamExchange",
  "version": 1,
  "metadata": {
    "sender_id": "faculty_cyber_dept",
    "recipient_id": "exam_controller_central",
    "filename": "sample_exam.txt",
    "file_size": 1024,
    "created_at": "2026-10-29T09:00:00Z",
    "encryption": "AES-256-GCM",
    "key_wrap": "RSA-OAEP-SHA256",
    "signature": "RSA-PSS-SHA256",
    "plaintext_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  },
  "encrypted_key": "<Base64 Encrypted 32-byte AES Key via RSA-OAEP>",
  "nonce": "<Base64 12-byte AES-GCM Nonce>",
  "ciphertext": "<Base64 AES-256-GCM Ciphertext excluding 16-byte tag>",
  "tag": "<Base64 16-byte AES-GCM Authentication Tag>",
  "signature": "<Base64 RSA-PSS Signature of Canonical Unsigned Package>"
}
```

#### Canonical Serialization Rules
1. **UTF-8 Encoding:** All JSON strings and bytes are encoded using UTF-8 without byte-order marks (BOM).
2. **Lexicographical Key Sorting:** All dictionary keys must be sorted lexicographically (`sort_keys=True`).
3. **Compact Separators:** Separators are strictly `(',', ':')` with no trailing spaces or indentation.
4. **NaN/Infinity Prohibition:** `allow_nan=False` is enforced.
5. **Duplicate Key Rejection:** Any incoming JSON containing duplicate keys must be rejected to prevent parser discrepancy attacks.
6. **Digital Signature Scope:** The digital signature is computed over the canonical UTF-8 bytes of the entire package **excluding** the top-level `"signature"` field.
7. **AES-GCM Associated Data:** The canonical UTF-8 bytes of the complete `metadata` object serve as Associated Authenticated Data (AAD).
""")

    add_cell("code", """# Protocol Constants & Canonical JSON Engine
PROTOCOL_NAME = "SecureExamExchange"
PROTOCOL_VERSION = 1
DEFAULT_MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB safety ceiling

def canonical_json_dumps(obj: Any) -> bytes:
    \"\"\"Serializes any Python dictionary or object into deterministic canonical UTF-8 JSON bytes:
    - Keys sorted lexicographically
    - Compact separators (',', ':') without whitespace
    - allow_nan=False
    - Strict UTF-8 encoding
    \"\"\"
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(',', ':'),
        allow_nan=False,
        ensure_ascii=False
    ).encode('utf-8')

def _reject_duplicate_keys(pairs):
    \"\"\"Parser hook that raises ValueError if duplicate keys exist in a JSON object.\"\"\"
    res = {}
    for k, v in pairs:
        if k in res:
            raise ValueError(f"Security Error: Duplicate key detected in JSON payload: '{k}'")
        res[k] = v
    return res

def parse_secure_json(data: Union[str, bytes]) -> dict:
    \"\"\"Parses JSON string or bytes enforcing UTF-8 and strict duplicate key rejection.\"\"\"
    if isinstance(data, bytes):
        data = data.decode('utf-8')
    return json.loads(data, object_pairs_hook=_reject_duplicate_keys)

# Self-validation of canonical serialization
_test_dict = {"version": 1, "protocol": "SecureExamExchange", "z": 99, "a": "first"}
_canonical = canonical_json_dumps(_test_dict)
print("Canonical JSON Serialization Output:")
print(_canonical.decode('utf-8'))
assert _canonical == b'{"a":"first","protocol":"SecureExamExchange","version":1,"z":99}'
print("Canonical JSON serialization validated successfully.")
""")

    # -------------------------------------------------------------------------
    # 3. Create project directories and synthetic sample paper (Markdown + Code)
    # -------------------------------------------------------------------------
    add_cell("markdown", """---
## 3. Create Project Directories and Synthetic Sample Paper

The application establishes a clear folder structure relative to the notebook's working directory:
* `secure_exam_exchange/keys/`: Stores sender private key (encrypted) and imported receiver public key.
* `secure_exam_exchange/input_papers/`: Directory containing examination papers to encrypt.
* `secure_exam_exchange/outgoing/`: Storage for encrypted, signed package JSON files ready for distribution.
* `secure_exam_exchange/received_public_keys/`: Ingestion folder for incoming colleague public keys.
* `secure_exam_exchange/test_results/`: Audit logs and automated test reports.

A synthetic sample paper (`sample_exam.txt`) containing fictional examination questions is created **only if it does not already exist**, preserving existing files.
""")

    add_cell("code", """# Define runtime directories
BASE_DIR = Path("secure_exam_exchange")
DIR_KEYS = BASE_DIR / "keys"
DIR_INPUT = BASE_DIR / "input_papers"
DIR_OUTGOING = BASE_DIR / "outgoing"
DIR_RECEIVED_KEYS = BASE_DIR / "received_public_keys"
DIR_TEST_RESULTS = BASE_DIR / "test_results"

for folder in [DIR_KEYS, DIR_INPUT, DIR_OUTGOING, DIR_RECEIVED_KEYS, DIR_TEST_RESULTS]:
    folder.mkdir(parents=True, exist_ok=True)

# Create synthetic sample exam paper only if not present
sample_exam_path = DIR_INPUT / "sample_exam.txt"

if not sample_exam_path.exists():
    synthetic_exam_questions = \"\"\"================================================================================
NATIONAL INSTITUTE OF TECHNOLOGY — AUTUMN SEMESTER EXAMINATION
Course Code : CYBER-701: Modern Applied Cryptography & Zero-Knowledge Systems
Duration    : 3 Hours                      Maximum Marks: 100
Instructions: Strictly Confidential. Unauthorized access or reproduction is prohibited.
================================================================================

SECTION A: ASYMMETRIC CRYPTOSYSTEMS & PADDING SCHEMES (40 Marks)
1. (a) In RSA-OAEP, describe the specific role of the Optimal Asymmetric Encryption Padding
       generator and explain why plain RSA encryption is vulnerable to malleability attacks. [10]
   (b) Contrast RSA-PSS with PKCS#1 v1.5 digital signature schemes. How does randomized salt
       in PSS achieve tight security reduction in the Random Oracle Model?                 [10]

SECTION B: AUTHENTICATED SYMMETRIC CIPHERS & KEY WRAPPING (30 Marks)
2. (a) Explain how AES-256-GCM combines counter-mode encryption with GMAC authentication.
       Why does reusing an AES-GCM nonce under the same key completely destroy authenticity? [15]
   (b) Describe the Key Encapsulation Mechanism (KEM) used to wrap symmetric session keys.  [15]

SECTION C: PROTOCOL ARCHITECTURE & ATTACK SCENARIOS (30 Marks)
3. A sender signs an examination paper before encrypting it ("sign-then-encrypt").
   (a) Detail how a malicious recipient could re-encrypt the signed plaintext and claim
       authorship to a third party (Surreptitious Forwarding).                              [15]
   (b) How does binding recipient metadata as Associated Authenticated Data (AAD) in
       AES-GCM neutralize this vulnerability?                                              [15]

================================================================================
END OF CONFIDENTIAL EXAMINATION PAPER
================================================================================
\"\"\"
    with open(sample_exam_path, "w", encoding="utf-8") as f:
        f.write(synthetic_exam_questions)
    print(f"[CREATED] Synthetic exam paper generated at: {sample_exam_path}")
else:
    print(f"[PRESERVED] Existing exam paper found at: {sample_exam_path}")

print("Directory structure initialized:")
for folder in [DIR_KEYS, DIR_INPUT, DIR_OUTGOING, DIR_RECEIVED_KEYS, DIR_TEST_RESULTS]:
    print(f"  - {folder.as_posix()}/")
""")

    # -------------------------------------------------------------------------
    # 4. Generate or load sender keys (Markdown + Code)
    # -------------------------------------------------------------------------
    add_cell("markdown", """---
## 4. Generate or Load Sender Keys

This section handles the Sender's RSA key pair:
* **RSA-3072 Generation:** Generates a 3072-bit RSA key pair with public exponent $e = 65537$.
* **PKCS#8 Encrypted Storage:** The private key is serialized as encrypted PKCS#8 PEM (`BestAvailableEncryption`) protected by a user passphrase.
* **Passphrase Security:** Passphrases are prompted securely using `getpass.getpass()`. Passphrases are **never** stored in code, logs, or outputs.
* **Overwrite Protection:** Existing key files are **never** silently overwritten; explicit confirmation is required.
* **Key Separation:** The Sender Private Key is used **only** for creating RSA-PSS digital signatures.
""")

    add_cell("code", """def generate_sender_key_pair(key_size: int = 3072) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    \"\"\"Generates an RSA private/public key pair (minimum 3072 bits).\"\"\"
    if key_size < 3072:
        raise ValueError(f"Security Policy: Key size must be >= 3072 bits (requested {key_size} bits).")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    return private_key, private_key.public_key()

def save_sender_private_key(
    private_key: rsa.RSAPrivateKey,
    filepath: Union[str, Path],
    passphrase: str,
    force: bool = False
) -> Path:
    \"\"\"Encrypts and saves the sender private key using PKCS#8 PEM format.\"\"\"
    path = Path(filepath)
    if path.exists() and not force:
        raise FileExistsError(f"Private key file already exists at {path}. Set force=True to confirm overwrite.")
    if not passphrase or len(passphrase.strip()) == 0:
        raise ValueError("Passphrase cannot be empty.")
    
    pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode('utf-8'))
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        f.write(pem_bytes)
    
    try:
        os.chmod(path, 0o600)  # Restrict permissions where supported
    except Exception:
        pass
    return path

def load_sender_private_key(filepath: Union[str, Path], passphrase: str) -> rsa.RSAPrivateKey:
    \"\"\"Loads and decrypts the sender private key from encrypted PKCS#8 PEM.\"\"\"
    path = Path(filepath)
    if not path.is_file():
        raise FileNotFoundError(f"Sender private key file not found: {path}")
    if not passphrase:
        raise ValueError("Passphrase cannot be empty.")
    with open(path, "rb") as f:
        pem_bytes = f.read()
    return serialization.load_pem_private_key(pem_bytes, password=passphrase.encode('utf-8'))

def save_public_key(public_key: rsa.RSAPublicKey, filepath: Union[str, Path], force: bool = False) -> Path:
    \"\"\"Saves an RSA public key in SubjectPublicKeyInfo PEM format.\"\"\"
    path = Path(filepath)
    if path.exists() and not force:
        raise FileExistsError(f"Public key file already exists at {path}. Set force=True to confirm overwrite.")
    pem_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        f.write(pem_bytes)
    try:
        os.chmod(path, 0o644)
    except Exception:
        pass
    return path

def load_and_validate_public_key(filepath: Union[str, Path], min_key_size: int = 3072) -> rsa.RSAPublicKey:
    \"\"\"Loads a public key from PEM and validates that it is an RSA key of at least min_key_size bits.\"\"\"
    path = Path(filepath)
    if not path.is_file():
        raise FileNotFoundError(f"Public key file not found: {path}")
    with open(path, "rb") as f:
        pem_bytes = f.read()
    pub_key = serialization.load_pem_public_key(pem_bytes)
    if not isinstance(pub_key, rsa.RSAPublicKey):
        raise TypeError(f"Invalid key type: Expected RSA public key, got {type(pub_key).__name__}")
    if pub_key.key_size < min_key_size:
        raise ValueError(f"Insecure Key Length: RSA key is {pub_key.key_size} bits; policy requires >= {min_key_size} bits.")
    return pub_key

def get_public_key_fingerprint(public_key: rsa.RSAPublicKey) -> str:
    \"\"\"Computes SHA-256 fingerprint over SubjectPublicKeyInfo DER encoding,
    formatted as uppercase hexadecimal with colon separators.
    \"\"\"
    der_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    digest = hashlib.sha256(der_bytes).hexdigest().upper()
    return ":".join(digest[i:i+2] for i in range(0, len(digest), 2))

print("Key management functions compiled.")
""")

    # Interactive key generation / loading execution cell
    add_cell("code", """# Sender Key Initialization Workflow
sender_priv_path = DIR_KEYS / "sender_private.pem"
sender_pub_path = DIR_KEYS / "sender_public.pem"

sender_public_key = None

if sender_priv_path.exists() and sender_pub_path.exists():
    print("Found existing Sender RSA key pair in 'keys/' directory. Reusing existing keys.")
    sender_public_key = load_and_validate_public_key(sender_pub_path, min_key_size=3072)
    print(f"Loaded Sender Public Key ({sender_public_key.key_size} bits).")
    print(f"Sender Public Key Fingerprint (SHA-256):\\n{get_public_key_fingerprint(sender_public_key)}")
    print("\\n[Security Notice: Private key remains encrypted on disk until needed for signing.]")
else:
    print("No existing sender keys found. Generating fresh RSA-3072 key pair...")
    passphrase_1 = getpass.getpass("Enter passphrase to encrypt Sender Private Key: ")
    passphrase_2 = getpass.getpass("Confirm passphrase: ")
    if passphrase_1 != passphrase_2:
        raise ValueError("Passphrases do not match. Aborting key generation.")
    if len(passphrase_1) < 8:
        raise ValueError("Passphrase must be at least 8 characters long for security.")
    
    priv_key, pub_key = generate_sender_key_pair(key_size=3072)
    save_sender_private_key(priv_key, sender_priv_path, passphrase_1, force=False)
    save_public_key(pub_key, sender_pub_path, force=False)
    sender_public_key = pub_key
    
    print("\\nSender RSA-3072 Key Pair successfully generated and stored!")
    print(f"Encrypted Private Key : {sender_priv_path.resolve()}")
    print(f"Public Key            : {sender_pub_path.resolve()}")
    print(f"Sender Public Key Fingerprint (SHA-256):\\n{get_public_key_fingerprint(sender_public_key)}")
""")

    # -------------------------------------------------------------------------
    # 5. Export sender public key (Markdown + Code)
    # -------------------------------------------------------------------------
    add_cell("markdown", """---
## 5. Export Sender Public Key

To enable your colleague (the Receiver) to verify the digital signatures on incoming packages, you must share your Sender Public Key with them.

Run this cell to display your public key as formatted text that you can **directly copy and send**, as well as export it as a file.
""")

    add_cell("code", """# Export and Output Sender Public Key
export_dir = BASE_DIR / "exported_keys"
export_dir.mkdir(parents=True, exist_ok=True)
exported_sender_pub = export_dir / "sender_public.pem"

shutil.copyfile(sender_pub_path, exported_sender_pub)

sender_pem_str = sender_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode('utf-8').strip()

print("=" * 80)
print("      YOUR SENDER PUBLIC KEY (COPY THIS ENTIRE BLOCK AND SEND TO RECEIVER)")
print("=" * 80)
print(sender_pem_str)
print("=" * 80)
print(f"SHA-256 Fingerprint:\\n{get_public_key_fingerprint(sender_public_key)}")
print("=" * 80)
print(f"Exported File Path  : {exported_sender_pub.resolve()}")
print("ACTION: Copy the PEM block above and send it to your colleague (or send the file).")
""")

    # -------------------------------------------------------------------------
    # 6. Import receiver public key (Markdown + Code)
    # -------------------------------------------------------------------------
    add_cell("markdown", """---
## 6. Input / Import Receiver Public Key

Before encrypting an examination paper, you must provide your colleague's **Receiver Public Key**.
You can:
* **Option 1:** Paste your colleague's PEM key text directly into the `RECEIVER_PUBLIC_KEY_PEM` variable below.
* **Option 2:** Drop their `receiver_public.pem` file directly into the `crypto_workshop1` workspace folder.
* **Option 3:** Place it in `secure_exam_exchange/received_public_keys/receiver_public.pem`.
""")

    add_cell("code", """# OPTION 1: Paste Receiver Public Key PEM text directly here (or leave empty to use file):
RECEIVER_PUBLIC_KEY_PEM = \"\"\"\"\"\"

recipient_public_key = None

if "BEGIN PUBLIC KEY" in RECEIVER_PUBLIC_KEY_PEM:
    print("Parsing pasted Receiver Public Key text...")
    pub_candidate = serialization.load_pem_public_key(RECEIVER_PUBLIC_KEY_PEM.strip().encode('utf-8'))
    if not isinstance(pub_candidate, rsa.RSAPublicKey) or pub_candidate.key_size < 3072:
        raise ValueError("Pasted key must be an RSA public key of at least 3072 bits.")
    save_public_key(pub_candidate, DIR_KEYS / "receiver_public.pem", force=True)
    recipient_public_key = pub_candidate
    print(f"Successfully validated pasted RSA-{recipient_public_key.key_size} public key and saved to keys store.")
else:
    # OPTION 2: Auto-detect from crypto_workshop1 root or received_public_keys folder
    candidate_locations = [
        Path("receiver_public.pem"),
        DIR_RECEIVED_KEYS / "receiver_public.pem",
        DIR_KEYS / "receiver_public.pem"
    ]
    found_key_file = next((p for p in candidate_locations if p.is_file()), None)
    
    if found_key_file:
        print(f"Loading Receiver Public Key from file: {found_key_file.resolve()}")
        recipient_public_key = load_and_validate_public_key(found_key_file, min_key_size=3072)
        save_public_key(recipient_public_key, DIR_KEYS / "receiver_public.pem", force=True)
        print(f"Successfully loaded and validated RSA-{recipient_public_key.key_size} Receiver Public Key.")
    else:
        print("=" * 70)
        print("[ACTION REQUIRED: PROVIDE RECEIVER PUBLIC KEY]")
        print("1. Paste the receiver's PEM string into RECEIVER_PUBLIC_KEY_PEM above, OR")
        print("2. Drop 'receiver_public.pem' in the crypto_workshop1 folder and re-run.")
        print("=" * 70)

if recipient_public_key is not None:
    print(f"Receiver Public Key Fingerprint (SHA-256):\\n{get_public_key_fingerprint(recipient_public_key)}")
""")

    # -------------------------------------------------------------------------
    # 7. Display and compare public-key fingerprints (Markdown + Code)
    # -------------------------------------------------------------------------
    add_cell("markdown", """---
## 7. Display and Compare Public-Key Fingerprints

### Mitigating Man-in-the-Middle (MitM) Attacks
Electronic file transfer channels (unauthenticated LAN folders, email, instant messages) are susceptible to interception. An adversary could replace your colleague's public key with an impostor key, enabling the adversary to decrypt your confidential examination papers!

By comparing the **SHA-256 fingerprints** (formatted in uppercase hexadecimal with colon separators) over an **authenticated out-of-band channel** (e.g., in-person verification, a voice telephone call, or trusted institutional directory), both parties verify that the keys are authentic.
""")

    add_cell("code", """print("=" * 75)
print("                     PUBLIC KEY FINGERPRINT COMPARISON")
print("=" * 75)
print("1. MY SENDER PUBLIC KEY FINGERPRINT:")
print(f"   {get_public_key_fingerprint(sender_public_key)}")
print("   -> Read this fingerprint to your colleague over a trusted voice/in-person channel.")
print("-" * 75)

if recipient_public_key is not None:
    print("2. COLLEAGUE'S RECEIVER PUBLIC KEY FINGERPRINT:")
    print(f"   {get_public_key_fingerprint(recipient_public_key)}")
    print("   -> Verify that this matches the fingerprint displayed on your colleague's laptop.")
    print("=" * 75)
    print("[STATUS] Receiver Public Key is verified and ready for encryption.")
else:
    print("2. COLLEAGUE'S RECEIVER PUBLIC KEY: [NOT YET LOADED]")
    print("=" * 75)
    print("[STATUS] Waiting for receiver public key before paper encryption.")
""")

    # -------------------------------------------------------------------------
    # 8. Encrypt and digitally sign an examination paper (Markdown + Code)
    # -------------------------------------------------------------------------
    add_cell("markdown", """---
## 8. Encrypt and Digitally Sign an Examination Paper

This section defines `encrypt_and_sign_file(...)` and executes the encryption workflow.

### Cryptographic Sequence:
1. **Plaintext Reading & Digest:** Read the file in binary mode without alteration; compute its byte size and SHA-256 digest.
2. **Fresh Session Key & Nonce:** Generate a cryptographically random 32-byte AES key (`os.urandom(32)`) and 12-byte nonce (`os.urandom(12)`). **Never reuse nonces or keys.**
3. **Metadata Construction:** Create the metadata dictionary binding `sender_id`, `recipient_id`, filename, size, timestamp, and algorithm identifiers.
4. **Associated Authenticated Data (AAD):** Canonicalize the complete metadata dictionary into UTF-8 JSON bytes.
5. **AES-256-GCM Symmetric Encryption:** Encrypt the plaintext using the session key, nonce, and metadata AAD. Separate the 16-byte authentication tag from the ciphertext.
6. **RSA-OAEP Session Key Wrapping:** Encrypt the 32-byte AES key using the Receiver's RSA-3072 public key, OAEP padding, SHA-256 hash, and MGF1-SHA-256.
7. **Canonical Unsigned Package:** Assemble the package and serialize to canonical UTF-8 JSON.
8. **RSA-PSS Digital Signature:** Sign the canonical unsigned package bytes with the Sender's RSA-3072 private key, PSS padding, SHA-256, and maximum salt length (`padding.PSS.MAX_LENGTH`).
9. **Final Package Persistence:** Insert the Base64 signature into the package and save as canonical JSON in `secure_exam_exchange/outgoing/`.
""")

    add_cell("code", """def encrypt_and_sign_file(
    input_path: Union[str, Path],
    sender_private_key: rsa.RSAPrivateKey,
    recipient_public_key: rsa.RSAPublicKey,
    sender_id: str,
    recipient_id: str,
    output_dir: Union[str, Path],
    max_size_bytes: int = DEFAULT_MAX_FILE_SIZE,
    output_filename: Optional[str] = None
) -> Tuple[Path, dict]:
    \"\"\"Encrypts and digitally signs an examination paper according to the SecureExamExchange protocol.
    
    Returns:
        (saved_package_path, signed_package_dict)
    \"\"\"
    in_path = Path(input_path)
    if not in_path.is_file():
        raise FileNotFoundError(f"Input examination paper not found: {in_path}")
    
    # 1. Enforce size limits
    file_size = in_path.stat().st_size
    if file_size > max_size_bytes:
        raise ValueError(f"File size ({file_size} bytes) exceeds maximum allowable limit ({max_size_bytes} bytes).")
    
    # 2. Key validations
    if not isinstance(recipient_public_key, rsa.RSAPublicKey):
        raise TypeError("Recipient public key must be an instance of rsa.RSAPublicKey")
    if recipient_public_key.key_size < 3072:
        raise ValueError(f"Recipient public key ({recipient_public_key.key_size} bits) is under 3072 bits.")
    
    if not isinstance(sender_private_key, rsa.RSAPrivateKey):
        raise TypeError("Sender private key must be an instance of rsa.RSAPrivateKey")
    if sender_private_key.key_size < 3072:
        raise ValueError(f"Sender private key ({sender_private_key.key_size} bits) is under 3072 bits.")

    # 3. Read file without modification & compute SHA-256
    with open(in_path, "rb") as f:
        plaintext = f.read()
    plaintext_sha256 = hashlib.sha256(plaintext).hexdigest()

    # 4. Generate fresh 32-byte AES key and 12-byte nonce
    aes_session_key = os.urandom(32)
    nonce = os.urandom(12)

    # 5. Build metadata object
    created_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    metadata = {
        "created_at": created_at,
        "encryption": "AES-256-GCM",
        "filename": in_path.name,
        "file_size": len(plaintext),
        "key_wrap": "RSA-OAEP-SHA256",
        "plaintext_sha256": plaintext_sha256,
        "recipient_id": str(recipient_id).strip(),
        "sender_id": str(sender_id).strip(),
        "signature": "RSA-PSS-SHA256"
    }

    # 6. Canonicalize metadata for AES-GCM Associated Authenticated Data (AAD)
    aad_bytes = canonical_json_dumps(metadata)

    # 7. Encrypt paper using AES-256-GCM
    aesgcm = AESGCM(aes_session_key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, aad_bytes)
    # Tag is exactly the last 16 bytes; ciphertext is the preceding bytes
    ciphertext = ciphertext_with_tag[:-16]
    tag = ciphertext_with_tag[-16:]

    # 8. Encrypt AES session key with recipient RSA public key (RSA-OAEP)
    encrypted_key = recipient_public_key.encrypt(
        aes_session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # 9. Base64 encoding
    b64_encrypted_key = base64.b64encode(encrypted_key).decode('ascii')
    b64_nonce = base64.b64encode(nonce).decode('ascii')
    b64_ciphertext = base64.b64encode(ciphertext).decode('ascii')
    b64_tag = base64.b64encode(tag).decode('ascii')

    # 10. Assemble unsigned package
    unsigned_package = {
        "ciphertext": b64_ciphertext,
        "encrypted_key": b64_encrypted_key,
        "metadata": metadata,
        "nonce": b64_nonce,
        "protocol": PROTOCOL_NAME,
        "tag": b64_tag,
        "version": PROTOCOL_VERSION
    }

    # 11. Canonicalize unsigned package & sign with sender private key (RSA-PSS)
    canonical_unsigned_bytes = canonical_json_dumps(unsigned_package)
    signature_bytes = sender_private_key.sign(
        canonical_unsigned_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    b64_signature = base64.b64encode(signature_bytes).decode('ascii')

    # 12. Create final signed package
    signed_package = dict(unsigned_package)
    signed_package["signature"] = b64_signature

    # 13. Write signed package to disk as canonical UTF-8 JSON
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    if not output_filename:
        stem = in_path.stem
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        rand_id = os.urandom(4).hex()
        output_filename = f"{stem}_pkg_{ts}_{rand_id}.json"
    
    out_file = out_dir / output_filename
    with open(out_file, "wb") as f:
        f.write(canonical_json_dumps(signed_package))

    # Also save package directly in crypto_workshop1 root directory for immediate access
    root_pkg_file = Path(f"{stem}_encrypted_package.json")
    with open(root_pkg_file, "wb") as f:
        f.write(canonical_json_dumps(signed_package))

    return out_file, signed_package

print("encrypt_and_sign_file function compiled.")
""")

    # Interactive Execution Cell for Encryption
    add_cell("code", """# Interactive Examination Paper Selection & Encryption
# Configure an explicit file name (if placed in crypto_workshop1 or input_papers),
# or leave as None to automatically detect any exam paper placed in crypto_workshop1 root.
CUSTOM_EXAM_FILENAME = None  # e.g. "my_final_exam.pdf" or "question_paper.txt"

def discover_exam_paper(explicit_name: Optional[str] = None) -> Path:
    \"\"\"Discovers the examination paper to encrypt.
    Searches the root workspace directory (crypto_workshop1) first.
    Falls back to secure_exam_exchange/input_papers/sample_exam.txt if no root file is found.
    \"\"\"
    if explicit_name:
        p_root = Path(explicit_name)
        if p_root.is_file():
            return p_root
        p_sub = DIR_INPUT / explicit_name
        if p_sub.is_file():
            return p_sub
        raise FileNotFoundError(f"Configured CUSTOM_EXAM_FILENAME '{explicit_name}' not found.")

    # Scan crypto_workshop1 workspace root for document files
    ignored_ext = {".py", ".ipynb", ".json", ".pem", ".md", ".git"}
    ignored_names = {"build_notebook.py", "run_sender.py"}
    
    root_candidates = [
        f for f in Path(".").iterdir()
        if f.is_file() and f.suffix.lower() not in ignored_ext and f.name not in ignored_names
    ]
    if root_candidates:
        # If multiple files exist, prioritize ones with relevant keywords
        for c in root_candidates:
            if any(k in c.name.lower() for k in ["exam", "paper", "question", "main"]):
                return c
        return root_candidates[0]

    # Default fallback
    return DIR_INPUT / "sample_exam.txt"

target_paper = discover_exam_paper(CUSTOM_EXAM_FILENAME)
SENDER_ID = "faculty_cyber_dept"
RECIPIENT_ID = "exam_controller_central"

if not target_paper.is_file():
    raise FileNotFoundError(f"Selected paper does not exist: {target_paper}")

if recipient_public_key is None:
    raise RuntimeError(
        "ENCRYPTION BLOCKED: Receiver public key is missing! "
        "Please import your colleague's 'receiver_public.pem' in Section 6 before encrypting."
    )

print("=" * 70)
print("PREPARING TO ENCRYPT AND SIGN EXAMINATION PAPER")
print(f"Target Paper Name : {target_paper.name}")
print(f"Full Source Path  : {target_paper.resolve()} ({target_paper.stat().st_size} bytes)")
print(f"Sender ID         : {SENDER_ID}")
print(f"Recipient ID      : {RECIPIENT_ID}")
print("-" * 70)

# Secure passphrase prompt to unlock sender private key
passphrase = getpass.getpass("Enter passphrase to unlock Sender Private Key: ")
sender_private_key = load_sender_private_key(sender_priv_path, passphrase)
print("Sender private key unlocked in memory.")

# Perform encryption and signing
saved_package_path, package_payload = encrypt_and_sign_file(
    input_path=target_paper,
    sender_private_key=sender_private_key,
    recipient_public_key=recipient_public_key,
    sender_id=SENDER_ID,
    recipient_id=RECIPIENT_ID,
    output_dir=DIR_OUTGOING
)

# Erase private key reference from memory immediately
del sender_private_key

direct_root_pkg = Path(f"{target_paper.stem}_encrypted_package.json")

print("=" * 70)
print("EXAMINATION PAPER ENCRYPTED & SIGNED SUCCESSFULLY!")
print(f"Direct Root Package : {direct_root_pkg.resolve()}")
print(f"Outgoing Archive    : {saved_package_path.resolve()}")
print(f"Package File Size   : {direct_root_pkg.stat().st_size} bytes")
print("=" * 70)
print("You can now copy the encrypted package directly from crypto_workshop1 and send it to your friend!")
""")

    # -------------------------------------------------------------------------
    # 9. Inspect package metadata (Markdown + Code)
    # -------------------------------------------------------------------------
    add_cell("markdown", """---
## 9. Inspect Package Metadata

This cell verifies the cryptographic encapsulation of the saved JSON package.
Notice that the plaintext exam paper is completely concealed — only metadata, Base64 ciphertext, and cryptographic tokens are exposed.
""")

    add_cell("code", """# Inspect Package Content
with open(saved_package_path, "rb") as f:
    pkg = parse_secure_json(f.read())

print("=" * 75)
print("                 SECURE PACKAGE ENVELOPE INSPECTION")
print("=" * 75)
print(f"Protocol Name          : {pkg['protocol']} (Version {pkg['version']})")
print("Metadata Attributes:")
for key, value in pkg['metadata'].items():
    print(f"  * {key:<20}: {value}")
print("-" * 75)
print(f"Encrypted Session Key  : {pkg['encrypted_key'][:36]}... (Length: {len(pkg['encrypted_key'])} chars)")
print(f"AES-GCM Nonce (12 B)   : {pkg['nonce']}")
print(f"Ciphertext (excl tag)  : {pkg['ciphertext'][:36]}... (Length: {len(pkg['ciphertext'])} chars)")
print(f"Auth Tag (16 B)        : {pkg['tag']}")
print(f"RSA-PSS Signature      : {pkg['signature'][:36]}... (Length: {len(pkg['signature'])} chars)")
print("=" * 75)
print("Security Verification: Plaintext exam questions are nowhere in the package.")
""")

    # -------------------------------------------------------------------------
    # 10. Export or share the encrypted package (Markdown + Code)
    # -------------------------------------------------------------------------
    add_cell("markdown", """---
## 10. Export or Share the Encrypted Package

The signed and encrypted JSON package in `secure_exam_exchange/outgoing/` can now be safely transferred across untrusted channels:
1. **USB Drive / Offline Physical Media**
2. **Campus File Share / Network Folder**
3. **Email Attachment or Cloud Storage**

Because the file is protected with AES-256-GCM and signed with RSA-PSS, interception or tampering during transit will be detected immediately by the receiver.
""")

    add_cell("code", """def export_package_to_directory(source_pkg: Path, target_directory: Path) -> Path:
    \"\"\"Exports the encrypted package to a chosen directory (e.g., USB drive).\"\"\"
    target_dir = Path(target_directory)
    target_dir.mkdir(parents=True, exist_ok=True)
    dest = target_dir / source_pkg.name
    shutil.copyfile(source_pkg, dest)
    return dest

# Export package to distribution staging folder
dist_folder = BASE_DIR / "exported_packages"
exported_pkg_file = export_package_to_directory(saved_package_path, dist_folder)

print("=" * 70)
print(f"PACKAGE EXPORTED FOR SHARING")
print(f"Source   : {saved_package_path.resolve()}")
print(f"Exported : {exported_pkg_file.resolve()}")
print("=" * 70)
""")

    # -------------------------------------------------------------------------
    # 11. Optional network transmission (Markdown + Code)
    # -------------------------------------------------------------------------
    add_cell("markdown", """---
## 11. Optional Network Transmission

If your colleague is running an HTTP receiver server on their laptop over the local network (LAN), you can transmit the package directly via an HTTP POST request.

### Crucial Security Warning Regarding Transport Security
> [!WARNING]
> Plain HTTP (`http://`) does **not** provide transport-layer encryption or server authentication! While our hybrid package protects the confidentiality and integrity of the examination paper, plain HTTP allows passive network sniffers to view metadata (timestamps, filenames, sender/recipient IDs) and exposes the sender to traffic analysis.
>
> In production deployments, **HTTPS** with strict certificate validation must always be enforced.

### Distinction Between Transmission Status and Decryption Proof
> [!IMPORTANT]
> An HTTP `200 OK` response indicates **only** that the network socket delivered the payload. It does **NOT** prove that the receiver successfully verified the signature or decrypted the paper. Receiver confirmation requires an explicit, cryptographically authenticated response body from the receiver application.
""")

    add_cell("code", """def send_package_to_receiver(
    package_file: Union[str, Path],
    receiver_url: str,
    timeout_seconds: Tuple[float, float] = (5.0, 15.0)
) -> Dict[str, Any]:
    \"\"\"Transmits the encrypted package JSON via HTTP POST to the receiver endpoint.
    
    timeout_seconds is (connect_timeout, read_timeout).
    \"\"\"
    path = Path(package_file)
    if not path.is_file():
        raise FileNotFoundError(f"Package file not found: {path}")
    
    with open(path, "rb") as f:
        payload = parse_secure_json(f.read())
    
    print(f"Initiating HTTP POST transmission...")
    print(f"Target Endpoint : {receiver_url}")
    print(f"Package File    : {path.name} ({path.stat().st_size} bytes)")
    
    try:
        response = requests.post(
            receiver_url,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=timeout_seconds
        )
        return {
            "status": "TRANSMITTED",
            "http_status_code": response.status_code,
            "response_headers": dict(response.headers),
            "response_body": response.text,
            "receiver_confirmed": (response.status_code == 200 and "verified" in response.text.lower())
        }
    except requests.exceptions.ConnectTimeout:
        return {"status": "FAILED", "error": "Connection Timed Out: Receiver host is unreachable."}
    except requests.exceptions.ConnectionError as e:
        return {"status": "FAILED", "error": f"Connection Refused: Receiver service is not running. ({e})"}
    except requests.exceptions.Timeout:
        return {"status": "FAILED", "error": "Read Timed Out: Receiver did not respond within timeout window."}
    except requests.exceptions.RequestException as e:
        return {"status": "FAILED", "error": f"HTTP Transmission Error: {e}"}

# Safety Toggle: Set SEND_NOW = True when your colleague's receiver server is running!
SEND_NOW = False
RECEIVER_ENDPOINT = "http://192.168.1.100:8000/receive"  # Adjust to colleague's LAN IP

if SEND_NOW:
    tx_result = send_package_to_receiver(saved_package_path, RECEIVER_ENDPOINT)
    print("\\nTransmission Result:")
    for k, v in tx_result.items():
        print(f"  {k}: {v}")
else:
    print(f"[SKIPPED] Network transmission not triggered (SEND_NOW=False).")
    print(f"Configure RECEIVER_ENDPOINT and set SEND_NOW = True when ready to transmit over LAN.")
""")

    # -------------------------------------------------------------------------
    # 12. Run security and tampering tests (Markdown + Code)
    # -------------------------------------------------------------------------
    add_cell("markdown", """---
## 12. Run Security and Tampering Tests

This cell executes **15 automated tests** in isolated temporary environments using synthetic test keys and test papers to prove the correctness and resilience of our cryptographic pipeline:

### 15 Security Test Cases:
1. **RSA Key Generation & Serialization:** RSA-3072 bit length validation.
2. **Encrypted PKCS#8 Storage:** Validates passphrase decryption and wrong-passphrase rejection.
3. **Public Key Export/Import:** PEM encoding roundtrip integrity.
4. **SHA-256 Fingerprint Formatting:** Validates uppercase hexadecimal colon-delimited format.
5. **Rejection of Weak Keys:** Rejection of RSA keys smaller than 3072 bits.
6. **Overwrite Protection:** Refusal to overwrite existing keys without explicit confirmation.
7. **Package Creation:** Conformance to `SecureExamExchange` schema.
8. **Indistinguishability:** Fresh nonces and session keys on repeat encryptions of identical plaintexts.
9. **Signature Verification:** Positive verification with legitimate sender key.
10. **Wrong Sender Public Key Rejection:** Rejection of signatures verified with impostor keys.
11. **Tamper Detection (6 Vectors):** Detects tampering of ciphertext, metadata, nonce, tag, wrapped key, and signature.
12. **Malformed JSON & Base64:** Rejection of duplicate JSON keys and corrupted Base64.
13. **Empty & Binary File Handling:** Encryption and verification of 0-byte and arbitrary binary files.
14. **Missing Receiver Public Key:** Refusal to encrypt without recipient key.
15. **Network Failure Handling:** Graceful error reporting when endpoint is offline.
""")

    add_cell("code", """# Test Fixture: Verification and Decryption helper for automated testing
def _test_verify_and_decrypt(
    package: dict,
    sender_public_key: rsa.RSAPublicKey,
    recipient_private_key: rsa.RSAPrivateKey
) -> bytes:
    \"\"\"Cryptographic verification fixture used strictly for automated test validation.\"\"\"
    if "signature" not in package:
        raise ValueError("Package lacks signature field")
    
    # 1. Separate signature and canonicalize unsigned package
    b64_sig = package["signature"]
    sig_bytes = base64.b64decode(b64_sig, validate=True)
    unsigned = {k: v for k, v in package.items() if k != "signature"}
    unsigned_bytes = canonical_json_dumps(unsigned)

    # 2. Verify RSA-PSS signature
    sender_public_key.verify(
        sig_bytes,
        unsigned_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # 3. Unwrap AES session key using recipient private key
    enc_key_bytes = base64.b64decode(package["encrypted_key"], validate=True)
    aes_key = recipient_private_key.decrypt(
        enc_key_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # 4. Decrypt AES-256-GCM ciphertext
    nonce = base64.b64decode(package["nonce"], validate=True)
    ciphertext = base64.b64decode(package["ciphertext"], validate=True)
    tag = base64.b64decode(package["tag"], validate=True)
    if len(tag) != 16:
        raise ValueError("Invalid tag length")
    
    aad_bytes = canonical_json_dumps(package["metadata"])
    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext + tag, aad_bytes)

    # 5. Metadata verification
    meta = package["metadata"]
    if len(plaintext) != meta["file_size"]:
        raise ValueError("Decrypted length does not match metadata file_size")
    if hashlib.sha256(plaintext).hexdigest() != meta["plaintext_sha256"]:
        raise ValueError("Decrypted hash does not match metadata plaintext_sha256")

    return plaintext


def run_full_security_test_suite() -> Dict[str, Tuple[str, str]]:
    \"\"\"Runs all 15 automated security tests and writes summary to test_results/.\"\"\"
    test_results = {}
    print("=" * 75)
    print("STARTING 15 AUTOMATED CYBERSECURITY TESTS")
    print("=" * 75)

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        t_keys = temp_path / "keys"
        t_keys.mkdir()
        t_outgoing = temp_path / "outgoing"
        t_outgoing.mkdir()

        # -------------------------------------------------------------
        # Test 1: Key Generation
        # -------------------------------------------------------------
        try:
            priv, pub = generate_sender_key_pair(3072)
            assert priv.key_size == 3072 and pub.key_size == 3072
            test_results["test_01_rsa_key_generation"] = ("PASS", "RSA-3072 key pair generated successfully")
        except Exception as e:
            test_results["test_01_rsa_key_generation"] = ("FAIL", str(e))

        # -------------------------------------------------------------
        # Test 2: Encrypted Private Key IO
        # -------------------------------------------------------------
        try:
            priv_p = t_keys / "sender_priv.pem"
            save_sender_private_key(priv, priv_p, "MyTestSecretPass123!")
            loaded_priv = load_sender_private_key(priv_p, "MyTestSecretPass123!")
            assert loaded_priv.key_size == 3072
            
            wrong_pass_blocked = False
            try:
                load_sender_private_key(priv_p, "WrongPassphrase!")
            except Exception:
                wrong_pass_blocked = True
            assert wrong_pass_blocked, "Failed to reject invalid passphrase"
            test_results["test_02_encrypted_private_key_io"] = ("PASS", "PKCS#8 encryption and wrong-passphrase rejection verified")
        except Exception as e:
            test_results["test_02_encrypted_private_key_io"] = ("FAIL", str(e))

        # -------------------------------------------------------------
        # Test 3: Public Key Export & Import
        # -------------------------------------------------------------
        try:
            pub_p = t_keys / "sender_pub.pem"
            save_public_key(pub, pub_p)
            loaded_pub = load_and_validate_public_key(pub_p, min_key_size=3072)
            assert loaded_pub.key_size == 3072
            test_results["test_03_public_key_export_import"] = ("PASS", "Public key export/import cycle verified")
        except Exception as e:
            test_results["test_03_public_key_export_import"] = ("FAIL", str(e))

        # -------------------------------------------------------------
        # Test 4: SHA-256 Fingerprint Generation
        # -------------------------------------------------------------
        try:
            fp = get_public_key_fingerprint(pub)
            parts = fp.split(":")
            assert len(parts) == 32 and all(len(p) == 2 for p in parts)
            test_results["test_04_fingerprint_generation"] = ("PASS", f"Valid colon-delimited hex fingerprint ({fp[:17]}...)")
        except Exception as e:
            test_results["test_04_fingerprint_generation"] = ("FAIL", str(e))

        # -------------------------------------------------------------
        # Test 5: Rejection of Small RSA Keys (< 3072 bits)
        # -------------------------------------------------------------
        try:
            weak_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            weak_pub = weak_priv.public_key()
            weak_p = t_keys / "weak_pub.pem"
            save_public_key(weak_pub, weak_p)
            
            weak_rejected = False
            try:
                load_and_validate_public_key(weak_p, min_key_size=3072)
            except ValueError:
                weak_rejected = True
            assert weak_rejected, "2048-bit key was not rejected"
            test_results["test_05_reject_small_rsa_keys"] = ("PASS", "Rejected weak 2048-bit key (< 3072 bits policy)")
        except Exception as e:
            test_results["test_05_reject_small_rsa_keys"] = ("FAIL", str(e))

        # -------------------------------------------------------------
        # Test 6: Overwrite Protection Without Confirmation
        # -------------------------------------------------------------
        try:
            overwrite_refused = False
            try:
                save_public_key(pub, pub_p, force=False)
            except FileExistsError:
                overwrite_refused = True
            assert overwrite_refused, "Allowed silent overwrite of existing public key"
            test_results["test_06_refuse_silent_overwrite"] = ("PASS", "Prevented silent file overwrite without explicit confirmation")
        except Exception as e:
            test_results["test_06_refuse_silent_overwrite"] = ("FAIL", str(e))

        # Receiver keys fixture for package tests
        rec_priv, rec_pub = generate_sender_key_pair(3072)

        # Sample test file
        test_file = temp_path / "test_paper.txt"
        test_file.write_text("CONFIDENTIAL QUESTION PAPER CONTENT", encoding="utf-8")

        # -------------------------------------------------------------
        # Test 7: Successful Package Creation
        # -------------------------------------------------------------
        try:
            pkg_p, pkg_data = encrypt_and_sign_file(
                input_path=test_file,
                sender_private_key=priv,
                recipient_public_key=rec_pub,
                sender_id="faculty_test",
                recipient_id="evaluator_test",
                output_dir=t_outgoing
            )
            assert pkg_p.is_file()
            assert pkg_data["protocol"] == PROTOCOL_NAME
            assert pkg_data["version"] == PROTOCOL_VERSION
            test_results["test_07_package_creation"] = ("PASS", f"Package created conforming to protocol: {pkg_p.name}")
        except Exception as e:
            test_results["test_07_package_creation"] = ("FAIL", str(e))

        # -------------------------------------------------------------
        # Test 8: Indistinguishability & Fresh Nonces
        # -------------------------------------------------------------
        try:
            _, pkg_data_2 = encrypt_and_sign_file(
                input_path=test_file,
                sender_private_key=priv,
                recipient_public_key=rec_pub,
                sender_id="faculty_test",
                recipient_id="evaluator_test",
                output_dir=t_outgoing
            )
            assert pkg_data["nonce"] != pkg_data_2["nonce"]
            assert pkg_data["encrypted_key"] != pkg_data_2["encrypted_key"]
            assert pkg_data["ciphertext"] != pkg_data_2["ciphertext"]
            assert pkg_data["signature"] != pkg_data_2["signature"]
            test_results["test_08_indistinguishability_fresh_nonces"] = ("PASS", "Distinct nonces, wrapped keys, ciphertexts, and signatures across identical plaintexts")
        except Exception as e:
            test_results["test_08_indistinguishability_fresh_nonces"] = ("FAIL", str(e))

        # -------------------------------------------------------------
        # Test 9: Signature Verification with Correct Key
        # -------------------------------------------------------------
        try:
            decrypted = _test_verify_and_decrypt(pkg_data, pub, rec_priv)
            assert decrypted == test_file.read_bytes()
            test_results["test_09_signature_verification_success"] = ("PASS", "Signature verified and plaintext recovered successfully")
        except Exception as e:
            test_results["test_09_signature_verification_success"] = ("FAIL", str(e))

        # -------------------------------------------------------------
        # Test 10: Signature Rejection with Wrong Sender Public Key
        # -------------------------------------------------------------
        try:
            _, impostor_pub = generate_sender_key_pair(3072)
            wrong_sig_caught = False
            try:
                _test_verify_and_decrypt(pkg_data, impostor_pub, rec_priv)
            except InvalidSignature:
                wrong_sig_caught = True
            assert wrong_sig_caught, "Signature verification did not reject impostor public key"
            test_results["test_10_wrong_sender_public_key"] = ("PASS", "Signature rejected when verified under impostor public key")
        except Exception as e:
            test_results["test_10_wrong_sender_public_key"] = ("FAIL", str(e))

        # -------------------------------------------------------------
        # Test 11: Tamper Detection (6 Independent Vectors)
        # -------------------------------------------------------------
        try:
            vectors_caught = 0
            # 11a: Ciphertext tampering
            p_tamper = json.loads(json.dumps(pkg_data))
            raw_ct = bytearray(base64.b64decode(p_tamper["ciphertext"]))
            raw_ct[0] ^= 0x01
            p_tamper["ciphertext"] = base64.b64encode(raw_ct).decode('ascii')
            try:
                _test_verify_and_decrypt(p_tamper, pub, rec_priv)
            except (InvalidSignature, InvalidTag):
                vectors_caught += 1

            # 11b: Metadata tampering
            p_tamper = json.loads(json.dumps(pkg_data))
            p_tamper["metadata"]["file_size"] += 1
            try:
                _test_verify_and_decrypt(p_tamper, pub, rec_priv)
            except (InvalidSignature, InvalidTag):
                vectors_caught += 1

            # 11c: Nonce tampering
            p_tamper = json.loads(json.dumps(pkg_data))
            raw_nonce = bytearray(base64.b64decode(p_tamper["nonce"]))
            raw_nonce[0] ^= 0x01
            p_tamper["nonce"] = base64.b64encode(raw_nonce).decode('ascii')
            try:
                _test_verify_and_decrypt(p_tamper, pub, rec_priv)
            except (InvalidSignature, InvalidTag):
                vectors_caught += 1

            # 11d: Tag tampering
            p_tamper = json.loads(json.dumps(pkg_data))
            raw_tag = bytearray(base64.b64decode(p_tamper["tag"]))
            raw_tag[0] ^= 0x01
            p_tamper["tag"] = base64.b64encode(raw_tag).decode('ascii')
            try:
                _test_verify_and_decrypt(p_tamper, pub, rec_priv)
            except (InvalidSignature, InvalidTag):
                vectors_caught += 1

            # 11e: Wrapped Key tampering
            p_tamper = json.loads(json.dumps(pkg_data))
            raw_k = bytearray(base64.b64decode(p_tamper["encrypted_key"]))
            raw_k[0] ^= 0x01
            p_tamper["encrypted_key"] = base64.b64encode(raw_k).decode('ascii')
            try:
                _test_verify_and_decrypt(p_tamper, pub, rec_priv)
            except (InvalidSignature, ValueError):
                vectors_caught += 1

            # 11f: Signature tampering
            p_tamper = json.loads(json.dumps(pkg_data))
            raw_sig = bytearray(base64.b64decode(p_tamper["signature"]))
            raw_sig[0] ^= 0x01
            p_tamper["signature"] = base64.b64encode(raw_sig).decode('ascii')
            try:
                _test_verify_and_decrypt(p_tamper, pub, rec_priv)
            except InvalidSignature:
                vectors_caught += 1

            assert vectors_caught == 6, f"Expected 6 tampering vectors detected, got {vectors_caught}"
            test_results["test_11_tamper_detection"] = ("PASS", "All 6 tampering vectors (ciphertext, metadata, nonce, tag, key, signature) detected")
        except Exception as e:
            test_results["test_11_tamper_detection"] = ("FAIL", str(e))

        # -------------------------------------------------------------
        # Test 12: Malformed JSON & Base64
        # -------------------------------------------------------------
        try:
            dup_json = '{"protocol":"SecureExamExchange","version":1,"version":2}'
            dup_caught = False
            try:
                parse_secure_json(dup_json)
            except ValueError:
                dup_caught = True
            
            p_tamper = json.loads(json.dumps(pkg_data))
            p_tamper["ciphertext"] = "MalformedBase64!@#$"
            b64_caught = False
            try:
                _test_verify_and_decrypt(p_tamper, pub, rec_priv)
            except Exception:
                b64_caught = True
            
            assert dup_caught and b64_caught
            test_results["test_12_malformed_json_and_b64"] = ("PASS", "Rejected duplicate JSON keys and malformed Base64 data")
        except Exception as e:
            test_results["test_12_malformed_json_and_b64"] = ("FAIL", str(e))

        # -------------------------------------------------------------
        # Test 13: Empty and Binary Files
        # -------------------------------------------------------------
        try:
            # 0-byte file
            empty_f = temp_path / "empty.txt"
            empty_f.write_bytes(b"")
            _, p_empty = encrypt_and_sign_file(empty_f, priv, rec_pub, "f", "r", t_outgoing)
            assert _test_verify_and_decrypt(p_empty, pub, rec_priv) == b""

            # Arbitrary binary (PDF mock)
            bin_f = temp_path / "mock.pdf"
            pdf_bytes = b"%PDF-1.7\\r\\n" + bytes([0x00, 0xFF, 0xFE, 0xCA, 0xFE]) + os.urandom(2048)
            bin_f.write_bytes(pdf_bytes)
            _, p_bin = encrypt_and_sign_file(bin_f, priv, rec_pub, "f", "r", t_outgoing)
            assert _test_verify_and_decrypt(p_bin, pub, rec_priv) == pdf_bytes

            test_results["test_13_empty_and_binary_files"] = ("PASS", "Successfully handled 0-byte empty files and raw binary payloads")
        except Exception as e:
            test_results["test_13_empty_and_binary_files"] = ("FAIL", str(e))

        # -------------------------------------------------------------
        # Test 14: Missing Receiver Public Key
        # -------------------------------------------------------------
        try:
            missing_key_caught = False
            try:
                encrypt_and_sign_file(test_file, priv, None, "f", "r", t_outgoing)
            except (TypeError, ValueError):
                missing_key_caught = True
            assert missing_key_caught
            test_results["test_14_missing_receiver_key"] = ("PASS", "Refused encryption when receiver public key is absent")
        except Exception as e:
            test_results["test_14_missing_receiver_key"] = ("FAIL", str(e))

        # -------------------------------------------------------------
        # Test 15: Network Failure Handling
        # -------------------------------------------------------------
        try:
            offline_url = "http://127.0.0.1:59998/nonexistent"
            res = send_package_to_receiver(pkg_p, offline_url, timeout_seconds=(0.5, 0.5))
            assert res["status"] == "FAILED"
            test_results["test_15_network_failure_handling"] = ("PASS", f"Gracefully caught offline network error: {res['error'][:40]}...")
        except Exception as e:
            test_results["test_15_network_failure_handling"] = ("FAIL", str(e))

    # Print summary
    for name, (status, desc) in test_results.items():
        print(f"[{status}] {name:<40}: {desc}")
    
    passed_count = sum(1 for s, _ in test_results.values() if s == "PASS")
    total_count = len(test_results)
    print("=" * 75)
    print(f"TEST RESULTS SUMMARY: {passed_count}/{total_count} TESTS PASSED")
    print("=" * 75)

    # Persist summary report to secure_exam_exchange/test_results/
    summary_report_path = DIR_TEST_RESULTS / "test_summary.json"
    report_data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total": total_count,
        "passed": passed_count,
        "failed": total_count - passed_count,
        "results": test_results
    }
    with open(summary_report_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)
    print(f"Test summary persisted to: {summary_report_path.resolve()}")

    return test_results

# Execute test suite
test_run_output = run_full_security_test_suite()
""")

    # -------------------------------------------------------------------------
    # 13. Display test results and explain security properties (Markdown + Code)
    # -------------------------------------------------------------------------
    add_cell("markdown", """---
## 13. Display Test Results and Explain Security Properties

### Theoretical Security Evaluation

#### 1. Confidentiality (AES-256-GCM + RSA-OAEP)
* **Hybrid Cryptosystem Rationale:** Asymmetric ciphers like RSA cannot encrypt payloads larger than their modulus and are computationally slow. Symmetric ciphers like AES-256 process gigabytes per second. We generate a fresh, cryptographically secure 32-byte session key for each paper, encrypting the paper symmetrically and encapsulating the session key asymmetrically.
* **Semantic Security:** RSA-OAEP incorporates random salt into the encryption padding. Encrypting the exact same 32-byte AES key twice produces completely different ciphertext bytes, preventing chosen-plaintext attacks.

#### 2. Cryptographic Integrity & Authenticity (AES-GCM & RSA-PSS)
* **Galois/Counter Mode (GCM):** AES-GCM generates a 128-bit authentication tag calculated over both the ciphertext and the canonical Associated Authenticated Data (AAD). If an active attacker flips even a single bit in the ciphertext or alters the file size in the metadata, tag verification fails unconditionally.
* **Probabilistic Signature Scheme (PSS):** Unlike older PKCS#1 v1.5 padding schemes which had structural vulnerabilities (e.g., Bleichenbacher's signature forgery), RSA-PSS utilizes randomized salting and provable security reductions to guarantee that forged signatures cannot be constructed.

#### 3. Key Separation Principle
* A fundamental tenet of cryptographic engineering is **key specialization**. The sender's private key is exclusively used for *signing* (`RSA-PSS`). The receiver's public key is exclusively used for *wrapping* session keys (`RSA-OAEP`). Reusing the same key pair for both signing and encryption creates severe cross-protocol vulnerabilities.

#### 4. Public Key Authentication & MitM Prevention
* Digital signatures alone **do not** prove a person's real-world identity unless their public key is authenticated.
* If Alice accepts Bob's public key without checking its authenticity, an adversary Eve could substitute her own public key. Eve could then decrypt all papers sent to Bob.
* Comparing the SHA-256 public key fingerprint via an authenticated out-of-band channel (e.g., telephone call, trusted PKI, in-person meeting) guarantees that the public key actually belongs to the intended faculty colleague.

#### 5. Replay Attack Vectors & Mitigation in Production
* A valid digital signature guarantees that the sender created the message at some point in the past. However, **signatures alone do not prevent an adversary from capturing a valid encrypted package and re-sending it later** (Replay Attack).
* In this application, replay protection is enhanced by embedding a UTC ISO-8601 timestamp (`created_at`) and unique session nonces in the canonical metadata signed by the sender.
* In a scaled production deployment:
  1. The receiver maintains a **Replay Cache / Database** of recently observed package fingerprints and message IDs.
  2. Any package whose `created_at` timestamp is outside an acceptable clock-skew window (e.g., $\\pm 5$ minutes) is rejected.
  3. Any package with a previously recorded message ID or digest within the window is discarded as a replay.
""")

    add_cell("code", """# Display Persisted Audit Log of Security Test Results
summary_file = DIR_TEST_RESULTS / "test_summary.json"

if summary_file.exists():
    with open(summary_file, "r", encoding="utf-8") as f:
        summary = json.load(f)
    print("=" * 80)
    print(f"             OFFICIAL CRYPTOGRAPHIC AUDIT REPORT ({summary['timestamp']})")
    print("=" * 80)
    print(f"Total Tests Executed : {summary['total']}")
    print(f"Passed               : {summary['passed']}")
    print(f"Failed               : {summary['failed']}")
    print("-" * 80)
    for test_name, (status, detail) in summary["results"].items():
        print(f"  [{status}] {test_name:<42}: {detail}")
    print("=" * 80)
else:
    print("No persisted test summary found.")
""")

    # -------------------------------------------------------------------------
    # Section 16: Colleague Receiver Prompt
    # -------------------------------------------------------------------------
    add_cell("markdown", """---
## Companion Receiver Application Prompt

Copy the prompt below and give it to your colleague. They can provide it directly to an AI assistant on their laptop to generate a 100% compatible Receiver Jupyter notebook without needing access to your sender source code.

```markdown
# PROMPT FOR RECEIVER APPLICATION: Secure Examination-Paper Exchange Using Python

Act as a senior Python cybersecurity developer. Build the companion Receiver application for a college workshop project called "Secure Examination-Paper Exchange Using Python".

Build the receiver application inside ONE Jupyter Notebook named `receiver_secure_exam_exchange.ipynb` running in VS Code with Python 3.11+ and the Jupyter extension.

## Compatibility Requirements

Your receiver must be 100% compatible with packages generated by the sender protocol:
- Protocol Name: "SecureExamExchange", Version: 1
- Cryptographic Library: `cryptography`
- Asymmetric Keys: RSA-3072 bits or higher
- Session Key Decryption: RSA-OAEP with SHA-256, MGF1-SHA-256, empty label
- Symmetric Decryption: AES-256-GCM with 32-byte key, 12-byte nonce, 16-byte authentication tag
- Associated Authenticated Data (AAD): Canonical UTF-8 JSON bytes of the complete `metadata` object
- Digital Signature Verification: RSA-PSS with SHA-256, MGF1-SHA-256, maximum salt length
- Signature Scope: Signature covers the entire canonical JSON unsigned package (the complete package with the top-level "signature" key removed)
- Public Key Fingerprints: Uppercase hexadecimal SHA-256 of SubjectPublicKeyInfo DER with colon separators ("AA:BB:CC:...")

## Package JSON Structure
{
  "protocol": "SecureExamExchange",
  "version": 1,
  "metadata": {
    "sender_id": "string",
    "recipient_id": "string",
    "filename": "string",
    "file_size": 123,
    "created_at": "ISO-8601 UTC timestamp",
    "encryption": "AES-256-GCM",
    "key_wrap": "RSA-OAEP-SHA256",
    "signature": "RSA-PSS-SHA256",
    "plaintext_sha256": "hex digest"
  },
  "encrypted_key": "Base64",
  "nonce": "Base64",
  "ciphertext": "Base64",
  "tag": "Base64",
  "signature": "Base64"
}

## Workflow & Features Required
1. Generate Receiver RSA-3072 key pair, save private key as PKCS#8 PEM encrypted with a passphrase prompted via getpass.getpass(), save public key as PEM.
2. Export receiver public key to share with sender.
3. Import sender's public key (validating >= 3072 bits) and display SHA-256 fingerprints of both keys.
4. Ingest sender's JSON package from local incoming folder or optional HTTP receiver endpoint (Flask/FastAPI/http.server on port 8000).
5. Canonicalize package without "signature" key, verify RSA-PSS signature against sender public key.
6. Decrypt AES session key with receiver private key (RSA-OAEP).
7. Decrypt AES-256-GCM ciphertext using the nonce, tag, and canonical metadata as AAD.
8. Verify recovered plaintext byte length against `metadata.file_size` and SHA-256 against `metadata.plaintext_sha256`.
9. Save verified decrypted exam paper in a secure `decrypted_papers/` folder.
10. Include automated security tests verifying decryption, tamper rejection, invalid signature rejection, and wrong key rejection.
```
""")

    notebook = {
        "cells": cells,
        "metadata": {
            "kernelspec": {
                "display_name": "Python 3",
                "language": "python",
                "name": "python3"
            },
            "language_info": {
                "codemirror_mode": {
                    "name": "ipython",
                    "version": 3
                },
                "file_extension": ".py",
                "mimetype": "text/x-python",
                "name": "python",
                "nbformat_minor": 5,
                "pygments_lexer": "ipython3",
                "version": "3.13.15"
            }
        },
        "nbformat": 4,
        "nbformat_minor": 5
    }

    out_file = Path("sender_secure_exam_exchange.ipynb")
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(notebook, f, indent=1)
    
    print(f"Generated {out_file.resolve()} with {len(cells)} cells.")

if __name__ == "__main__":
    generate_notebook()
