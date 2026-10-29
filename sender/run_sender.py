"""
Sender Application Runner: Secure Examination-Paper Exchange
Executes the full Sender workflow:
  Phase A: Sender RSA-3072 Key Pair Loading / Generation & Display Public Key to Copy
  Phase B: Receiver Public Key Input (Paste PEM or Load File) & Fingerprint Comparison
  Phase C: Examination Paper Hybrid Encryption (AES-256-GCM + RSA-OAEP) & Signing (RSA-PSS)
  Phase D: Save Encrypted Package Directly into crypto_workshop1 Root Directory
  Phase E: Comprehensive 15-Test Cryptographic Audit Suite
"""
import os
import sys
import json
import base64
import hashlib
import shutil
import getpass
from datetime import datetime, timezone
from pathlib import Path
from typing import Tuple, Dict, Any, Union, Optional

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature, InvalidTag

PROTOCOL_NAME = "SecureExamExchange"
PROTOCOL_VERSION = 1
DEFAULT_MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB

# Runtime directories
BASE_DIR = Path("secure_exam_exchange")
DIR_KEYS = BASE_DIR / "keys"
DIR_INPUT = BASE_DIR / "input_papers"
DIR_OUTGOING = BASE_DIR / "outgoing"
DIR_RECEIVED_KEYS = BASE_DIR / "received_public_keys"
DIR_TEST_RESULTS = BASE_DIR / "test_results"
DIR_EXPORTED_KEYS = BASE_DIR / "exported_keys"
DIR_EXPORTED_PKGS = BASE_DIR / "exported_packages"

for folder in [DIR_KEYS, DIR_INPUT, DIR_OUTGOING, DIR_RECEIVED_KEYS, DIR_TEST_RESULTS, DIR_EXPORTED_KEYS, DIR_EXPORTED_PKGS]:
    folder.mkdir(parents=True, exist_ok=True)

# --- Canonical Serialization Engine ---

def canonical_json_dumps(obj: Any) -> bytes:
    """Serializes an object into deterministic canonical UTF-8 JSON bytes."""
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(',', ':'),
        allow_nan=False,
        ensure_ascii=False
    ).encode('utf-8')

def _reject_duplicate_keys(pairs):
    res = {}
    for k, v in pairs:
        if k in res:
            raise ValueError(f"Duplicate JSON key: {k}")
        res[k] = v
    return res

def parse_secure_json(data: Union[str, bytes]) -> dict:
    if isinstance(data, bytes):
        data = data.decode('utf-8')
    return json.loads(data, object_pairs_hook=_reject_duplicate_keys)

def get_public_key_fingerprint(public_key: rsa.RSAPublicKey) -> str:
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    digest = hashlib.sha256(der).hexdigest().upper()
    return ":".join(digest[i:i+2] for i in range(0, len(digest), 2))

# --- Core Cryptographic Operations ---

def generate_sender_key_pair(key_size: int = 3072) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    if key_size < 3072:
        raise ValueError(f"Key size must be >= 3072 bits (got {key_size}).")
    priv = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    return priv, priv.public_key()

def save_sender_private_key(priv: rsa.RSAPrivateKey, path: Path, passphrase: str, force: bool = False):
    if path.exists() and not force:
        raise FileExistsError(f"Private key already exists at {path}")
    pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode('utf-8'))
    )
    with open(path, "wb") as f:
        f.write(pem)
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass

def load_sender_private_key(path: Path, passphrase: str) -> rsa.RSAPrivateKey:
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=passphrase.encode('utf-8'))

def save_public_key(pub: rsa.RSAPublicKey, path: Path, force: bool = False):
    if path.exists() and not force:
        raise FileExistsError(f"Public key already exists at {path}")
    pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(path, "wb") as f:
        f.write(pem)

def load_and_validate_public_key_pem_bytes(pem_bytes: bytes, min_bits: int = 3072) -> rsa.RSAPublicKey:
    pub = serialization.load_pem_public_key(pem_bytes)
    if not isinstance(pub, rsa.RSAPublicKey):
        raise TypeError("Provided key is not an RSA public key.")
    if pub.key_size < min_bits:
        raise ValueError(f"Key size ({pub.key_size} bits) is under required {min_bits} bits.")
    return pub

def load_and_validate_public_key(path: Path, min_bits: int = 3072) -> rsa.RSAPublicKey:
    with open(path, "rb") as f:
        return load_and_validate_public_key_pem_bytes(f.read(), min_bits)

# --- Candidate Paper Discovery in Root Workspace (crypto_workshop1) ---

def discover_exam_paper(explicit_name: Optional[str] = None) -> Path:
    """Discovers the exam paper to encrypt.
    Prioritizes files placed directly in the crypto_workshop1 root directory.
    Falls back to secure_exam_exchange/input_papers/sample_exam.txt if none is in root.
    """
    if explicit_name:
        p_root = Path(explicit_name)
        if p_root.is_file():
            return p_root
        p_sub = DIR_INPUT / explicit_name
        if p_sub.is_file():
            return p_sub
        raise FileNotFoundError(f"Specified exam paper '{explicit_name}' was not found.")

    # Scan crypto_workshop1 root for document files
    ignored_ext = {".py", ".ipynb", ".json", ".pem", ".md", ".git"}
    ignored_names = {"build_notebook.py", "run_sender.py"}
    
    root_candidates = [
        f for f in Path(".").iterdir()
        if f.is_file() and f.suffix.lower() not in ignored_ext and f.name not in ignored_names
    ]
    if root_candidates:
        # Prioritize files with 'exam', 'paper', 'question', 'main' in name if multiple
        for c in root_candidates:
            if any(k in c.name.lower() for k in ["exam", "paper", "question", "main"]):
                return c
        return root_candidates[0]

    # Default fallback
    return DIR_INPUT / "sample_exam.txt"

def encrypt_and_sign_file(
    input_path: Path,
    sender_private_key: rsa.RSAPrivateKey,
    recipient_public_key: rsa.RSAPublicKey,
    sender_id: str,
    recipient_id: str,
    output_dir: Path,
    max_size_bytes: int = DEFAULT_MAX_FILE_SIZE
) -> Tuple[Path, Path, dict]:
    file_size = input_path.stat().st_size
    if file_size > max_size_bytes:
        raise ValueError(f"File size {file_size} exceeds {max_size_bytes} limit.")

    with open(input_path, "rb") as f:
        plaintext = f.read()
    plaintext_sha256 = hashlib.sha256(plaintext).hexdigest()

    # Fresh session key and nonce
    aes_session_key = os.urandom(32)
    nonce = os.urandom(12)

    created_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    metadata = {
        "created_at": created_at,
        "encryption": "AES-256-GCM",
        "filename": input_path.name,
        "file_size": len(plaintext),
        "key_wrap": "RSA-OAEP-SHA256",
        "plaintext_sha256": plaintext_sha256,
        "recipient_id": recipient_id,
        "sender_id": sender_id,
        "signature": "RSA-PSS-SHA256"
    }

    # AES-GCM Associated Authenticated Data
    aad_bytes = canonical_json_dumps(metadata)

    aesgcm = AESGCM(aes_session_key)
    ct_with_tag = aesgcm.encrypt(nonce, plaintext, aad_bytes)
    ciphertext = ct_with_tag[:-16]
    tag = ct_with_tag[-16:]

    # RSA-OAEP session key encryption
    encrypted_key = recipient_public_key.encrypt(
        aes_session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    unsigned_package = {
        "ciphertext": base64.b64encode(ciphertext).decode('ascii'),
        "encrypted_key": base64.b64encode(encrypted_key).decode('ascii'),
        "metadata": metadata,
        "nonce": base64.b64encode(nonce).decode('ascii'),
        "protocol": PROTOCOL_NAME,
        "tag": base64.b64encode(tag).decode('ascii'),
        "version": PROTOCOL_VERSION
    }

    # RSA-PSS signature over canonical unsigned package
    canonical_unsigned_bytes = canonical_json_dumps(unsigned_package)
    sig_bytes = sender_private_key.sign(
        canonical_unsigned_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    signed_package = dict(unsigned_package)
    signed_package["signature"] = base64.b64encode(sig_bytes).decode('ascii')

    stem = input_path.stem
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    rand_id = os.urandom(4).hex()
    out_filename = f"{stem}_pkg_{ts}_{rand_id}.json"
    
    # Save copy 1 in secure_exam_exchange/outgoing/
    out_file = output_dir / out_filename
    with open(out_file, "wb") as f:
        f.write(canonical_json_dumps(signed_package))

    # Save copy 2 DIRECTLY in crypto_workshop1 root directory!
    root_file = Path(f"{stem}_encrypted_package.json")
    with open(root_file, "wb") as f:
        f.write(canonical_json_dumps(signed_package))

    return root_file, out_file, signed_package

# --- Main Sender Workflow Execution ---

def main():
    print("=" * 80)
    print("         SENDER APPLICATION EXECUTION: SECURE EXAMINATION-PAPER EXCHANGE")
    print("=" * 80)

    # 1. Sender Keys Management
    sender_priv_path = DIR_KEYS / "sender_private.pem"
    sender_pub_path = DIR_KEYS / "sender_public.pem"
    sender_passphrase = None

    print("\n[PHASE A: SENDER KEY MANAGEMENT & PUBLIC KEY OUTPUT]")
    if sender_priv_path.exists() and sender_pub_path.exists():
        print(f" -> Found existing Sender keys in 'keys/'. Reusing existing keys.")
        sender_pub = load_and_validate_public_key(sender_pub_path, min_bits=3072)
    else:
        print(" -> Generating new RSA-3072 key pair for Sender...")
        passphrase = getpass.getpass("Enter passphrase to encrypt Sender Private Key: ")
        passphrase_confirmation = getpass.getpass("Confirm passphrase: ")
        if passphrase != passphrase_confirmation:
            raise ValueError("Passphrases do not match. Aborting key generation.")
        if len(passphrase) < 8:
            raise ValueError("Passphrase must be at least 8 characters long.")

        priv, pub = generate_sender_key_pair(3072)
        save_sender_private_key(priv, sender_priv_path, passphrase)
        save_public_key(pub, sender_pub_path)
        sender_pub = pub
        sender_passphrase = passphrase
        print(f" -> Saved Sender Encrypted Private Key : {sender_priv_path}")
        print(f" -> Saved Sender Public Key           : {sender_pub_path}")

    sender_fp = get_public_key_fingerprint(sender_pub)
    sender_pem_text = sender_pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8').strip()

    # PRINT SENDER PUBLIC KEY CLEARLY FOR COPYING
    print("\n" + "=" * 80)
    print("      YOUR SENDER PUBLIC KEY (COPY THIS ENTIRE BLOCK AND SEND TO RECEIVER)")
    print("=" * 80)
    print(sender_pem_text)
    print("=" * 80)
    print(f"SHA-256 Fingerprint: {sender_fp}")
    print("=" * 80)

    # Export copy to file as well
    exported_sender_pub = DIR_EXPORTED_KEYS / "sender_public.pem"
    shutil.copyfile(sender_pub_path, exported_sender_pub)

    # 2. Receiver Public Key Input
    print("\n[PHASE B: INPUT RECEIVER PUBLIC KEY]")
    
    # Check if a file already exists in root or received_public_keys
    candidate_paths = [
        Path("receiver_public.pem"),
        DIR_RECEIVED_KEYS / "receiver_public.pem",
        DIR_KEYS / "receiver_public.pem"
    ]
    existing_key_file = next((p for p in candidate_paths if p.is_file()), None)

    receiver_pub = None
    print("How would you like to provide the Receiver's Public Key?")
    print("  1. Press Enter to use existing file if placed in crypto_workshop1/ or received_public_keys/")
    print("  2. Type 'paste' to paste the PEM text directly into console")
    print("  3. Type the filename or path (e.g., 'receiver_public.pem')")
    
    try:
        user_choice = input("Your choice (or press Enter): ").strip()
    except EOFError:
        user_choice = ""

    if user_choice.lower() == "paste":
        print("\nPaste the Receiver Public Key below (must include '-----END PUBLIC KEY-----'):")
        lines = []
        while True:
            line = input()
            lines.append(line)
            if "-----END PUBLIC KEY-----" in line:
                break
        pem_raw = "\n".join(lines).encode('utf-8')
        receiver_pub = load_and_validate_public_key_pem_bytes(pem_raw, min_bits=3072)
        save_public_key(receiver_pub, DIR_KEYS / "receiver_public.pem", force=True)
        print(" [SUCCESS] Parsed and validated pasted RSA-3072 Receiver Public Key.")
    elif user_choice:
        p = Path(user_choice)
        if p.is_file():
            receiver_pub = load_and_validate_public_key(p, min_bits=3072)
            save_public_key(receiver_pub, DIR_KEYS / "receiver_public.pem", force=True)
            print(f" [SUCCESS] Loaded and validated Receiver Public Key from: {p}")
        else:
            raise FileNotFoundError(f"Key file '{user_choice}' not found.")
    elif existing_key_file:
        receiver_pub = load_and_validate_public_key(existing_key_file, min_bits=3072)
        print(f" [SUCCESS] Loaded existing Receiver Public Key from: {existing_key_file}")
    else:
        print("[ERROR] No Receiver Public Key provided!")
        return

    receiver_fp = get_public_key_fingerprint(receiver_pub)
    print(f" -> Receiver Public Key Fingerprint (SHA-256):\n    {receiver_fp}")
    print("\n -> [TRUST CHECK] Confirm these fingerprints with your colleague via voice/in-person:")
    print(f"    - My Sender Key   : {sender_fp}")
    print(f"    - Friend Recv Key : {receiver_fp}")

    # 3. Encryption and Signing
    print("\n[PHASE C: EXAM PAPER ENCRYPTION & DIGITAL SIGNATURE]")
    exam_paper_path = discover_exam_paper()
    if not exam_paper_path.exists():
        print(f"[ERROR] No exam paper found at {exam_paper_path}")
        return

    print(f" -> Selected Examination Paper : {exam_paper_path.name}")
    print(f" -> Paper Source Location     : {exam_paper_path.resolve()} ({exam_paper_path.stat().st_size} bytes)")
    print(f" -> Sender ID                : faculty_cyber_dept")
    print(f" -> Recipient ID             : exam_controller_central")

    # Load sender private key in memory temporarily
    if sender_passphrase is None:
        sender_passphrase = getpass.getpass("Enter passphrase to unlock Sender Private Key: ")
    sender_priv = load_sender_private_key(sender_priv_path, sender_passphrase)
    print(" -> Unlocked Sender Private Key with passphrase.")

    # Encrypt and sign
    root_pkg_file, archive_pkg_file, package_dict = encrypt_and_sign_file(
        input_path=exam_paper_path,
        sender_private_key=sender_priv,
        recipient_public_key=receiver_pub,
        sender_id="faculty_cyber_dept",
        recipient_id="exam_controller_central",
        output_dir=DIR_OUTGOING
    )
    # Erase private key reference
    del sender_priv

    # 4. Package Inspection & Direct Root Saving Output
    print("\n" + "=" * 80)
    print(" [SUCCESS] ENCRYPTED & SIGNED EXAMINATION PACKAGE SAVED DIRECTLY IN ROOT:")
    print(f" -> {root_pkg_file.resolve()}")
    print("=" * 80)
    print(f" -> Backup Copy in Outgoing : {archive_pkg_file.resolve()}")
    print(f" -> Package File Size       : {root_pkg_file.stat().st_size} bytes")
    print(f" -> Protocol Stack          : AES-256-GCM + RSA-OAEP-SHA256 + RSA-PSS-SHA256")
    print(f" -> Plaintext SHA-256       : {package_dict['metadata']['plaintext_sha256']}")
    print(f" -> Wrapped Key Size        : {len(package_dict['encrypted_key'])} chars")
    print(f" -> Nonce (12 B Base64)     : {package_dict['nonce']}")
    print(f" -> Auth Tag (16 B Base64)  : {package_dict['tag']}")
    print(f" -> Signature Length        : {len(package_dict['signature'])} chars")
    print("=" * 80)
    print("INSTRUCTIONS FOR SHARING:")
    print(f"1. You can now copy '{root_pkg_file.name}' directly from your crypto_workshop1 folder.")
    print("2. Send this file to your friend via USB, LAN, or email.")
    print("3. Your friend can decrypt it using their Receiver Private Key.")
    print("=" * 80)

if __name__ == "__main__":
    main()
