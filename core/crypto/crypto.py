"""
Cryptographic engine for SecureText ECC project.

Implements hybrid encryption using:
- ECC (ECDH) for key exchange
- HKDF for key derivation
- AES-GCM for authenticated encryption

Design goals:
- Plaintext is never stored
- Private keys are generated per deployment
- Strong, modern cryptography with minimal attack surface
"""

import os
from typing import Tuple
from pathlib import Path
from django.conf import settings

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# ======================================================
# Configuration
# ======================================================

CURVE = ec.SECP256R1()

# Directory to store server private key (NOT committed)
KEY_DIR = settings.BASE_DIR / "secure_keys"
SERVER_KEY_FILE = KEY_DIR / "server_ec_private.pem"


# ======================================================
# Key Management
# ======================================================

def _ensure_key_dir() -> None:
    """Ensure secure directory exists for key storage."""
    KEY_DIR.mkdir(parents=True, exist_ok=True)


def load_or_create_server_private_key() -> ec.EllipticCurvePrivateKey:
    """
    Load the persistent server ECC private key or securely generate one.

    The key is:
    - Generated only once
    - Stored locally
    - Never hardcoded
    - Never committed to version control
    """
    _ensure_key_dir()

    if SERVER_KEY_FILE.exists():
        return serialization.load_pem_private_key(
            SERVER_KEY_FILE.read_bytes(),
            password=None,
        )

    # Generate new server private key
    private_key = ec.generate_private_key(CURVE)

    # Serialize and store securely
    SERVER_KEY_FILE.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    # Restrict permissions (Linux/macOS safe; ignored on Windows)
    try:
        SERVER_KEY_FILE.chmod(0o600)
    except PermissionError:
        pass

    return private_key


def get_server_public_key_pem(
    server_private_key: ec.EllipticCurvePrivateKey,
) -> bytes:
    """
    Return the server public key in PEM format.
    """
    return server_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


# ======================================================
# Key Derivation
# ======================================================

def _derive_aes_key(shared_secret: bytes, salt: bytes) -> bytes:
    """
    Derive a 256-bit AES key from ECDH shared secret using HKDF.
    """

    # 🔥 FIX: Convert PostgreSQL memoryview → bytes
    if isinstance(salt, memoryview):
        salt = bytes(salt)

    if isinstance(shared_secret, memoryview):
        shared_secret = bytes(shared_secret)

    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # 256-bit AES key
        salt=salt,
        info=b"securetext-ecc-aes",
    ).derive(shared_secret)


# ======================================================
# Encryption
# ======================================================

def encrypt_message(
    plaintext: str,
    server_private_key: ec.EllipticCurvePrivateKey,
) -> Tuple[bytes, bytes, bytes, bytes]:
    """
    Encrypt plaintext using ECC + AES-GCM.

    Flow:
    - Generate ephemeral ECC key (client-side simulation)
    - Perform ECDH key exchange
    - Derive AES key via HKDF
    - Encrypt using AES-GCM

    Returns:
        ciphertext, nonce, salt, client_public_key_pem
    """

    # Ephemeral client key (per message)
    client_private_key = ec.generate_private_key(CURVE)
    client_public_key = client_private_key.public_key()

    # ECDH shared secret
    shared_secret = server_private_key.exchange(
        ec.ECDH(),
        client_public_key,
    )

    # Key derivation
    salt = os.urandom(16)
    aes_key = _derive_aes_key(shared_secret, salt)

    # AES-GCM encryption
    nonce = os.urandom(12)  # Recommended size for GCM
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(
        nonce,
        plaintext.encode("utf-8"),
        None,
    )

    return (
        ciphertext,
        nonce,
        salt,
        client_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
    )


# ======================================================
# Decryption
# ======================================================

def decrypt_message(
    ciphertext: bytes,
    nonce: bytes,
    salt: bytes,
    client_public_key_pem: bytes,
    server_private_key: ec.EllipticCurvePrivateKey,
) -> str:
    """
    Decrypt AES-GCM encrypted message using ECC-derived key.

    Plaintext exists only in memory and is never persisted.
    """

    client_public_key = serialization.load_pem_public_key(
        client_public_key_pem
    )

    # Recompute shared secret
    shared_secret = server_private_key.exchange(
        ec.ECDH(),
        client_public_key,
    )

    # Derive AES key
    aes_key = _derive_aes_key(shared_secret, salt)

    # Decrypt
    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(
        nonce,
        ciphertext,
        None,
    )

    return plaintext.decode("utf-8")