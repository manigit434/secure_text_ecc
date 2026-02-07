"""
Cryptographic engine for SecureText ECC project.

Implements hybrid encryption using:
- ECC (ECDH) for key exchange
- HKDF for key derivation
- AES-GCM for authenticated encryption
"""

from pathlib import Path
import os
from typing import Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# ======================================================
# Configuration
# ======================================================
CURVE = ec.SECP256R1()
KEY_DIR = Path("secure_keys")
SERVER_KEY_FILE = KEY_DIR / "server_ec_private.pem"


# ======================================================
# Key Management
# ======================================================
def _ensure_key_dir() -> None:
    """Ensure secure key storage directory exists."""
    KEY_DIR.mkdir(parents=True, exist_ok=True)


def load_or_create_server_private_key() -> ec.EllipticCurvePrivateKey:
    """
    Load the persistent server ECC private key or generate one securely.
    """
    _ensure_key_dir()

    if SERVER_KEY_FILE.exists():
        return serialization.load_pem_private_key(
            SERVER_KEY_FILE.read_bytes(),
            password=None,
        )

    private_key = ec.generate_private_key(CURVE)

    SERVER_KEY_FILE.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

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
    Derive a 256-bit AES key from ECDH shared secret.
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"securetext-ecc-aes",
    ).derive(shared_secret)


# ======================================================
# Encryption / Decryption
# ======================================================
def encrypt_message(
    plaintext: str,
    server_private_key: ec.EllipticCurvePrivateKey,
) -> Tuple[bytes, bytes, bytes, bytes]:
    """
    Encrypt plaintext using ECC + AES-GCM.

    Returns:
        ciphertext, nonce, salt, client_public_key_pem
    """

    # Client ephemeral key (demo-safe, production-ready pattern)
    client_private_key = ec.generate_private_key(CURVE)
    client_public_key = client_private_key.public_key()

    # ECDH shared secret
    shared_secret = server_private_key.exchange(
        ec.ECDH(),
        client_public_key,
    )

    # AES key derivation
    salt = os.urandom(16)
    aes_key = _derive_aes_key(shared_secret, salt)

    # Authenticated encryption
    nonce = os.urandom(12)
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


def decrypt_message(
    ciphertext: bytes,
    nonce: bytes,
    salt: bytes,
    client_public_key_pem: bytes,
    server_private_key: ec.EllipticCurvePrivateKey,
) -> str:
    """
    Decrypt AES-GCM encrypted message using ECC-derived key.
    """

    client_public_key = serialization.load_pem_public_key(
        client_public_key_pem
    )

    shared_secret = server_private_key.exchange(
        ec.ECDH(),
        client_public_key,
    )

    aes_key = _derive_aes_key(shared_secret, salt)

    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    return plaintext.decode("utf-8")
