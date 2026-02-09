"""
Elliptic Curve Cryptography (ECC) operations.
"""

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes


class ECCCrypto:
    """Handles ECC key generation and shared secret derivation."""

    @staticmethod
    def generate_private_key():
        return ec.generate_private_key(ec.SECP256R1())

    @staticmethod
    def serialize_private_key(private_key):
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    @staticmethod
    def serialize_public_key(public_key):
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    @staticmethod
    def load_public_key(public_key_bytes):
        return serialization.load_pem_public_key(public_key_bytes)

    @staticmethod
    def derive_shared_key(private_key, peer_public_key):
        return private_key.exchange(ec.ECDH(), peer_public_key)
