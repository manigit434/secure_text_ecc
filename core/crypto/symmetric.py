"""
Symmetric encryption using AES-GCM.
"""

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os


class AESCipher:
    @staticmethod
    def encrypt(key: bytes, plaintext: bytes):
        nonce = os.urandom(12)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        return nonce, ciphertext

    @staticmethod
    def decrypt(key: bytes, nonce: bytes, ciphertext: bytes):
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None)
