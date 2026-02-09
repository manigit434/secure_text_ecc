"""
Test suite for the Core application.

These tests validate the integrity of the encrypted submission
workflow without exposing or relying on plaintext storage.
"""

from django.contrib.auth import get_user_model
from django.test import TestCase

from core.models import Submission
from core.crypto.crypto import (
    load_or_create_server_private_key,
    encrypt_message,
    decrypt_message,
)


User = get_user_model()


class SubmissionModelTests(TestCase):
    """
    Tests related to the Submission model and cryptographic workflow.
    """

    def setUp(self):
        """
        Create a test user and load server cryptographic keys.
        """
        self.user = User.objects.create_user(
            username="testuser",
            password="StrongTestPassword123",
        )
        self.server_private_key = load_or_create_server_private_key()

    def test_encrypted_submission_creation(self):
        """
        Ensure encrypted data is stored correctly and no plaintext is saved.
        """
        plaintext = "This is a highly confidential message."

        (
            ciphertext,
            nonce,
            salt,
            client_pubkey_pem,
        ) = encrypt_message(plaintext, self.server_private_key)

        submission = Submission.objects.create(
            user=self.user,
            encrypted_text=ciphertext,
            nonce=nonce,
            salt=salt,
            client_pubkey_pem=client_pubkey_pem,
        )

        self.assertIsNotNone(submission.id)
        self.assertEqual(submission.user, self.user)
        self.assertNotEqual(submission.encrypted_text, plaintext.encode())

    def test_encrypted_message_decryption(self):
        """
        Ensure encrypted messages can be decrypted correctly
        using ECC-derived AES keys.
        """
        plaintext = "Secure message round-trip test."

        (
            ciphertext,
            nonce,
            salt,
            client_pubkey_pem,
        ) = encrypt_message(plaintext, self.server_private_key)

        submission = Submission.objects.create(
            user=self.user,
            encrypted_text=ciphertext,
            nonce=nonce,
            salt=salt,
            client_pubkey_pem=client_pubkey_pem,
        )

        decrypted_text = decrypt_message(
            submission.encrypted_text,
            submission.nonce,
            submission.salt,
            submission.client_pubkey_pem,
            self.server_private_key,
        )

        self.assertEqual(decrypted_text, plaintext)

    def test_submission_string_representation(self):
        """
        Verify the string representation does not leak sensitive data.
        """
        submission = Submission.objects.create(
            user=self.user,
            encrypted_text=b"dummy",
            nonce=b"dummy",
            salt=b"dummy",
            client_pubkey_pem=b"dummy",
        )

        self.assertIn("Encrypted Submission", str(submission))
