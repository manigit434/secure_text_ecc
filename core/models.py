from django.conf import settings
from django.db import models
from django.contrib.auth.models import User


class Submission(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
    )

    encrypted_text = models.BinaryField()
    nonce = models.BinaryField()
    salt = models.BinaryField()
    client_pubkey_pem = models.BinaryField()

    created_at = models.DateTimeField(auto_now_add=True)

    # ✅ Updated field name for clarity
    submission_ip = models.GenericIPAddressField(null=True, blank=True)

    def __str__(self):
        return f"Submission #{self.id}"


class DecryptionAuditLog(models.Model):
    admin = models.ForeignKey(User, on_delete=models.PROTECT)
    submission = models.ForeignKey(Submission, on_delete=models.PROTECT)

    ip_address = models.CharField(max_length=64)
    reason = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]