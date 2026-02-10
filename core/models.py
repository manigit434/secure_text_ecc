from django.conf import settings
from django.db import models
from django.contrib.auth.models import User


class Submission(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
    )

    # ✅ Correct field types
    encrypted_text = models.TextField()
    nonce = models.CharField(max_length=64)
    salt = models.CharField(max_length=64)
    client_pubkey_pem = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    # ✅ Store client IP (supports IPv4 + IPv6)
    ip_address = models.GenericIPAddressField(null=True, blank=True)

    def __str__(self):
        return f"Submission #{self.id}"


class DecryptionAuditLog(models.Model):
    admin = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
    )

    submission = models.ForeignKey(
        Submission,
        on_delete=models.PROTECT,
    )

    # ✅ Updated to GenericIPAddressField
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    reason = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"AuditLog #{self.pk} — {self.admin} on Submission #{self.submission_id}"