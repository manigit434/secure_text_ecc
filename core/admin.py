# core/admin.py
from django.contrib import admin, messages
from django.shortcuts import render, get_object_or_404
from django.urls import path
from django.contrib.auth import authenticate

from .models import Submission, DecryptionAuditLog
from core.crypto.crypto import (
    load_or_create_server_private_key,
    decrypt_message,
)


@admin.register(Submission)
class SubmissionAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "created_at", "decrypt_button")
    readonly_fields = (
        "user",
        "created_at",
        "encrypted_text",
        "nonce",
        "salt",
        "client_pubkey_pem",
    )

    # 🔒 Disable Add, Change, Delete
    def has_add_permission(self, request):
        return False  # ❌ removes "Add Encrypted Submission +"

    def has_change_permission(self, request, obj=None):
        return False  # ❌ prevents editing

    def has_delete_permission(self, request, obj=None):
        return False  # ❌ prevents deletion

    def decrypt_button(self, obj):
        return admin.utils.format_html(
            '<a class="button" href="decrypt/{}/">🔒 Decrypt</a>',
            obj.id,
        )
    decrypt_button.short_description = "Decrypt"

    def get_urls(self):
        urls = super().get_urls()
        custom_urls = [
            path(
                "decrypt/<int:submission_id>/",
                self.admin_site.admin_view(self.decrypt_view),
                name="submission-decrypt",
            ),
        ]
        return custom_urls + urls

    def decrypt_view(self, request, submission_id):
        submission = get_object_or_404(Submission, pk=submission_id)

        if request.method == "POST":
            password = request.POST.get("password")
            reason = request.POST.get("reason", "").strip()

            user = authenticate(
                username=request.user.username,
                password=password,
            )

            if not user:
                messages.error(request, "Invalid admin password")
            elif not reason:
                messages.error(request, "Reason for decryption is required")
            else:
                server_key = load_or_create_server_private_key()

                plaintext = decrypt_message(
                    submission.encrypted_text,
                    submission.nonce,
                    submission.salt,
                    submission.client_pubkey_pem,
                    server_key,
                )

                DecryptionAuditLog.objects.create(
                    admin=request.user,
                    submission=submission,
                    ip_address=request.META.get("REMOTE_ADDR", ""),
                    reason=reason,
                )

                return render(
                    request,
                    "admin_decrypt_confirm.html",
                    {
                        "sub": submission,
                        "plaintext": plaintext,
                    },
                )

        return render(
            request,
            "admin_decrypt_confirm.html",
            {"sub": submission},
        )


@admin.register(DecryptionAuditLog)
class DecryptionAuditLogAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "admin",
        "submission",
        "created_at",
        "ip_address",
        "reason",
    )

    list_filter = ("created_at", "admin")
    search_fields = ("admin__username", "submission__id", "reason")
    ordering = ("-created_at",)

    # 🔒 ABSOLUTE LOCKDOWN
    def has_add_permission(self, request):
        return False  # ❌ cannot manually add logs

    def has_change_permission(self, request, obj=None):
        return False  # ❌ cannot edit logs

    def has_delete_permission(self, request, obj=None):
        return False  # ❌ cannot delete logs

    actions = None  # ❌ disable bulk actions

    readonly_fields = (
        "admin",
        "submission",
        "created_at",
        "ip_address",
        "reason",
    )