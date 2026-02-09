# core/forms.py
import re
from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User


class SecureUserCreationForm(UserCreationForm):
    class Meta:
        model = User
        fields = ("username", "password1", "password2")

    def clean_username(self):
        username = self.cleaned_data.get("username", "").strip()

        # ✅ Must contain at least one letter
        if not re.search(r"[A-Za-z]", username):
            raise forms.ValidationError(
                "Username must contain at least one letter (A–Z)."
            )

        # ✅ Length enforcement
        if len(username) < 4 or len(username) > 30:
            raise forms.ValidationError(
                "Username must be between 4 and 30 characters long."
            )

        # ✅ Allowed characters: letters, digits, underscore
        if not re.match(r"^[A-Za-z][A-Za-z0-9_]+$", username):
            raise forms.ValidationError(
                "Username must start with a letter and contain only letters, digits, or underscores."
            )

        # ✅ Reserved words check
        reserved = {"admin", "root", "superuser", "staff"}
        if username.lower() in reserved:
            raise forms.ValidationError(
                f"'{username}' is a reserved word and cannot be used as a username."
            )

        # ✅ Ensure unique username
        if User.objects.filter(username=username).exists():
            raise forms.ValidationError(
                "This username is already taken."
            )

        return username