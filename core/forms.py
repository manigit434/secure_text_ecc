# core/forms.py
import re
from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User


class SecureUserCreationForm(UserCreationForm):
    email = forms.EmailField(
        required=True,
        help_text="Required. Enter a valid email address.",
        widget=forms.EmailInput(attrs={"placeholder": "you@example.com"})
    )

    class Meta:
        model = User
        fields = ("username", "email", "password1", "password2")

    def clean_username(self):
        username = self.cleaned_data.get("username", "")

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

        return username

    def clean_email(self):
        email = self.cleaned_data.get("email", "").lower()

        # ✅ Ensure unique email
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError(
                "This email address is already registered."
            )

        return email