import time
import re

from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.admin.views.decorators import staff_member_required
from django.contrib.auth.models import User
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.views.decorators.http import require_http_methods

from core.forms import SecureUserCreationForm
from core.models import Submission, DecryptionAuditLog
from core.crypto.crypto import (
    load_or_create_server_private_key,
    encrypt_message,
    decrypt_message,
)
from core.utils import get_client_ip


# ======================================================
# ROOT HOME VIEW
# ======================================================
def home(request: HttpRequest) -> HttpResponse:
    """
    Root homepage view.
    IMPORTANT: base.html is a layout, not a page.
    """
    return render(request, "dashboard.html")


# ======================================================
# PUBLIC DASHBOARD
# ======================================================
def public_dashboard_view(request: HttpRequest) -> HttpResponse:
    """
    Public landing page.
    No authentication required.
    """
    return render(request, "dashboard.html")


# ======================================================
# AUTHENTICATION
# ======================================================
@require_http_methods(["GET", "POST"])
def login_view(request: HttpRequest) -> HttpResponse:
    if request.user.is_authenticated:
        return redirect("core:success")

    MAX_ATTEMPTS = 3
    REDIRECT_AFTER = 5
    COOLDOWN_SECONDS = 30

    now = int(time.time())

    attempts = request.session.get("login_failures", 0)
    cooldown_until = request.session.get("cooldown_until", 0)

    # 🚫 ACTIVE COOLDOWN
    if now < cooldown_until:
        return render(request, "login.html", {
            "locked": True,
            "cooldown": cooldown_until - now
        })

    if request.method == "POST":
        ip_address = get_client_ip(request)

        username = request.POST.get("username", "").strip()
        password = request.POST.get("password", "")

        user = authenticate(request, username=username, password=password)

        if user:
            login(request, user)
            request.session["login_failures"] = 0
            request.session["cooldown_until"] = 0
            return redirect("core:success")

        # ❌ FAILED LOGIN
        attempts += 1
        request.session["login_failures"] = attempts

        # ⏳ COOLDOWN
        if attempts == MAX_ATTEMPTS:
            request.session["cooldown_until"] = now + COOLDOWN_SECONDS
            return render(request, "login.html", {
                "locked": True,
                "cooldown": COOLDOWN_SECONDS
            })

        # 🔁 REDIRECT TO REGISTER
        if attempts >= REDIRECT_AFTER:
            request.session["login_failures"] = 0
            return redirect("core:register")

        return render(request, "login.html", {
            "error": "Invalid username or password."
        })

    return render(request, "login.html")


@login_required
@require_http_methods(["POST"])
def logout_view(request: HttpRequest) -> HttpResponse:
    logout(request)
    return redirect("core:dashboard")


@require_http_methods(["GET", "POST"])
def register_view(request: HttpRequest) -> HttpResponse:
    if request.user.is_authenticated:
        return redirect("core:success")

    form = SecureUserCreationForm(request.POST or None)

    if request.method == "POST":
        if form.is_valid():
            form.save()
            messages.success(
                request,
                "Account created successfully. Please log in."
            )
            return redirect("core:login")

    return render(request, "register.html", {"form": form})


# ======================================================
# USERNAME AVAILABILITY CHECK (AJAX)
# ======================================================
@require_http_methods(["GET"])
def check_username(request: HttpRequest) -> JsonResponse:
    username = request.GET.get("username", "").strip()

    if not username:
        return JsonResponse({
            "available": False,
            "message": "Username is required."
        })

    if not re.search(r"[A-Za-z]", username):
        return JsonResponse({
            "available": False,
            "message": "Username must contain at least one letter."
        })

    if User.objects.filter(username=username).exists():
        return JsonResponse({
            "available": False,
            "message": "Username already taken."
        })

    return JsonResponse({
        "available": True,
        "message": "Username available."
    })


# ======================================================
# USER DASHBOARD
# ======================================================
@login_required
def success_view(request: HttpRequest) -> HttpResponse:
    """
    User dashboard after login.
    """
    return render(request, "success.html")


@login_required
def mine_view(request: HttpRequest) -> HttpResponse:
    """
    View encrypted submissions of logged-in user.
    """
    submissions = Submission.objects.filter(user=request.user)

    # IMPORTANT: template must exist exactly at this path
    return render(
        request,
        "my_submissions.html",
        {"subs": submissions},
    )


# ======================================================
# SECURE SUBMISSION
# ======================================================
@login_required
@require_http_methods(["GET", "POST"])
def submit_view(request: HttpRequest) -> HttpResponse:
    """
    Encrypt and securely store a user message.
    """
    if request.method == "POST":
        message = request.POST.get("message", "").strip()

        if not message:
            return redirect("core:submit")

        server_key = load_or_create_server_private_key()

        ciphertext, nonce, salt, client_pub = encrypt_message(
            message,
            server_key,
        )

        Submission.objects.create(
            user=request.user,
            encrypted_text=ciphertext,
            nonce=nonce,
            salt=salt,
            client_pubkey_pem=client_pub,
        )

        return redirect("core:mine")

    return render(request, "submit.html")


# ======================================================
# ADMIN DECRYPT (ZERO-TRUST FLOW)
# ======================================================
@staff_member_required
@require_http_methods(["GET", "POST"])
def admin_decrypt_view(
    request: HttpRequest,
    sub_id: int,
) -> HttpResponse:
    """
    Admin-only decryption with audit logging.
    """
    submission = get_object_or_404(Submission, id=sub_id)

    context = {"sub": submission}

    if request.method == "POST":
        password = request.POST.get("password")
        reason = request.POST.get("reason", "").strip()

        admin_user = authenticate(
            username=request.user.username,
            password=password,
        )

        if not admin_user:
            context["error"] = "Invalid admin password"
            return render(
                request,
                "admin_decrypt_confirm.html",
                context,
            )

        if not reason:
            context["error"] = "Decryption reason is required."
            return render(
                request,
                "admin_decrypt_confirm.html",
                context,
            )

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
            ip_address=get_client_ip(request),
            reason=reason,
        )

        context["plaintext"] = plaintext

    return render(
        request,
        "admin_decrypt_confirm.html",
        context,
    )
