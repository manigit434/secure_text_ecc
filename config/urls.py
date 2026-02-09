"""
URL configuration for SecureText ECC project.

This file routes incoming requests to the appropriate Django apps.
"""

from django.contrib import admin
from django.urls import path, include
from core import views   # ✅ Import views for root URL

urlpatterns = [
    # Admin interface
    path("admin/", admin.site.urls),

    # Root homepage (required)
    path("", views.public_dashboard_view, name="home"),

    # Core application URLs
    path("", include("core.urls")),
]